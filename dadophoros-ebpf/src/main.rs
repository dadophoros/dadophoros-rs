#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_sock_addr,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        gen::bpf_skb_load_bytes,
    },
    macros::{cgroup_sock_addr, classifier, map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::{SockAddrContext, TcContext, TracePointContext},
};
use dadophoros_common::{ConnectEvent, DnsEvent, ProcessInfo};

// Max bytes we copy from a DNS packet into the ringbuf entry.
const DNS_BUF_MAX: u32 = 512;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static PROCESS_INFO: HashMap<u32, ProcessInfo> = HashMap::with_max_entries(32768, 0);

// --- cgroup sock_addr hooks (Step 1) ----------------------------------------

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    emit_v4(ctx.sock_addr, false);
    1
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    emit_v6(ctx.sock_addr, false);
    1
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    emit_v4(ctx.sock_addr, true);
    1
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    emit_v6(ctx.sock_addr, true);
    1
}

// read_volatile forces LLVM to emit a direct `*(u32 *)(ctx + const)` load
// at each access. Without it, the BPF backend may emit `r2 = ctx; r2 += off;
// *(u32 *)(r2 + 0)`, which the verifier rejects as "dereference of modified
// ctx ptr disallowed".

#[inline(always)]
fn emit_v4(s: *mut bpf_sock_addr, is_sendmsg: bool) {
    // Skip dport=0 events: connect()/sendmsg() with port 0 is socket
    // bookkeeping (source-IP probes, AF_UNSPEC dissolution) and carries no
    // real traffic.
    let port_u32 = unsafe { core::ptr::read_volatile(&(*s).user_port) };
    let dport = u16::from_be(port_u32 as u16);
    if dport == 0 {
        return;
    }

    let daddr_v4 = unsafe { core::ptr::read_volatile(&(*s).user_ip4) };

    // For UDP sendmsg only: drop deliveries to 127.0.0.0/8. These are
    // intra-host plumbing (e.g. systemd-resolved sending DNS replies back
    // to the requesting app's ephemeral port). The original outbound
    // query side goes through connect() and stays visible.
    // daddr_v4 holds the raw __be32 value; on the LE BPF target the
    // first network byte sits in the low byte of the u32.
    if is_sendmsg && (daddr_v4 & 0xFF) == 0x7F {
        return;
    }

    let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) else {
        return;
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let ev = ConnectEvent {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        daddr_v4,
        daddr_v6: [0u8; 16],
        dport,
        family: 4,
        _pad: 0,
        comm,
    };

    unsafe {
        core::ptr::write_unaligned(entry.as_mut_ptr(), ev);
    }
    entry.submit(0);
}

#[inline(always)]
fn emit_v6(s: *mut bpf_sock_addr, is_sendmsg: bool) {
    let port_u32 = unsafe { core::ptr::read_volatile(&(*s).user_port) };
    let dport = u16::from_be(port_u32 as u16);
    if dport == 0 {
        return;
    }

    let w0 = unsafe { core::ptr::read_volatile(&(*s).user_ip6[0]) };
    let w1 = unsafe { core::ptr::read_volatile(&(*s).user_ip6[1]) };
    let w2 = unsafe { core::ptr::read_volatile(&(*s).user_ip6[2]) };
    let w3 = unsafe { core::ptr::read_volatile(&(*s).user_ip6[3]) };

    // For UDP sendmsg only: drop ::1 (bytes: 15× 0x00 then 0x01). On the LE
    // BPF target that final byte lives in the low byte of word 3 read as a
    // host-order u32 — i.e. word 3 reads as 0x0100_0000.
    if is_sendmsg && w0 == 0 && w1 == 0 && w2 == 0 && w3 == 0x0100_0000 {
        return;
    }

    let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) else {
        return;
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let daddr_v6: [u8; 16] = unsafe { core::mem::transmute([w0, w1, w2, w3]) };

    let ev = ConnectEvent {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        daddr_v4: 0,
        daddr_v6,
        dport,
        family: 6,
        _pad: 0,
        comm,
    };

    unsafe {
        core::ptr::write_unaligned(entry.as_mut_ptr(), ev);
    }
    entry.submit(0);
}

// --- tracepoints maintaining PROCESS_INFO (Step 2) --------------------------

// On execve, record the current task's metadata. Note: at sys_enter the new
// exe has not been loaded yet, but pid/uid/start_ns are stable across execve.
// comm reflects the *old* exe at this point — the new comm becomes visible
// after the kernel finishes loading. For Step 2 we leave start_ns/ppid/
// exe_inode as 0; later steps fill them in via CO-RE.
#[tracepoint]
pub fn sys_enter_execve(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let info = ProcessInfo {
        pid,
        ppid: 0,
        uid: uid_gid as u32,
        _pad: 0,
        start_ns: 0,
        exe_inode: 0,
        comm,
    };

    let _ = PROCESS_INFO.insert(&pid, &info, 0);
    0
}

// sched_process_fork format (stable on 5.x/6.x):
//   parent_comm[16] @ 8, parent_pid @ 24, child_comm[16] @ 28, child_pid @ 44
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let parent_pid: u32 = match unsafe { ctx.read_at::<i32>(24) } {
        Ok(p) if p > 0 => p as u32,
        _ => return 0,
    };
    let child_pid: u32 = match unsafe { ctx.read_at::<i32>(44) } {
        Ok(p) if p > 0 => p as u32,
        _ => return 0,
    };

    if let Some(parent) = unsafe { PROCESS_INFO.get(&parent_pid) } {
        let mut child = *parent;
        child.pid = child_pid;
        child.ppid = parent_pid;
        // child has its own start_ns; left 0 for Step 2.
        let _ = PROCESS_INFO.insert(&child_pid, &child, 0);
    }
    0
}

// sched_process_exit format: comm[16] @ 8, pid @ 24
#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    let pid: u32 = match unsafe { ctx.read_at::<i32>(24) } {
        Ok(p) if p > 0 => p as u32,
        _ => return 0,
    };
    let _ = PROCESS_INFO.remove(&pid);
    0
}

// --- tc classifier programs for DNS sniffing (Step 3) -----------------------

const TC_ACT_OK: i32 = 0;
const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_UDP: u8 = 17;
const IPV6_HDR_LEN: usize = 40;
const UDP_HDR_LEN: usize = 8;
const DNS_MIN_HDR: usize = 12;

#[classifier]
pub fn dns_egress(ctx: TcContext) -> i32 {
    let _ = capture_dns(&ctx);
    TC_ACT_OK
}

#[classifier]
pub fn dns_ingress(ctx: TcContext) -> i32 {
    let _ = capture_dns(&ctx);
    TC_ACT_OK
}

#[inline(always)]
fn capture_dns(ctx: &TcContext) -> Result<(), ()> {
    // Ethernet: ethertype at offset 12. (Loopback packets on Linux also
    // carry an ethernet-like header.)
    let eth_type_be = ctx.load::<u16>(12).map_err(|_| ())?;
    let eth_type = u16::from_be(eth_type_be);

    let (ip_proto, l4_off) = if eth_type == ETH_P_IP {
        let vihl: u8 = ctx.load(ETH_HDR_LEN).map_err(|_| ())?;
        let ihl = (vihl & 0x0f) as usize * 4;
        if !(20..=60).contains(&ihl) {
            return Err(());
        }
        let proto: u8 = ctx.load(ETH_HDR_LEN + 9).map_err(|_| ())?;
        (proto, ETH_HDR_LEN + ihl)
    } else if eth_type == ETH_P_IPV6 {
        let nh: u8 = ctx.load(ETH_HDR_LEN + 6).map_err(|_| ())?;
        // No extension header handling — we only care about plain UDP DNS.
        (nh, ETH_HDR_LEN + IPV6_HDR_LEN)
    } else {
        return Err(());
    };

    if ip_proto != IPPROTO_UDP {
        return Err(());
    }

    let src_port = u16::from_be(ctx.load::<u16>(l4_off).map_err(|_| ())?);
    let dst_port = u16::from_be(ctx.load::<u16>(l4_off + 2).map_err(|_| ())?);
    if src_port != 53 && dst_port != 53 {
        return Err(());
    }

    // UDP length field tells us exactly how many bytes of payload there are.
    // Clamp to our buffer size and use that as the single load size — avoids
    // mid-RR truncation that would break hickory-proto parsing.
    let udp_total = u16::from_be(ctx.load::<u16>(l4_off + 4).map_err(|_| ())?) as u32;
    if udp_total < (UDP_HDR_LEN as u32 + DNS_MIN_HDR as u32) {
        return Err(());
    }
    // Cap udp_total upper bound before subtracting so the result stays bounded.
    let udp_capped: u32 = if udp_total > (UDP_HDR_LEN as u32 + DNS_BUF_MAX) {
        UDP_HDR_LEN as u32 + DNS_BUF_MAX
    } else {
        udp_total
    };
    let dns_payload_len = udp_capped - UDP_HDR_LEN as u32;
    // Re-assert bounds after subtraction. The BPF verifier drops scalar bounds
    // across subtraction (it can't rule out underflow), so we restate the
    // valid range here for the size argument to bpf_skb_load_bytes.
    if dns_payload_len == 0 || dns_payload_len > DNS_BUF_MAX {
        return Err(());
    }
    let copy_len: u32 = dns_payload_len;

    let dns_off = l4_off + UDP_HDR_LEN;

    let Some(mut entry) = DNS_EVENTS.reserve::<DnsEvent>(0) else {
        return Err(());
    };
    let event_ptr = entry.as_mut_ptr();
    unsafe {
        (*event_ptr).len = 0;
        (*event_ptr)._pad = [0; 6];
    }

    let dst_ptr = unsafe { &mut (*event_ptr).data as *mut _ as *mut core::ffi::c_void };
    let skb_ptr = ctx.skb.skb as *const _ as *mut _;
    let r = unsafe {
        bpf_skb_load_bytes(skb_ptr, dns_off as u32, dst_ptr, copy_len)
    };
    if r != 0 {
        entry.discard(0);
        return Err(());
    }

    unsafe {
        (*event_ptr).len = copy_len as u16;
    }
    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
