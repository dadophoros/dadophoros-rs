use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, RingBuf},
    programs::{tc, CgroupAttachMode, CgroupSockAddr, SchedClassifier, TcAttachType, TracePoint},
    Ebpf,
};
use dadophoros_common::{ConnectEvent, DnsEvent, FlowKey};
use dadophoros_proto::{EnrichedEvent, ServerMessage};
use hickory_proto::{op::Message, rr::RData, serialize::binary::BinDecodable};
use notify::Watcher;
use tokio::io::unix::AsyncFd;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

mod ipc;
mod rules;
use rules::{Action, Verdict};

const CGROUP_PATH: &str = "/sys/fs/cgroup";
pub(crate) const RULES_DIR: &str = "/etc/dadophoros/rules.d";
const EBPF_OBJ: &[u8] =
    include_bytes_aligned!("../../target/bpfel-unknown-none/release/dadophoros-ebpf");
const CGROUP_HOOKS: &[&str] = &["connect4", "connect6", "sendmsg4", "sendmsg6"];
const TRACEPOINTS: &[(&str, &str)] = &[
    ("syscalls", "sys_enter_execve"),
    ("sched", "sched_process_fork"),
    ("sched", "sched_process_exit"),
];
const DNS_TC_HOOKS: &[(&str, TcAttachType)] = &[
    ("dns_egress", TcAttachType::Egress),
    ("dns_ingress", TcAttachType::Ingress),
];

const VERDICT_DENY: u8 = 0;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    info!("starting");

    let mut ebpf = Ebpf::load(EBPF_OBJ).context("loading eBPF object")?;
    let cgroup = std::fs::File::open(CGROUP_PATH)
        .with_context(|| format!("opening cgroup at {CGROUP_PATH}"))?;

    for name in CGROUP_HOOKS {
        let prog: &mut CgroupSockAddr = ebpf
            .program_mut(name)
            .with_context(|| format!("program {name} not found"))?
            .try_into()?;
        prog.load().with_context(|| format!("loading {name}"))?;
        prog.attach(&cgroup, CgroupAttachMode::Single)
            .with_context(|| format!("attaching {name}"))?;
        info!(hook = name, "attached cgroup hook");
    }

    for (category, name) in TRACEPOINTS {
        let prog: &mut TracePoint = ebpf
            .program_mut(name)
            .with_context(|| format!("tracepoint {name} not found"))?
            .try_into()?;
        prog.load().with_context(|| format!("loading {name}"))?;
        prog.attach(category, name)
            .with_context(|| format!("attaching {category}/{name}"))?;
        info!(category = category, name = name, "attached tracepoint");
    }

    for (name, _) in DNS_TC_HOOKS {
        let prog: &mut SchedClassifier = ebpf
            .program_mut(name)
            .with_context(|| format!("tc program {name} not found"))?
            .try_into()?;
        prog.load().with_context(|| format!("loading {name}"))?;
    }

    let interfaces = list_up_interfaces();
    info!(interfaces = ?interfaces, "attaching TC programs");
    for iface in &interfaces {
        if let Err(e) = tc::qdisc_add_clsact(iface) {
            debug!(iface = %iface, error = %e, "clsact add (may be EEXIST)");
        }
        for (name, attach_type) in DNS_TC_HOOKS {
            let prog: &mut SchedClassifier = ebpf
                .program_mut(name)
                .with_context(|| format!("tc program {name} missing"))?
                .try_into()?;
            match prog.attach(iface, *attach_type) {
                Ok(_) => info!(iface = %iface, hook = %name, "attached"),
                Err(e) => warn!(iface = %iface, hook = %name, error = %e, "tc attach failed"),
            }
        }
    }

    // Take the verdict cache handle. Main loop writes to it directly on rule
    // matches; the kernel reads it on every connect/sendmsg.
    let cache_map = ebpf
        .take_map("VERDICT_CACHE")
        .context("VERDICT_CACHE map missing")?;
    let mut verdict_cache: AyaHashMap<_, FlowKey, u8> = AyaHashMap::try_from(cache_map)?;

    let mut exe_paths: HashMap<u32, Option<PathBuf>> = HashMap::new();
    backfill_proc(&mut exe_paths);
    info!(pids = exe_paths.len(), "/proc backfill complete");

    let rules_dir = PathBuf::from(RULES_DIR);
    let mut rule_set = rules::load_dir(&rules_dir);
    info!(count = rule_set.len(), dir = %rules_dir.display(), "loaded rules");

    let (rules_tx, mut rules_rx) = mpsc::unbounded_channel::<()>();
    let _rules_tx_keepalive = rules_tx.clone();
    let _watcher = make_rules_watcher(&rules_dir, rules_tx);

    let events_map = ebpf.take_map("EVENTS").context("EVENTS map missing")?;
    let dns_map = ebpf
        .take_map("DNS_EVENTS")
        .context("DNS_EVENTS map missing")?;
    let events: RingBuf<_> = RingBuf::try_from(events_map)?;
    let dns: RingBuf<_> = RingBuf::try_from(dns_map)?;
    let mut events_fd = AsyncFd::new(events)?;
    let mut dns_fd = AsyncFd::new(dns)?;

    let mut dns_cache: HashMap<IpAddr, DnsEntry> = HashMap::new();
    let mut evict_tick = tokio::time::interval(Duration::from_secs(1));

    // Broadcast ServerMessages (only Event under the current model — other
    // variants are per-connection responses, never broadcast).
    let (event_tx, _) = broadcast::channel::<ServerMessage>(1024);
    ipc::spawn_server(event_tx.clone(), rules_dir.clone())?;

    info!("draining events (Ctrl-C to exit)");

    loop {
        tokio::select! {
            biased;
            r = dns_fd.readable_mut() => {
                let mut guard = r?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() < std::mem::size_of::<DnsEvent>() {
                        continue;
                    }
                    let event: DnsEvent =
                        bytemuck::pod_read_unaligned(&item[..std::mem::size_of::<DnsEvent>()]);
                    ingest_dns(&event, &mut dns_cache);
                }
                guard.clear_ready();
            }
            r = events_fd.readable_mut() => {
                let mut guard = r?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() < std::mem::size_of::<ConnectEvent>() {
                        error!(len = item.len(), "short event");
                        continue;
                    }
                    let event: ConnectEvent =
                        bytemuck::pod_read_unaligned(&item[..std::mem::size_of::<ConnectEvent>()]);
                    let exe = lookup_exe(event.pid, &mut exe_paths);
                    let exe_str = exe.as_deref().and_then(|p| p.to_str());
                    let host = lookup_host(&event, &dns_cache);
                    let dest_ip_string = event_ip_string(&event);
                    let verdict = rules::evaluate(
                        &rule_set,
                        exe_str,
                        host,
                        dest_ip_string.as_deref(),
                        event.dport,
                    );
                    print_event(&event, exe_str, host, verdict.as_ref());

                    // Cache deny verdicts in the kernel so the next connect
                    // from the same flow is blocked without round-tripping
                    // back to userspace. Allow rules don't write here —
                    // allow is the implicit default for anything not in
                    // the map.
                    if let Some(v) = &verdict {
                        if v.action == Action::Deny {
                            let key = common_flow_key(&event);
                            if let Err(e) = verdict_cache.insert(key, VERDICT_DENY, 0) {
                                warn!(error = %e, "deny cache insert failed");
                            }
                        }
                    }

                    let enriched = enrich(&event, exe_str, host, verdict.as_ref());
                    let _ = event_tx.send(ServerMessage::Event(enriched));
                }
                guard.clear_ready();
            }
            _ = rules_rx.recv() => {
                while rules_rx.try_recv().is_ok() {}
                rule_set = rules::load_dir(&rules_dir);
                info!(count = rule_set.len(), "reloaded rules");
            }
            _ = evict_tick.tick() => {
                let now = Instant::now();
                let before = dns_cache.len();
                dns_cache.retain(|_, e| e.expires_at > now);
                if dns_cache.len() != before {
                    debug!(removed = before - dns_cache.len(), "DNS cache eviction");
                }
            }
        }
    }
}

fn make_rules_watcher(
    dir: &Path,
    tx: mpsc::UnboundedSender<()>,
) -> Option<notify::RecommendedWatcher> {
    if !dir.exists() {
        warn!(dir = %dir.display(), "rules directory does not exist; not watching");
        return None;
    }
    let mut watcher =
        match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if res.is_ok() {
                let _ = tx.send(());
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "could not create rules watcher");
                return None;
            }
        };
    if let Err(e) = watcher.watch(dir, notify::RecursiveMode::NonRecursive) {
        warn!(dir = %dir.display(), error = %e, "could not watch rules dir");
        return None;
    }
    info!(dir = %dir.display(), "watching rules directory");
    Some(watcher)
}

#[derive(Debug)]
struct DnsEntry {
    hostname: String,
    expires_at: Instant,
}

fn ingest_dns(event: &DnsEvent, cache: &mut HashMap<IpAddr, DnsEntry>) {
    let len = event.len as usize;
    if len == 0 || len > event.data.len() {
        return;
    }
    let msg = match Message::from_bytes(&event.data[..len]) {
        Ok(m) => m,
        Err(e) => {
            debug!(len = len, error = %e, "DNS parse failed");
            return;
        }
    };
    let answers = msg.answer_count();
    debug!(len = len, answers = answers, "DNS event");
    if answers == 0 {
        return;
    }
    for record in msg.answers() {
        let name = record.name().to_utf8();
        let name = name.trim_end_matches('.').to_string();
        if name.is_empty() {
            continue;
        }
        let ttl = record.ttl().max(1);
        let expires_at = Instant::now() + Duration::from_secs(ttl as u64);
        let ip = match record.data() {
            Some(RData::A(a)) => IpAddr::V4(a.0),
            Some(RData::AAAA(aaaa)) => IpAddr::V6(aaaa.0),
            _ => continue,
        };
        debug!(ip = %ip, host = %name, ttl = ttl, "DNS cache insert");
        cache.insert(
            ip,
            DnsEntry {
                hostname: name,
                expires_at,
            },
        );
    }
}

fn lookup_host<'a>(event: &ConnectEvent, cache: &'a HashMap<IpAddr, DnsEntry>) -> Option<&'a str> {
    let ip = connect_event_ip(event)?;
    let entry = cache.get(&ip)?;
    if entry.expires_at > Instant::now() {
        Some(&entry.hostname)
    } else {
        None
    }
}

/// Display form of the connection's destination address, in the same format
/// the TUI uses when sending dest_ip in `CreateDenyRule`. Returns None for
/// zero v4 or unknown family.
fn event_ip_string(e: &ConnectEvent) -> Option<String> {
    if e.family == 4 {
        if e.daddr_v4 == 0 {
            return None;
        }
        Some(Ipv4Addr::from(e.daddr_v4.to_ne_bytes()).to_string())
    } else if e.family == 6 {
        Some(Ipv6Addr::from(e.daddr_v6).to_string())
    } else {
        None
    }
}

fn connect_event_ip(event: &ConnectEvent) -> Option<IpAddr> {
    if event.family == 4 {
        if event.daddr_v4 == 0 {
            return None;
        }
        Some(IpAddr::V4(Ipv4Addr::from(event.daddr_v4.to_ne_bytes())))
    } else if event.family == 6 {
        Some(IpAddr::V6(Ipv6Addr::from(event.daddr_v6)))
    } else {
        None
    }
}

fn list_up_interfaces() -> Vec<String> {
    let mut out = Vec::new();
    let dir = match std::fs::read_dir("/sys/class/net") {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "could not read /sys/class/net");
            return out;
        }
    };
    for entry in dir.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let state_path = format!("/sys/class/net/{name}/operstate");
        let Ok(state) = std::fs::read_to_string(&state_path) else {
            continue;
        };
        let state = state.trim();
        if state == "up" || state == "unknown" {
            out.push(name);
        }
    }
    out
}

fn backfill_proc(exe_paths: &mut HashMap<u32, Option<PathBuf>>) {
    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "could not read /proc for backfill");
            return;
        }
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };
        exe_paths.insert(pid, read_proc_exe(pid));
    }
}

fn read_proc_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

fn lookup_exe(pid: u32, exe_paths: &mut HashMap<u32, Option<PathBuf>>) -> Option<PathBuf> {
    if let Some(cached) = exe_paths.get(&pid) {
        return cached.clone();
    }
    let resolved = read_proc_exe(pid);
    exe_paths.insert(pid, resolved.clone());
    resolved
}

fn print_event(e: &ConnectEvent, exe: Option<&str>, host: Option<&str>, verdict: Option<&Verdict>) {
    let comm = comm_str(&e.comm);
    let addr = if e.family == 4 {
        Ipv4Addr::from(e.daddr_v4.to_ne_bytes()).to_string()
    } else {
        format!("[{}]", Ipv6Addr::from(e.daddr_v6))
    };
    let exe_str = exe.unwrap_or("?");
    let host_str = host.unwrap_or("?");
    let (vstr, rstr): (&str, &str) = match verdict {
        Some(v) => (
            match v.action {
                Action::Allow => "allow",
                Action::Deny => "deny",
            },
            v.rule_id.as_str(),
        ),
        None => ("allow", "-"),
    };
    println!(
        "pid={} uid={} comm={} exe={} host={} verdict={} rule={} -> {}:{}",
        e.pid, e.uid, comm, exe_str, host_str, vstr, rstr, addr, e.dport
    );
}

fn comm_str(buf: &[u8; 16]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("?")
}

fn common_flow_key(e: &ConnectEvent) -> FlowKey {
    FlowKey {
        pid: e.pid,
        _pad0: 0,
        start_ns: e.start_ns,
        daddr_v4: e.daddr_v4,
        daddr_v6: e.daddr_v6,
        dport: e.dport,
        family: e.family,
        _pad: 0,
    }
}

// proto<->common FlowKey conversion functions removed: the DecideVerdict
// path that needed them went away with the enforcement pivot. When the
// Step 8 CO-RE work lands a real start_ns and we want to reference flows
// from the TUI again, bring them back.

fn enrich(
    e: &ConnectEvent,
    exe: Option<&str>,
    host: Option<&str>,
    verdict: Option<&Verdict>,
) -> EnrichedEvent {
    let ts_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let (vd, rule) = match verdict {
        Some(v) => (
            match v.action {
                Action::Allow => dadophoros_proto::Verdict::Allow,
                Action::Deny => dadophoros_proto::Verdict::Deny,
            },
            Some(v.rule_id.clone()),
        ),
        None => (dadophoros_proto::Verdict::Allow, None),
    };
    EnrichedEvent {
        ts_unix_ns,
        pid: e.pid,
        uid: e.uid,
        comm: comm_str(&e.comm).to_string(),
        exe_path: exe.map(str::to_owned),
        family: e.family,
        daddr_v4: e.daddr_v4,
        daddr_v6: e.daddr_v6,
        dport: e.dport,
        hostname: host.map(str::to_owned),
        verdict: vd,
        matched_rule: rule,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn comm_str_stops_at_null() {
        let buf = *b"curl\0extra-bytes";
        assert_eq!(comm_str(&buf), "curl");
    }

    #[test]
    fn comm_str_empty_buffer() {
        let buf = [0u8; 16];
        assert_eq!(comm_str(&buf), "");
    }

    #[test]
    fn comm_str_full_buffer_no_null() {
        let buf = *b"abcdefghijklmnop";
        assert_eq!(comm_str(&buf), "abcdefghijklmnop");
    }

    fn ev(family: u8, daddr_v4: u32, daddr_v6: [u8; 16]) -> ConnectEvent {
        ConnectEvent {
            pid: 0,
            uid: 0,
            start_ns: 0,
            daddr_v4,
            daddr_v6,
            dport: 443,
            family,
            _pad: 0,
            comm: [0; 16],
        }
    }

    #[test]
    fn connect_event_ip_v4_decodes_network_order() {
        let e = ev(4, 0x04030201, [0; 16]);
        let ip = connect_event_ip(&e).unwrap();
        assert_eq!(ip, IpAddr::V4("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn connect_event_ip_v6_returns_addr_from_bytes() {
        let bytes: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let e = ev(6, 0, bytes);
        let ip = connect_event_ip(&e).unwrap();
        assert_eq!(ip, IpAddr::V6("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn connect_event_ip_zero_v4_is_none() {
        let e = ev(4, 0, [0; 16]);
        assert!(connect_event_ip(&e).is_none());
    }

    #[test]
    fn connect_event_ip_unknown_family_is_none() {
        let e = ev(255, 0, [0; 16]);
        assert!(connect_event_ip(&e).is_none());
    }

}
