#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ConnectEvent {
    pub pid: u32,
    pub uid: u32,
    pub daddr_v4: u32,
    pub daddr_v6: [u8; 16],
    pub dport: u16,
    pub family: u8,
    pub _pad: u8,
    pub comm: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<ConnectEvent>() == 48);

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub _pad: u32,      // align start_ns to 8 bytes
    pub start_ns: u64,  // task->start_boottime, populated in later steps via CO-RE
    pub exe_inode: u64, // populated in step 8 (binary hashing)
    pub comm: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<ProcessInfo>() == 48);

pub const DNS_PAYLOAD_MAX: usize = 512;

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct DnsEvent {
    pub len: u16,
    pub _pad: [u8; 6],
    pub data: [u8; DNS_PAYLOAD_MAX],
}

const _: () = assert!(core::mem::size_of::<DnsEvent>() == 520);
