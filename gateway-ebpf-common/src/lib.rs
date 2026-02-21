#![no_std]

// 48 bytes SPA Payload layout
#[repr(C, packed)]
pub struct SpaPayload {
    pub magic: u32,          // 0x54535054 ("TSPT")
    pub version: u32,        // 0x01
    pub timestamp_ns: u64,   // Big-endian network byte order Unix Nano
    pub signature: [u8; 32], // SipHash / Blake3
}

impl SpaPayload {
    pub const MAGIC: u32 = 0x54535054;
    pub const VERSION: u32 = 0x01;
    pub const LEN: usize = core::mem::size_of::<SpaPayload>();
}

// Kernel audit event emitted on sys_enter_execve, sent via RingBuf to userspace
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AuditEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub filename: [u8; 128],
    pub args_len: u32,
    pub args: [u8; 256],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AuditEvent {}
