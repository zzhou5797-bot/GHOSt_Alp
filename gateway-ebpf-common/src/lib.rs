#![no_std]

// 60 bytes SPA Payload layout
#[repr(C, packed)]
pub struct SpaPayload {
    pub magic: u32,          // 0x54535054 ("TSPT")
    pub version: u32,        // 0x02
    pub subject: u32,        // User ID / DID truncated hash
    pub seq: u64,            // Big-endian network byte order sequence (descending)
    pub hash: [u8; 8],       // SipHash-2-4 result H_{N-x}
    pub signature: [u8; 32], // Additional cryptographic signature (e.g. Ed25519)
}

impl SpaPayload {
    pub const MAGIC: u32 = 0x54535054;
    pub const VERSION: u32 = 0x02;
    pub const LEN: usize = core::mem::size_of::<SpaPayload>();
}

// BPF Map value for ALLOW_LIST_MAP
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AuthState {
    pub expected_seq: u64,
    pub anchor_hash: [u8; 8],
    pub tokens: u64, // Used for XDP Token Bucket later
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AuthState {}

// Kernel audit event emitted on sys_enter_execve, sent via RingBuf to userspace
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AuditEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub filename: [u8; 128],
    pub args_len: u32,
    pub args: [u8; 256],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AuditEvent {}
