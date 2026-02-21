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

// BPF Map value that tracks per-DID authentication state AND rate-limiting.
// All fields are u64 to keep the struct naturally aligned for the BPF verifier.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AuthState {
    // ── Hash-chain verifier (Phase 1.1) ────────────────────────────────────
    pub expected_seq: u64, // Next required sequence number (strictly descending)
    pub anchor_hash_lo: u64, // Lower 8 bytes of current anchor H_N  (as u64 LE)

    // ── Token Bucket rate-limiter (Phase 1.2) ──────────────────────────────
    /// Current number of token-bucket tokens (each token = 1 allowed packet).
    /// Replenished at REFILL_RATE tokens/ns up to MAX_TOKENS.
    pub bucket_tokens: u64,
    /// Kernel monotonic timestamp (ns) of the last token refill.
    pub last_refill_ns: u64,

    // ── Quota tracking (Phase 2.1) ─────────────────────────────────────────
    /// Remaining bytes of payload quota. Decremented by userspace after AEAD decrypt.
    /// When 0, userspace calls bpf_map_delete_elem to disconnect.
    pub quota_bytes: u64,
}

impl AuthState {
    /// Maximum burst size: allow up to 512 packets before throttling.
    pub const MAX_TOKENS: u64 = 512;
    /// Replenish one token every 1 ms = 1_000_000 ns → ~1000 pps sustained rate.
    pub const REFILL_INTERVAL_NS: u64 = 1_000_000;
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
