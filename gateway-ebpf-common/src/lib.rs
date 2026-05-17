#![no_std]

//! Types shared between the eBPF kernel programs and the userspace server.
//!
//! This crate is `no_std` so it can be compiled for both targets:
//!   - `bpfel-unknown-none` (kernel BPF programs via `aya-ebpf`)
//!   - host architecture (server via `aya` with the `user` feature)
//!
//! The `user` feature enables `aya::Pod` impls, which are required by the
//! userspace map accessors but forbidden in the kernel target.

// ── SPA v2 knock packet (current protocol) ───────────────────────────────────

/// 60-byte Single Packet Authorization payload (protocol version 2).
///
/// The XDP program reads this struct directly from the UDP payload.
/// All multi-byte fields are big-endian on the wire.
///
/// Layout: magic(4) + version(4) + subject(4) + seq(8) + hash(8) + signature(32)
#[repr(C, packed)]
pub struct SpaPayload {
    /// Magic bytes `0x54535054` ("TSPT" in ASCII).
    pub magic: u32,
    /// Protocol version — must be `0x02` for this struct.
    pub version: u32,
    /// Numeric DID subject (key into `AUTH_STATE_MAP`).
    pub subject: u32,
    /// Current sequence number (big-endian, strictly descending per session).
    pub seq: u64,
    /// SipHash-2-4 tag `H_{N-x}`: a preimage relative to the stored anchor.
    pub hash: [u8; 8],
    /// Reserved for future Ed25519 binding (ignored by current XDP verifier).
    pub signature: [u8; 32],
}

impl SpaPayload {
    pub const MAGIC: u32 = 0x54535054;
    pub const VERSION: u32 = 0x02;
    pub const LEN: usize = core::mem::size_of::<SpaPayload>();
}

// ── SPA v1 knock packet (legacy, backward-compat window) ─────────────────────

/// 48-byte Single Packet Authorization payload (protocol version 1).
///
/// Version-1 clients authenticate with a UNIX timestamp instead of a hash
/// chain.  Accepted only within a ±60-second recency window; replay-filtered
/// via `REPLAY_FILTER_MAP`.  New clients should use v2.
///
/// Layout: magic(4) + version(4) + _pad(4) + timestamp_ns(8) + signature(8) + pad(24)
#[repr(C, packed)]
pub struct SpaPayloadV1 {
    pub magic: u32,
    /// Protocol version — must be `0x01` for this struct.
    pub version: u32,
    pub _pad: u32,
    /// UNIX timestamp in nanoseconds sent by the client.
    pub timestamp_ns: u64,
    /// SipHash-2-4 over `(magic | version, timestamp_ns)` using the shared secret.
    pub signature: [u8; 8],
}

impl SpaPayloadV1 {
    pub const MAGIC: u32 = 0x54535054;
    pub const VERSION: u32 = 0x01;
    pub const LEN: usize = core::mem::size_of::<SpaPayloadV1>();
}

// ── Per-DID authentication and rate-limit state (BPF map value) ──────────────

/// `AUTH_STATE_MAP` value: combines hash-chain state, token-bucket rate limiter,
/// quota counter, and revocation flag in a single 56-byte struct.
///
/// All fields are `u64` to guarantee 8-byte alignment for the BPF verifier.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AuthState {
    // Hash-chain verifier ──────────────────────────────────────────────────────
    /// Next accepted sequence number (strictly descending; higher = older knock).
    pub expected_seq: u64,
    /// Lower 8 bytes of the current anchor hash `H_N`, stored as little-endian u64.
    pub anchor_hash_lo: u64,

    // Token-bucket rate limiter ───────────────────────────────────────────────
    /// Remaining burst tokens.  Each admitted packet consumes one token.
    pub bucket_tokens: u64,
    /// Kernel monotonic timestamp (ns) of the last token refill.
    pub last_refill_ns: u64,

    // Quota tracking ─────────────────────────────────────────────────────────
    /// Remaining payload quota in bytes.  Decremented by userspace; when 0 the
    /// session is tombstoned by the GC daemon.
    pub quota_bytes: u64,
    /// Sequence number of the last quota-sync gossip message applied locally.
    /// Used to discard stale or replayed quota deltas.
    pub last_seen_quota_seq: u64,

    // Revocation flag ────────────────────────────────────────────────────────
    /// When non-zero, the XDP hot path drops all packets from this subject at
    /// NIC speed.  Set by the userspace BFT consensus handler.
    pub revoked: u64,
}

impl AuthState {
    /// Maximum burst size: 512 packets before the token bucket runs dry.
    pub const MAX_TOKENS: u64 = 512;
    /// Refill interval: one token per millisecond → ~1000 pps sustained throughput.
    pub const REFILL_INTERVAL_NS: u64 = 1_000_000;
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AuthState {}

// ── Kernel audit event ───────────────────────────────────────────────────────

/// Emitted by `audit_execve` on every `sys_enter_execve` inside a tracked cgroup.
/// Sent to userspace via `AUDIT_EVENTS` (perf event array).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AuditEvent {
    /// cgroupv2 numeric ID of the session that triggered the execve.
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    /// NUL-terminated executable path read from the syscall argument.
    pub filename: [u8; 128],
    /// Number of valid argv entries captured (max 5).
    pub args_len: u32,
    /// Up to 5 argument strings, each 51 bytes, NUL-terminated.
    pub args: [u8; 256],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AuditEvent {}

// ── Sovereign ring-buffer item ────────────────────────────────────────────────

/// Wire layout of a raw packet forwarded by the XDP sovereign filter into
/// `SOVEREIGN_RB`.  The filter that populates this ring buffer is not part of
/// this repository; without it `SOVEREIGN_RB` is always empty.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SovereignItem {
    pub data: [u8; 128],
    pub len: u32,
    pub ts_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SovereignItem {}

