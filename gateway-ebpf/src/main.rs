#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LruHashMap, PerfEventArray};
use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{tracepoint, xdp},
    programs::{TracePointContext, XdpContext},
};
use gateway_ebpf_common::{AuditEvent, AuthState, SpaPayload, SpaPayloadV1};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[map]
static AUTH_STATE_MAP: HashMap<u32, AuthState> = HashMap::with_max_entries(1024, 0);

#[map]
static ALLOW_LIST_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static AUDIT_EVENTS: PerfEventArray<AuditEvent> = PerfEventArray::new(0);

// Cgroup ID allowlist: only sessions whose cgroup_id is in this map will emit audit events
#[map]
static AUDIT_CGROUP_MAP: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

// ── v1 backward-compat maps (dual-stack transition period only) ─────────────
// TIME_DELTA_MAP[0] = UNIX_ns − ktime_ns offset, written by server at startup.
#[map]
static TIME_DELTA_MAP: Array<u64> = Array::with_max_entries(1, 0);

// REPLAY_FILTER_MAP: LRU of seen v1 timestamps to prevent replay attacks.
// Each entry is (timestamp_ns → 1). LRU capacity = 4096 entries ≈ 4096 unique knocks.
#[map]
static REPLAY_FILTER_MAP: LruHashMap<u64, u8> = LruHashMap::with_max_entries(4096, 0);

// Subject ID used for v1 (legacy) sessions — all share a single AuthState slot.
const V1_SUBJECT: u32 = 0xFFFF_FFFE;

#[inline(always)]
fn rotate_left(x: u64, b: u32) -> u64 {
    (x << b) | (x >> (64 - b))
}

#[inline(always)]
fn siphash24_compress(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = rotate_left(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotate_left(*v0, 32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = rotate_left(*v3, 16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = rotate_left(*v3, 21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = rotate_left(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotate_left(*v2, 32);
}

// Minimal SipHash-2-4 tailored for exactly 16 bytes of message (Magic + Version + Timestamp)
// and an 8-byte output, designed for strict BPF verifier compliance and zero allocation.
// The message is composed of 2 u64 words: [magic_version, timestamp].
#[inline(always)]
pub fn siphash24_16b(k0: u64, k1: u64, m0: u64, m1: u64) -> [u8; 8] {
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let b = (16 as u64) << 56;

    v3 ^= m0;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m0;

    v3 ^= m1;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m1;

    v3 ^= b;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);

    let h = v0 ^ v1 ^ v2 ^ v3;
    h.to_le_bytes()
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// \u2500\u2500 v1 Knock Handler (legacy timestamp-based SPA) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
// Called when version == 1. Performs:
//   1. Parse SpaPayloadV1 (timestamp_ns)
//   2. Convert ktime to unix_ns via TIME_DELTA_MAP[0]
//   3. Check |timestamp - unix_now| <= 60 s (recency window)
//   4. Anti-replay check via REPLAY_FILTER_MAP
//   5. Bootstrap AuthState for V1_SUBJECT (limited: 1 token, no quota)
//   6. Bind source IP in ALLOW_LIST_MAP → V1_SUBJECT
// Always returns XDP_DROP (silent knock; QUIC connect triggers the real check).
#[inline(always)]
fn handle_v1_knock(ctx: &XdpContext, payload_offset: usize, ipv4_source: u32) -> Result<u32, ()> {
    const V1_WINDOW_NS: u64 = 60_000_000_000; // 60 seconds

    let v1_payload: *const SpaPayloadV1 = unsafe { ptr_at(ctx, payload_offset)? };
    let timestamp_ns = u64::from_be(unsafe {
        core::ptr::read_unaligned(core::ptr::addr_of!((*v1_payload).timestamp_ns))
    });

    // Get ktime-\u003eunix offset from TIME_DELTA_MAP
    let time_delta = match unsafe { TIME_DELTA_MAP.get(0) } {
        Some(d) => *d,
        None => return Ok(xdp_action::XDP_DROP), // Server not initialized
    };
    let ktime_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let unix_now = ktime_ns.saturating_add(time_delta);

    // Recency check: reject packets outside the 60 s window
    let diff = if unix_now > timestamp_ns {
        unix_now - timestamp_ns
    } else {
        timestamp_ns - unix_now
    };
    if diff > V1_WINDOW_NS {
        return Ok(xdp_action::XDP_DROP);
    }

    // Anti-replay: drop if this timestamp was already seen
    if unsafe { REPLAY_FILTER_MAP.get(&timestamp_ns) }.is_some() {
        return Ok(xdp_action::XDP_DROP);
    }
    // Mark as seen (LRU evicts oldest entry automatically)
    let _ = unsafe { REPLAY_FILTER_MAP.insert(&timestamp_ns, &1u8, 0) };

    let v1_auth = AuthState {
        expected_seq: 0,
        anchor_hash_lo: 0,
        bucket_tokens: 1, // One-shot: enough for the QUIC handshake
        last_refill_ns: ktime_ns,
        quota_bytes: 1_000_000_000,
        last_seen_quota_seq: 0,
        revoked: 0, // 1 GiB default quota for legacy sessions
    };
    let _ = unsafe { AUTH_STATE_MAP.insert(&V1_SUBJECT, &v1_auth, 0) };

    // Bind source IP to V1_SUBJECT so the hot path lets QUIC through
    let _ = unsafe { ALLOW_LIST_MAP.insert(&ipv4_source, &V1_SUBJECT, 0) };

    Ok(xdp_action::XDP_DROP) // Silent knock — QUIC layer does the rest
}

#[xdp]
pub fn gateway_ebpf(ctx: XdpContext) -> u32 {
    match try_gateway_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_gateway_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Parse Ethernet Header
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    if ether_type != (EtherType::Ipv4 as u16) {
        return Ok(xdp_action::XDP_PASS); // Ignore non-IPv4
    }

    // 2. Parse IPv4 Header
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let ipv4_source = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    match unsafe { (*ipv4hdr).proto } {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS), // Ignore non-UDP
    }

    let ipv4hdr_len = (unsafe { (*ipv4hdr).ihl() } as usize) * 4;

    // 3. Parse UDP Header
    let udp_offset = EthHdr::LEN + ipv4hdr_len;
    let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, udp_offset)? };

    // Only intercept our Gateway port (8080)
    let dest_port = u16::from_be_bytes(unsafe { (*udphdr).dst });
    if dest_port != 8080 {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Hot path: Token-Bucket rate limiter for authorized QUIC traffic ──────
    // For every known-authorized IP, refill tokens based on elapsed kernel time,
    // then deduct one token per packet. If the bucket is empty, XDP_DROP.
    // This prevents spoofed-IP floods from consuming user-space quota.
    if let Some(user_id) = unsafe { ALLOW_LIST_MAP.get(&ipv4_source) } {
        let state_ptr = match unsafe { AUTH_STATE_MAP.get_ptr_mut(user_id) } {
            Some(p) => p,
            None => return Ok(xdp_action::XDP_DROP),
        };

        let mut st = unsafe { core::ptr::read_volatile(state_ptr) };

        // Refill: compute elapsed ns since last refill, add earned tokens
        let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let elapsed = now_ns.saturating_sub(st.last_refill_ns);
        let earned = elapsed / AuthState::REFILL_INTERVAL_NS; // 1 token per 1 ms

        if earned > 0 {
            st.bucket_tokens = (st.bucket_tokens.saturating_add(earned)).min(AuthState::MAX_TOKENS);
            st.last_refill_ns = now_ns;
        }

        // Deduct one token for this packet
        if st.bucket_tokens == 0 {
            // Bucket empty → soft-drop flood traffic; state unchanged
            return Ok(xdp_action::XDP_DROP);
        }
        st.bucket_tokens -= 1;

        // Write updated state back
        unsafe { core::ptr::write_volatile(state_ptr, st) };

        return Ok(xdp_action::XDP_PASS); // Authorized and within rate limit
    }

    let udp_len = u16::from_be_bytes(unsafe { (*udphdr).len }) as usize;
    if udp_len < UdpHdr::LEN {
        // Drop malformed packets to prevent integer underflow
        return Ok(xdp_action::XDP_DROP);
    }

    let payload_offset = udp_offset + UdpHdr::LEN;
    let payload_len = udp_len - UdpHdr::LEN;

    if payload_len < SpaPayload::LEN {
        // Too short for SPA Payload, potentially a blind scan
        // info!(&ctx, "XDP_DROP: Port 8080 blind scan or invalid length");
        return Ok(xdp_action::XDP_DROP);
    }

    let payload: *const SpaPayload = unsafe { ptr_at(&ctx, payload_offset)? };

    // 5. Magic Number Check
    let magic =
        u32::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*payload).magic)) });
    if magic != SpaPayload::MAGIC {
        // info!(&ctx, "XDP_DROP: Invalid SPA magic number");
        return Ok(xdp_action::XDP_DROP);
    }

    let version =
        u32::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*payload).version)) });

    // ── Version Discriminator: route to the correct SPA verification path ────────
    if version == SpaPayloadV1::VERSION {
        return handle_v1_knock(&ctx, payload_offset, ipv4_source);
    }

    // ── V2: Hash Chain path (current) ────────────────────────────────────────────
    let subject =
        u32::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*payload).subject)) });
    let seq =
        u64::from_be(unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*payload).seq)) });
    let packet_hash = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*payload).hash)) };

    // 6. Look up User Auth State
    let auth_state_ptr = match unsafe { AUTH_STATE_MAP.get_ptr_mut(&subject) } {
        Some(ptr) => ptr,
        None => return Ok(xdp_action::XDP_DROP), // Unknown user/DID subject
    };

    let mut auth_state = unsafe { core::ptr::read_volatile(auth_state_ptr) };

    // ── Phase 3.3 & 3.4 0-Day Immunity ──────────────────────────────────────
    if auth_state.revoked > 0 {
        return Ok(xdp_action::XDP_DROP); // Subject is slashed, kill connection at NIC
    }

    // 7. Hash Chain Sequence Validation
    if seq >= auth_state.expected_seq {
        return Ok(xdp_action::XDP_DROP); // Replay attack or old packet (seq must be strictly descending)
    }

    let delta = auth_state.expected_seq - seq;
    if delta > 10 {
        return Ok(xdp_action::XDP_DROP); // Exceeds lookahead window max (10 drops max)
    }

    // 8. O(1) Bounded Hash Verification Loop (#pragma unroll equivalent)
    let secret_k0: u64 = 0x04030201efbeadde;
    let secret_k1: u64 = 0x0d0c0b0affe0dcba;

    let mut current_hash = packet_hash;

    for i in 0..10 {
        if (i as u64) < delta {
            let mut m0_bytes = [0u8; 8];
            m0_bytes.copy_from_slice(&current_hash);
            let m0 = u64::from_le_bytes(m0_bytes);
            let m1 = 0; // padding for 16b SipHash
            current_hash = siphash24_16b(secret_k0, secret_k1, m0, m1);
        }
    }

    let mut match_ok = true;
    for i in 0..8 {
        let anchor_byte = ((auth_state.anchor_hash_lo >> (i * 8)) & 0xFF) as u8;
        if current_hash[i] != anchor_byte {
            match_ok = false;
        }
    }

    if !match_ok {
        return Ok(xdp_action::XDP_DROP); // Invalid Hash Preimage
    }

    // 9. State Fast-Forward & Bucket Bootstrap on first SPA accept
    auth_state.expected_seq = seq;
    auth_state.anchor_hash_lo = u64::from_le_bytes(packet_hash);

    // Initialise the token bucket on the very first admission (last_refill_ns == 0)
    // or replenish after a fresh knock (new QUIC session starting).
    let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    auth_state.bucket_tokens = AuthState::MAX_TOKENS; // full burst on connect
    auth_state.last_refill_ns = now_ns;

    // quota_bytes is set by userspace after the QUIC handshake (Phase 2);
    // leave it untouched here so repeated SPA knocks don't reset the quota.

    // Atomically write back state
    unsafe { core::ptr::write_volatile(auth_state_ptr, auth_state) };

    // Bind this IP to the subject
    let _ = ALLOW_LIST_MAP.insert(&ipv4_source, &subject, 0);

    Ok(xdp_action::XDP_DROP) // Drop the knock packet itself silently
}

// Tracepoint hook: fires on every execve(2) syscall entry in the kernel
#[tracepoint]
pub fn audit_execve(ctx: TracePointContext) -> u32 {
    match try_audit_execve(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_audit_execve(ctx: TracePointContext) -> Result<(), ()> {
    // Check if the current process belongs to a tracked cgroup
    let cgroup_id = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    if unsafe { AUDIT_CGROUP_MAP.get(&cgroup_id).is_none() } {
        return Ok(()); // Not a tracked session
    }

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xffff_ffff) as u32;
    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let uid = (uid_gid & 0xffff_ffff) as u32;

    // Build AuditEvent on the BPF stack (no heap)
    let mut event = AuditEvent {
        cgroup_id,
        pid,
        tid,
        uid,
        filename: [0u8; 128],
        args_len: 0,
        args: [0u8; 256],
    };

    // sys_enter_execve: +0 struct trace_entry (8), +8 __syscall_nr (4 + 4 pad), +16 filename*, +24 argv**, +32 envp**
    let filename_ptr: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    unsafe {
        let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
            filename_ptr as *const u8,
            &mut event.filename,
        );
    }

    let argv_ptr: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => {
            unsafe { AUDIT_EVENTS.output(&ctx, &event, 0) };
            return Ok(());
        }
    };

    let mut num_args = 0;

    // Read up to 5 arguments from argv into fixed-size chunks to satisfy BPF verifier
    for i in 0..5 {
        let arg_ptr_addr = (argv_ptr as usize + i * core::mem::size_of::<u64>()) as *const u64;
        let arg_ptr: u64 = match unsafe { aya_ebpf::helpers::bpf_probe_read_user(arg_ptr_addr) } {
            Ok(v) => v,
            Err(_) => break,
        };

        if arg_ptr == 0 {
            break; // Null terminator of argv array
        }

        let dest = match i {
            0 => &mut event.args[0..51],
            1 => &mut event.args[51..102],
            2 => &mut event.args[102..153],
            3 => &mut event.args[153..204],
            4 => &mut event.args[204..255],
            _ => break,
        };

        let _ =
            unsafe { aya_ebpf::helpers::bpf_probe_read_user_str_bytes(arg_ptr as *const u8, dest) };
        num_args += 1;
    }

    event.args_len = num_args as u32;

    unsafe { AUDIT_EVENTS.output(&ctx, &event, 0) };
    Ok(())
}
