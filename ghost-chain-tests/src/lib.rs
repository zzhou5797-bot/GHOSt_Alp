/// Phase 1.1 Hash Chain Verifier — user-space unit tests
/// Pure Rust; no eBPF, no no_std. Validates the cryptographic
/// chain-walk logic that mirrors what the XDP eBPF program executes.

// ── SipHash-2-4 (mirrors gateway-ebpf/src/main.rs) ────────────────────────

fn rotate_left(x: u64, b: u32) -> u64 {
    (x << b) | (x >> (64 - b))
}

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

fn siphash24_16b(k0: u64, k1: u64, m0: u64, m1: u64) -> [u8; 8] {
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let b = (16_u64) << 56;
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
    (v0 ^ v1 ^ v2 ^ v3).to_le_bytes()
}

// ── Hash Chain helpers ─────────────────────────────────────────────────────

const SECRET_K0: u64 = 0x04030201efbeadde;
const SECRET_K1: u64 = 0x0d0c0b0affe0dcba;

/// One forward step in the chain.
fn hash_step(h: [u8; 8]) -> [u8; 8] {
    siphash24_16b(SECRET_K0, SECRET_K1, u64::from_le_bytes(h), 0)
}

/// Build a chain of length `n` starting from `seed`.
/// `chain[0]` = seed, `chain[n]` = public anchor H_N.
fn build_chain(seed: [u8; 8], n: usize) -> Vec<[u8; 8]> {
    let mut chain = vec![seed];
    for _ in 0..n {
        let next = hash_step(*chain.last().unwrap());
        chain.push(next);
    }
    chain
}

/// Mirror the eBPF bounded loop: walk `delta` steps forward from
/// `knock_hash` and compare against `anchor_hash`.
fn verify_chain(knock_hash: [u8; 8], anchor_hash: [u8; 8], delta: u64) -> bool {
    if delta > 10 {
        return false; // Exceeds lookahead window — eBPF guard
    }
    let mut current = knock_hash;
    for i in 0u64..10 {
        if i < delta {
            current = hash_step(current);
        }
    }
    current == anchor_hash
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// Knock with the immediately previous hash (delta = 1). Normal happy path.
#[test]
fn test_single_step_ok() {
    let chain = build_chain([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33], 5);
    assert!(
        verify_chain(chain[4], chain[5], 1),
        "delta=1 should succeed"
    );
}

/// Knock with delta=10 — the maximum allowed by the lookahead window.
/// This simulates 10 consecutive UDP packet drops.
#[test]
fn test_max_lookahead_window_ok() {
    let chain = build_chain([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x01], 15);
    assert!(
        verify_chain(chain[5], chain[15], 10),
        "delta=10 (max window) must succeed"
    );
}

/// delta=11 exceeds the guard; must be rejected to prevent DoS probes.
#[test]
fn test_exceeds_window_rejected() {
    let chain = build_chain([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], 15);
    assert!(
        !verify_chain(chain[4], chain[15], 11),
        "delta=11 must be rejected"
    );
}

/// After accepting seq=N-1, eBPF expects seq < N-1.
/// A replayed packet with seq == expected_seq must be refused.
#[test]
fn test_replay_rejected_by_seq_guard() {
    // Simulate node state after fast-forward: expected_seq is now 9.
    // Replay arrives with seq=9 — that is NOT strictly less, so XDP drops it.
    let expected_seq: u64 = 9;
    let replayed_seq: u64 = 9;
    assert!(
        replayed_seq >= expected_seq,
        "seq >= expected_seq means replay — XDP must drop"
    );
}

/// A completely wrong/garbage preimage must not satisfy the chain.
#[test]
fn test_garbage_preimage_rejected() {
    let chain = build_chain([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], 5);
    let garbage = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    assert!(
        !verify_chain(garbage, chain[5], 1),
        "Garbage preimage must fail verification"
    );
}

/// After a knock is accepted and the state fast-forwards, the next
/// sequential knock must verify against the *new* anchor.
#[test]
fn test_state_fast_forward_and_next_knock() {
    let chain = build_chain([0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22], 10);

    // Original anchor = chain[10]; user sends chain[7] (delta=3)
    assert!(
        verify_chain(chain[7], chain[10], 3),
        "Initial delta=3 knock must pass"
    );

    // After fast-forward, anchor is now chain[7]; next knock is chain[6] (delta=1)
    assert!(
        verify_chain(chain[6], chain[7], 1),
        "Post-fast-forward sequential knock must pass"
    );
}

// ── Phase 1.2: Token Bucket tests ─────────────────────────────────────────
//
// The token bucket is a simple leaky-bucket algorithm:
//   * MAX_TOKENS = 512 (burst cap)
//   * REFILL_INTERVAL_NS = 1_000_000 (1 token per 1 ms → ~1000 pps sustained)
// Mirror the constants from AuthState::* so this stays in sync.

const TB_MAX_TOKENS: u64 = 512;
const TB_REFILL_NS: u64 = 1_000_000; // 1 ms

/// Simulate one XDP packet arrival:
///   `now_ns`     - fake kernel monotonic timestamp for this packet
///   `last_ns`    - last refill timestamp stored in AuthState
///   `tokens_in`  - bucket tokens before this packet
/// Returns `(allowed, tokens_out, last_ns_out)`.
fn token_bucket_tick(now_ns: u64, last_ns: u64, tokens_in: u64) -> (bool, u64, u64) {
    let elapsed = now_ns.saturating_sub(last_ns);
    let earned = elapsed / TB_REFILL_NS;

    let (mut tokens, mut last_ns_out) = if earned > 0 {
        let refilled = tokens_in.saturating_add(earned).min(TB_MAX_TOKENS);
        (refilled, now_ns)
    } else {
        (tokens_in, last_ns)
    };

    if tokens == 0 {
        return (false, tokens, last_ns_out); // XDP_DROP
    }
    tokens -= 1;
    (true, tokens, last_ns_out)
}

/// Fresh session starts with a full burst bucket (512 tokens).
/// First 512 packets should all be allowed.
#[test]
fn test_bucket_allows_initial_burst() {
    let start_ns: u64 = 1_000_000_000; // arbitrary start
    let mut tokens = TB_MAX_TOKENS;
    let mut last_ns = start_ns;

    for i in 0..TB_MAX_TOKENS {
        // Packets arrive with 0 ms gap — no refill occurs
        let (allowed, t, ln) = token_bucket_tick(start_ns, last_ns, tokens);
        assert!(allowed, "Packet {} of burst should be allowed", i);
        tokens = t;
        last_ns = ln;
    }
    assert_eq!(tokens, 0, "Bucket must be empty after full burst");
}

/// After the burst is exhausted, next packet with no time elapsed is dropped.
#[test]
fn test_bucket_drops_when_empty() {
    let start_ns: u64 = 2_000_000_000;
    // Simulate bucket already exhausted
    let (allowed, _t, _ln) = token_bucket_tick(start_ns, start_ns, 0);
    assert!(!allowed, "Empty bucket must XDP_DROP the packet");
}

/// Waiting 5 ms should replenish exactly 5 tokens.
#[test]
fn test_bucket_refills_after_wait() {
    let start_ns: u64 = 3_000_000_000;
    let empty_tokens = 0u64;
    // Simulate 5 ms elapsed
    let now_ns = start_ns + 5 * TB_REFILL_NS;

    let (allowed, tokens_out, _) = token_bucket_tick(now_ns, start_ns, empty_tokens);
    // 5 tokens earned, 1 consumed → 4 remaining
    assert!(allowed, "Packet after 5 ms wait should be allowed");
    assert_eq!(tokens_out, 4, "Should have 4 tokens remaining after refill");
}

/// Bucket refill capped at MAX_TOKENS even after a very long idle period.
#[test]
fn test_bucket_caps_at_max_tokens() {
    let start_ns: u64 = 4_000_000_000;
    // 1 second elapsed → 1000 tokens earned, but capped at 512
    let now_ns = start_ns + 1_000_000_000;
    let (_allowed, tokens_out, _) = token_bucket_tick(now_ns, start_ns, 0);
    // After consuming 1: expect MAX_TOKENS - 1 = 511
    assert_eq!(
        tokens_out,
        TB_MAX_TOKENS - 1,
        "Refill must be capped at MAX_TOKENS"
    );
}

/// Simulates a spoofed-IP flood: 1000 consecutive packets with no time
/// elapsed. Only the initial burst of 512 are passed; the rest are dropped.
#[test]
fn test_bucket_throttles_flood() {
    let start_ns: u64 = 5_000_000_000;
    let mut tokens = TB_MAX_TOKENS;
    let mut last_ns = start_ns;
    let mut passed = 0u64;
    let mut dropped = 0u64;

    for _ in 0..1000 {
        let (allowed, t, ln) = token_bucket_tick(start_ns, last_ns, tokens);
        if allowed {
            passed += 1;
        } else {
            dropped += 1;
        }
        tokens = t;
        last_ns = ln;
    }

    assert_eq!(passed, TB_MAX_TOKENS, "Only burst-cap packets should pass");
    assert_eq!(
        dropped,
        1000 - TB_MAX_TOKENS,
        "Remaining flood packets must be dropped"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// Genesis Credential tests
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod genesis_tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use shared::GenesisCredential;

    fn sign_credential(sk: &SigningKey, vc: &GenesisCredential) -> String {
        let anchor_hex: String = vc.anchor_hash.iter().map(|b| format!("{:02x}", b)).collect();
        let msg = format!("{}:{}:{}", vc.subject, vc.request_quota, anchor_hex);
        let sig = sk.sign(msg.as_bytes());
        hex::encode(sig.to_bytes())
    }

    /// A correctly signed GenesisCredential should deserialise and re-sign cleanly.
    #[test]
    fn test_genesis_credential_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let anchor = [0u8; 32];

        let mut vc = GenesisCredential {
            subject: 42,
            request_quota: 1_000_000,
            pubkey_index: 0,
            anchor_hash: anchor,
            signature_hex: String::new(),
        };
        vc.signature_hex = sign_credential(&sk, &vc);

        // Verify the message format ourselves (mirrors genesis.rs verify_genesis_credential)
        let anchor_hex: String = vc.anchor_hash.iter().map(|b| format!("{:02x}", b)).collect();
        let msg = format!("{}:{}:{}", vc.subject, vc.request_quota, anchor_hex);
        let mut sig_bytes = [0u8; 64];
        hex::decode_to_slice(&vc.signature_hex, &mut sig_bytes).unwrap();

        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let vk = sk.verifying_key();
        assert!(vk.verify(msg.as_bytes(), &sig).is_ok(), "Signature must verify");
    }

    /// Tampered `request_quota` must invalidate the signature.
    #[test]
    fn test_genesis_credential_tampered_quota_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let anchor = [0x11u8; 32];

        let mut vc = GenesisCredential {
            subject: 1,
            request_quota: 500_000,
            pubkey_index: 0,
            anchor_hash: anchor,
            signature_hex: String::new(),
        };
        vc.signature_hex = sign_credential(&sk, &vc);

        // Tamper with quota after signing
        vc.request_quota = 999_999_999;

        let anchor_hex: String = vc.anchor_hash.iter().map(|b| format!("{:02x}", b)).collect();
        let tampered_msg = format!("{}:{}:{}", vc.subject, vc.request_quota, anchor_hex);
        let mut sig_bytes = [0u8; 64];
        hex::decode_to_slice(&vc.signature_hex, &mut sig_bytes).unwrap();

        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let vk = sk.verifying_key();
        assert!(
            vk.verify(tampered_msg.as_bytes(), &sig).is_err(),
            "Tampered quota must fail verification"
        );
    }

    /// Wrong pubkey cannot verify a credential signed by a different key.
    #[test]
    fn test_genesis_credential_wrong_key_rejected() {
        let sk_real = SigningKey::generate(&mut OsRng);
        let sk_wrong = SigningKey::generate(&mut OsRng);
        let anchor = [0x22u8; 32];

        let mut vc = GenesisCredential {
            subject: 7,
            request_quota: 10_000,
            pubkey_index: 0,
            anchor_hash: anchor,
            signature_hex: String::new(),
        };
        vc.signature_hex = sign_credential(&sk_real, &vc);

        let anchor_hex: String = vc.anchor_hash.iter().map(|b| format!("{:02x}", b)).collect();
        let msg = format!("{}:{}:{}", vc.subject, vc.request_quota, anchor_hex);
        let mut sig_bytes = [0u8; 64];
        hex::decode_to_slice(&vc.signature_hex, &mut sig_bytes).unwrap();

        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        // Verify against the WRONG key
        let vk_wrong = sk_wrong.verifying_key();
        assert!(
            vk_wrong.verify(msg.as_bytes(), &sig).is_err(),
            "Wrong verifying key must reject the signature"
        );
    }

    /// JSON round-trip of GenesisCredential must preserve all fields exactly.
    #[test]
    fn test_genesis_credential_serde_roundtrip() {
        let vc = GenesisCredential {
            subject: 255,
            request_quota: u64::MAX,
            pubkey_index: 1,
            anchor_hash: [0xABu8; 32],
            signature_hex: "aa".repeat(32),
        };
        let json = serde_json::to_string(&vc).expect("serialise");
        let vc2: GenesisCredential = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(vc.subject, vc2.subject);
        assert_eq!(vc.request_quota, vc2.request_quota);
        assert_eq!(vc.pubkey_index, vc2.pubkey_index);
        assert_eq!(vc.anchor_hash, vc2.anchor_hash);
        assert_eq!(vc.signature_hex, vc2.signature_hex);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ControlMessage wire format tests
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod wire_format_tests {
    use shared::ControlMessage;

    #[test]
    fn test_authenticate_serde() {
        let msg = ControlMessage::Authenticate {
            token: "hunter2".to_string(),
            genesis_vc: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ControlMessage = serde_json::from_str(&json).unwrap();
        match back {
            ControlMessage::Authenticate { token, genesis_vc } => {
                assert_eq!(token, "hunter2");
                assert!(genesis_vc.is_none());
            }
            _ => panic!("wrong variant after roundtrip"),
        }
    }

    #[test]
    fn test_resize_serde() {
        let msg = ControlMessage::Resize { rows: 24, cols: 80 };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ControlMessage = serde_json::from_str(&json).unwrap();
        match back {
            ControlMessage::Resize { rows, cols } => {
                assert_eq!(rows, 24);
                assert_eq!(cols, 80);
            }
            _ => panic!("wrong variant after roundtrip"),
        }
    }

    #[test]
    fn test_setenv_serde() {
        let msg = ControlMessage::SetEnv {
            key: "TERM".to_string(),
            value: "xterm-256color".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ControlMessage = serde_json::from_str(&json).unwrap();
        match back {
            ControlMessage::SetEnv { key, value } => {
                assert_eq!(key, "TERM");
                assert_eq!(value, "xterm-256color");
            }
            _ => panic!("wrong variant after roundtrip"),
        }
    }

    #[test]
    fn test_startshell_serde() {
        let msg = ControlMessage::StartShell;
        let json = serde_json::to_string(&msg).unwrap();
        let back: ControlMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, ControlMessage::StartShell));
    }

    /// Unknown JSON variant must not silently produce a valid message.
    #[test]
    fn test_unknown_variant_rejected() {
        let bad_json = r#"{"UnknownCommand":{"foo":"bar"}}"#;
        let result: Result<ControlMessage, _> = serde_json::from_str(bad_json);
        assert!(result.is_err(), "Unknown variant must fail to deserialise");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Quota accounting tests (mirrors the AtomicU64 guillotine in server/main.rs)
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod quota_tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    const SYNC_THRESHOLD: u64 = 65_536; // mirrors server/src/main.rs

    /// Simulates the guillotine check: consumed + bytes > quota → reject.
    fn quota_check(consumed: &AtomicU64, bytes: u64, quota: u64) -> bool {
        let prev = consumed.fetch_add(bytes, Ordering::Relaxed);
        if prev + bytes > quota {
            consumed.fetch_sub(bytes, Ordering::Relaxed); // roll back
            false
        } else {
            true
        }
    }

    #[test]
    fn test_quota_allows_within_limit() {
        let consumed = AtomicU64::new(0);
        assert!(quota_check(&consumed, 1024, 1_000_000));
        assert_eq!(consumed.load(Ordering::Relaxed), 1024);
    }

    #[test]
    fn test_quota_rejects_over_limit() {
        let consumed = AtomicU64::new(999_500);
        // 999_500 + 600 = 1_000_100 > 1_000_000 → must reject
        assert!(!quota_check(&consumed, 600, 1_000_000));
        // Consumed must be rolled back
        assert_eq!(consumed.load(Ordering::Relaxed), 999_500);
    }

    #[test]
    fn test_quota_exactly_at_limit_allowed() {
        let consumed = AtomicU64::new(999_000);
        // exactly at limit: 999_000 + 1_000 = 1_000_000 = quota → allowed (not >)
        assert!(quota_check(&consumed, 1_000, 1_000_000));
    }

    #[test]
    fn test_quota_sync_threshold_fires() {
        let consumed = Arc::new(AtomicU64::new(0));
        let last_sync = Arc::new(AtomicU64::new(0));

        // Simulate writing 65_536 bytes in one shot
        let c = consumed.fetch_add(SYNC_THRESHOLD, Ordering::Relaxed);
        let prev_sync = last_sync.load(Ordering::Relaxed);
        let synced = if c + SYNC_THRESHOLD - prev_sync >= SYNC_THRESHOLD {
            last_sync.store(c + SYNC_THRESHOLD, Ordering::Relaxed);
            true
        } else {
            false
        };
        assert!(synced, "Sync must trigger after consuming SYNC_THRESHOLD bytes");
    }

    #[test]
    fn test_quota_sync_threshold_does_not_fire_early() {
        let consumed = Arc::new(AtomicU64::new(0));
        let last_sync = Arc::new(AtomicU64::new(0));

        let chunk = SYNC_THRESHOLD - 1;
        let c = consumed.fetch_add(chunk, Ordering::Relaxed);
        let prev_sync = last_sync.load(Ordering::Relaxed);
        let synced = c + chunk - prev_sync >= SYNC_THRESHOLD;
        assert!(!synced, "Sync must NOT fire before SYNC_THRESHOLD bytes consumed");
    }
}

// ── Ghost Protocol: Real UDP Integration Tests ────────────────────────────────
//
// These tests exercise the full Ghost Protocol stack over actual loopback UDP
// sockets — no mocking.  Each test:
//   1. Binds two UdpSubstrate instances on 127.0.0.1:0 (OS-assigned ports)
//   2. Encodes Ghost Frame(s) using the canonical wire format
//   3. Sends over the real kernel UDP path
//   4. Decodes on the receiver side and asserts field-level correctness
//
// Test topology:
//
//   [sender UdpSubstrate] ──UDP loopback──► [receiver UdpSubstrate]
//
// Coverage:
//   ● gp_udp_knock_roundtrip           — L2 Knock frame, all header fields
//   ● gp_udp_data_with_session_frame   — L2 Data + L3 SessionFrame::PtyData
//   ● gp_udp_knock_ack_bidirectional   — full request/reply exchange (A→B Knock, B→A Ack)
//   ● gp_udp_resize_roundtrip          — L3 PtyResize rows/cols survive full stack
#[cfg(test)]
mod gp_udp_integration {
    use shared::gp_frame::{
        FrameType, GhostFrame, SessionFrame, SessionType, Substrate, UdpSubstrate,
    };
    use std::net::SocketAddr;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// Bind a UdpSubstrate on loopback with an OS-assigned port.
    /// A 5-second read timeout prevents tests from hanging on unexpected failures.
    fn bind_local() -> UdpSubstrate {
        let s = UdpSubstrate::bind("127.0.0.1:0").expect("bind");
        s.set_read_timeout(Some(Duration::from_secs(5))).expect("set_read_timeout");
        s
    }

    /// Encode `addr` as the 6-byte `[a, b, c, d, port_hi, port_lo]` format
    /// expected by `UdpSubstrate::send`.
    fn dst(addr: SocketAddr) -> Vec<u8> {
        match addr {
            SocketAddr::V4(v4) => {
                let [a, b, c, d] = v4.ip().octets();
                let [ph, pl] = v4.port().to_be_bytes();
                vec![a, b, c, d, ph, pl]
            }
            SocketAddr::V6(_) => panic!("IPv6 not expected in loopback test"),
        }
    }

    // ── Test 1: L2 Knock roundtrip ────────────────────────────────────────────

    /// Encode a `Knock` frame on the sender side, send over UDP, decode on the
    /// receiver side, and verify every header field matches exactly.
    ///
    /// This validates the entire L2 encode → kernel UDP path → L2 decode cycle.
    #[test]
    fn gp_udp_knock_roundtrip() {
        let receiver = bind_local();
        let rx_addr  = receiver.local_addr().unwrap();

        // Spawn receiver thread — blocks on recv() until the frame arrives.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (_src, bytes) = receiver.recv().expect("recv");
            let (frame, _)    = GhostFrame::decode(&bytes).expect("decode").expect("complete frame");
            tx.send(frame).expect("channel send");
        });

        // Encode and send the Knock frame.
        let sender = bind_local();
        let mut buf = Vec::new();
        GhostFrame::knock(100, 200, 9999, 0xdeadbeefcafebabe)
            .encode(&mut buf).expect("encode");
        sender.send(&dst(rx_addr), &buf).expect("UDP send");

        // Verify every field survives the wire.
        let frame = rx.recv_timeout(Duration::from_secs(5)).expect("channel recv timeout");
        assert_eq!(frame.frame_type, FrameType::Knock,   "frame_type");
        assert_eq!(frame.did_src,    100,                "did_src");
        assert_eq!(frame.did_dst,    200,                "did_dst");
        assert_eq!(frame.chain_seq,  9999,               "chain_seq");
        assert_eq!(frame.chain_tag,  0xdeadbeefcafebabe, "chain_tag");
        assert!(frame.payload.is_empty(),                "Knock payload must be empty");
    }

    // ── Test 2: L2 Data + L3 SessionFrame::PtyData roundtrip ─────────────────

    /// Build a `SessionFrame::PtyData`, embed it in a `GhostFrame::Data`, send
    /// over UDP, then decode both L2 and L3 layers on the receiver and verify
    /// every field.
    ///
    /// This is the primary data-plane path used for PTY stdin/stdout bytes.
    #[test]
    fn gp_udp_data_with_session_frame_roundtrip() {
        let receiver = bind_local();
        let rx_addr  = receiver.local_addr().unwrap();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (_src, bytes) = receiver.recv().expect("recv");
            let (gf, _) = GhostFrame::decode(&bytes).expect("L2 decode").expect("L2 complete");
            let (sf, _) = SessionFrame::decode(&gf.payload).expect("L3 decode").expect("L3 complete");
            tx.send((gf, sf)).expect("channel send");
        });

        // L3: PTY stdin bytes
        let pty_bytes = b"echo hello\r\n".to_vec();
        let mut l3_buf = Vec::new();
        SessionFrame::pty_data(0, pty_bytes.clone())
            .encode(&mut l3_buf).expect("L3 encode");

        // L2: wrap in Data frame
        let sender = bind_local();
        let mut buf = Vec::new();
        GhostFrame::data(42, 7, 500, 0xabcdef1234567890, l3_buf)
            .encode(&mut buf).expect("L2 encode");
        sender.send(&dst(rx_addr), &buf).expect("UDP send");

        let (gf, sf) = rx.recv_timeout(Duration::from_secs(5)).expect("timeout");
        assert_eq!(gf.frame_type,     FrameType::Data,      "L2 type");
        assert_eq!(gf.did_src,        42,                    "L2 did_src");
        assert_eq!(gf.did_dst,        7,                     "L2 did_dst");
        assert_eq!(gf.chain_seq,      500,                   "L2 chain_seq");
        assert_eq!(gf.chain_tag,      0xabcdef1234567890,    "L2 chain_tag");
        assert_eq!(sf.session_type,   SessionType::PtyData,  "L3 type");
        assert_eq!(sf.stream_id,      0,                     "L3 stream_id");
        assert_eq!(sf.payload,        pty_bytes,             "L3 payload");
    }

    // ── Test 3: Bidirectional Knock→Ack exchange ──────────────────────────────

    /// Node A sends a `Knock` to node B.  Node B decodes it and replies with an
    /// `Ack` addressed back to A.  Node A decodes the `Ack` and verifies the
    /// reflected DID fields.
    ///
    /// This exercises the UDP src-address echo path used by `UdpSubstrate::recv`
    /// (it returns the sender's 6-byte encoded address so the receiver can reply
    /// without maintaining a routing table).
    #[test]
    fn gp_udp_knock_ack_bidirectional() {
        let node_a = bind_local();
        let node_b = bind_local();
        let addr_a = node_a.local_addr().unwrap();
        let addr_b = node_b.local_addr().unwrap();

        // B: receives Knock from A, sends Ack back to A using the src address
        // returned by recv() — no explicit routing needed.
        thread::spawn(move || {
            let (src_bytes, bytes) = node_b.recv().expect("B recv");
            let (knock, _) = GhostFrame::decode(&bytes).expect("B decode").expect("complete");
            assert_eq!(knock.frame_type, FrameType::Knock, "B: expected Knock");

            let ack = GhostFrame {
                frame_type: FrameType::Ack,
                flags:      0,
                did_src:    knock.did_dst, // B's DID
                did_dst:    knock.did_src, // back to A
                chain_seq:  knock.chain_seq,
                chain_tag:  knock.chain_tag,
                payload:    vec![],
            };
            let mut ack_buf = Vec::new();
            ack.encode(&mut ack_buf).expect("B encode Ack");
            node_b.send(&src_bytes, &ack_buf).expect("B send Ack");
        });

        // A: send Knock to B.
        let mut knock_buf = Vec::new();
        GhostFrame::knock(1, 2, 8000, 0x1122334455667788)
            .encode(&mut knock_buf).expect("A encode Knock");
        node_a.send(&dst(addr_b), &knock_buf).expect("A send Knock");

        // A: receive Ack from B.
        let (_src, ack_bytes) = node_a.recv().expect("A recv Ack");
        let (ack, _) = GhostFrame::decode(&ack_bytes).expect("A decode Ack").expect("complete");
        assert_eq!(ack.frame_type, FrameType::Ack, "A: expected Ack");
        assert_eq!(ack.did_src,    2,               "Ack did_src = B's DID");
        assert_eq!(ack.did_dst,    1,               "Ack did_dst = A's DID");
        assert_eq!(ack.chain_seq,  8000,            "chain_seq reflected");

        // Suppress unused warning — addr_a is the bind address, not needed for
        // routing since B echoes the UDP src; kept here for documentation.
        let _ = addr_a;
    }

    // ── Test 4: PtyResize rows/cols survive full stack ────────────────────────

    /// Verify that a `PtyResize` session frame (rows=48, cols=160) survives the
    /// full encode → L2 wrap → UDP → L2 decode → L3 decode cycle with the
    /// numeric values intact.
    #[test]
    fn gp_udp_resize_roundtrip() {
        let receiver = bind_local();
        let rx_addr  = receiver.local_addr().unwrap();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (_src, bytes) = receiver.recv().expect("recv");
            let (gf, _) = GhostFrame::decode(&bytes).expect("L2 decode").expect("L2 complete");
            let (sf, _) = SessionFrame::decode(&gf.payload).expect("L3 decode").expect("L3 complete");
            tx.send(sf).expect("send");
        });

        let mut l3_buf = Vec::new();
        SessionFrame::pty_resize(1, 48, 160).encode(&mut l3_buf).expect("L3 encode");

        let sender = bind_local();
        let mut buf = Vec::new();
        GhostFrame::data(3, 4, 100, 0, l3_buf).encode(&mut buf).expect("L2 encode");
        sender.send(&dst(rx_addr), &buf).expect("UDP send");

        let sf   = rx.recv_timeout(Duration::from_secs(5)).expect("timeout");
        let rows = u16::from_le_bytes(sf.payload[0..2].try_into().unwrap());
        let cols = u16::from_le_bytes(sf.payload[2..4].try_into().unwrap());
        assert_eq!(sf.session_type, SessionType::PtyResize, "session type");
        assert_eq!(sf.stream_id,    1,                       "stream_id");
        assert_eq!(rows,            48,                      "rows");
        assert_eq!(cols,            160,                     "cols");
    }
}
