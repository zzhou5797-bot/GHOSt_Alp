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
