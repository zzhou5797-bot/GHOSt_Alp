//! Shared SPA v2 hash-chain primitives.
//!
//! These constants and functions intentionally mirror the XDP implementation
//! in gateway-ebpf/src/main.rs so clients and the userspace gateway cannot
//! silently drift on byte order or chain semantics.

pub const DEV_SECRET_K0: u64 = 0x04030201efbeadde;
pub const DEV_SECRET_K1: u64 = 0x0d0c0b0affe0dcba;
pub const DEV_CHAIN_DEPTH: u64 = 10_000;
pub const DEV_SPA_KEY_HEX: &str = "deadbeef01020304badce0ff0a0b0c0d";
pub const DEV_SPA_SEED_HEX: &str = "0102030405060708090a0b0c0d0e0f10";
pub const DEV_SEED: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

pub fn parse_key_hex(input: &str) -> Option<(u64, u64)> {
    let bytes = parse_hex_prefix::<16>(input)?;
    let k0 = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let k1 = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    Some((k0, k1))
}

pub fn parse_seed_hex(input: &str) -> Option<[u8; 8]> {
    parse_hex_prefix::<8>(input)
}

fn parse_hex_prefix<const N: usize>(input: &str) -> Option<[u8; N]> {
    if input.len() < N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&input[start..start + 2], 16).ok()?;
    }
    Some(out)
}

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

pub fn siphash24_16b(k0: u64, k1: u64, m0: u64, m1: u64) -> [u8; 8] {
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;
    let b = (16_u64) << 56;

    for m in [m0, m1] {
        v3 ^= m;
        siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
        siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    v3 ^= b;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    for _ in 0..4 {
        siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    (v0 ^ v1 ^ v2 ^ v3).to_le_bytes()
}

pub fn hash_step(h: [u8; 8], k0: u64, k1: u64) -> [u8; 8] {
    siphash24_16b(k0, k1, u64::from_le_bytes(h), 0)
}

pub fn hash_at(seed: [u8; 8], seq: u64, k0: u64, k1: u64) -> [u8; 8] {
    let mut h = seed;
    for _ in 0..seq {
        h = hash_step(h, k0, k1);
    }
    h
}

pub fn dev_anchor() -> [u8; 8] {
    hash_at(DEV_SEED, DEV_CHAIN_DEPTH, DEV_SECRET_K0, DEV_SECRET_K1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_hex_key_matches_xdp_constants() {
        assert_eq!(
            parse_key_hex(DEV_SPA_KEY_HEX),
            Some((DEV_SECRET_K0, DEV_SECRET_K1))
        );
    }

    #[test]
    fn default_seed_parses_as_documented_bytes() {
        assert_eq!(parse_seed_hex(DEV_SPA_SEED_HEX), Some(DEV_SEED));
    }

    #[test]
    fn previous_hash_verifies_against_anchor() {
        let anchor = dev_anchor();
        let previous = hash_at(DEV_SEED, DEV_CHAIN_DEPTH - 1, DEV_SECRET_K0, DEV_SECRET_K1);
        assert_eq!(hash_step(previous, DEV_SECRET_K0, DEV_SECRET_K1), anchor);
    }
}
