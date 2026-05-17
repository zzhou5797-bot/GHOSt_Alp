//! Tier-1 validator key management.
//!
//! `ValidatorSet` is the runtime authority for:
//!   - which Ed25519 keys may issue `GenesisCredential` tokens
//!   - which Ed25519 keys may cast BFT slash votes
//!   - the BFT threshold (how many slash votes trigger revocation)
//!   - the network-wide pause flag
//!
//! The set is initialized from runtime-provided key material and mutated
//! at runtime by the P2P slash consensus path and the internal governance
//! mechanism.  There is no public API or network-visible governance endpoint.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;

use shared::GenesisCredential;

/// Development-only test keys.  **Never use these in production.**
/// Pass real keys via `--genesis-keys` (CLI) or `GENESIS_KEYS_HEX` (env).
const DEV_GENESIS_KEYS_HEX: &[&str] = &[
    "7a2d1237b19877ba382a493547e600e4dbf6b43c79702a5802dbe6b0d5d9e933",
    "f2c6c061fc621defa7c41ebdd8a6bebf4cfc3fc3b8398453ef63bc180abebd2f",
];

/// Parse a slice of hex strings into raw 32-byte Ed25519 public keys.
/// Silently drops malformed entries.
fn parse_keys_hex(hexes: &[String]) -> Vec<[u8; 32]> {
    hexes
        .iter()
        .filter_map(|h| {
            let mut b = [0u8; 32];
            hex::decode_to_slice(h.trim(), &mut b).ok().map(|_| b)
        })
        .collect()
}

fn dev_slash_pubkeys() -> HashMap<u32, [u8; 32]> {
    let pairs: &[(u32, &str)] = &[
        (0, "7a2d1237b19877ba382a493547e600e4dbf6b43c79702a5802dbe6b0d5d9e933"),
        (1, "f2c6c061fc621defa7c41ebdd8a6bebf4cfc3fc3b8398453ef63bc180abebd2f"),
    ];
    pairs
        .iter()
        .filter_map(|(did, hex)| {
            let mut b = [0u8; 32];
            hex::decode_to_slice(hex, &mut b).ok().map(|_| (*did, b))
        })
        .collect()
}

/// Live Tier-1 validator configuration, shared across all server tasks via `Arc<RwLock<_>>`.
///
/// Write access is only granted by the internal governance mechanism.
/// The gossipsub slash path acquires a write lock when BFT threshold is reached.
pub struct ValidatorSet {
    /// Ed25519 public keys that may sign `GenesisCredential` tokens, indexed by `pubkey_index`.
    pub genesis_keys: Vec<[u8; 32]>,
    /// DID → Ed25519 public key for authorized BFT slash voters.
    pub slash_keys: HashMap<u32, [u8; 32]>,
    /// Number of distinct slash votes required for BFT consensus to revoke a subject.
    pub bft_threshold: usize,
    /// When `true`, `handle_connection` rejects all new QUIC connections network-wide.
    pub paused: bool,
}

impl ValidatorSet {
    /// Construct from runtime-provided genesis key hexes.
    ///
    /// Pass the hex strings from `--genesis-keys` / `GENESIS_KEYS_HEX`.
    /// Slash keys are seeded to the same set; override via sovereign mechanism at runtime.
    pub fn bootstrap(genesis_keys_hex: &[String]) -> Self {
        let (gk_hex, sk_hex): (&[String], &[String]) = if genesis_keys_hex.is_empty() {
            let dev: Vec<String> = DEV_GENESIS_KEYS_HEX.iter().map(|s| s.to_string()).collect();
            // Leak into a static-lifetime vector for simplicity at startup.
            // Safety: called once at program startup.
            let leaked: &'static Vec<String> = Box::leak(Box::new(dev));
            (leaked.as_slice(), leaked.as_slice())
        } else {
            (genesis_keys_hex, genesis_keys_hex)
        };

        let genesis_keys = parse_keys_hex(gk_hex);
        let slash_keys: HashMap<u32, [u8; 32]> = if genesis_keys_hex.is_empty() {
            dev_slash_pubkeys()
        } else {
            parse_keys_hex(sk_hex)
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u32, k))
                .collect()
        };

        ValidatorSet {
            genesis_keys,
            slash_keys,
            bft_threshold: 3,
            paused: false,
        }
    }

    /// Construct the development set from the built-in test keys.
    /// **Only for local testing.** Production must call `bootstrap(keys)` with real keys.
    pub fn bootstrap_dev() -> Self {
        Self::bootstrap(&[])
    }

    /// Verify a `GenesisCredential` against the live genesis key set.
    ///
    /// The message that must be signed is `"{subject}:{request_quota}:{anchor_hash_hex}"`.
    /// Returns `false` on any verification failure without revealing which check failed.
    pub fn verify_genesis_credential(&self, vc: &GenesisCredential) -> bool {
        let idx = vc.pubkey_index as usize;
        if idx >= self.genesis_keys.len() {
            return false;
        }
        let Ok(verifying_key) = VerifyingKey::from_bytes(&self.genesis_keys[idx]) else {
            return false;
        };
        let mut sig_bytes = [0u8; 64];
        if hex::decode_to_slice(&vc.signature_hex, &mut sig_bytes).is_err() {
            return false;
        }
        let signature = Signature::from_bytes(&sig_bytes);
        let anchor_hex: String = vc.anchor_hash.iter().map(|b| format!("{:02x}", b)).collect();
        let msg = format!("{}:{}:{}", vc.subject, vc.request_quota, anchor_hex);
        verifying_key.verify(msg.as_bytes(), &signature).is_ok()
    }

    /// Verify a BFT slash vote Ed25519 signature from `issuer_did` against the live slash key set.
    ///
    /// The message that must be signed is `"slash:{subject}:{issuer_did}:{target_seq}"`.
    /// Returns `false` on any verification failure.
    pub fn verify_slash_signature(
        &self,
        subject: u32,
        issuer_did: u32,
        target_seq: u64,
        sig_hex: &str,
    ) -> bool {
        let Some(pubkey_bytes) = self.slash_keys.get(&issuer_did) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey_bytes) else {
            return false;
        };
        let mut sig_bytes = [0u8; 64];
        if hex::decode_to_slice(sig_hex, &mut sig_bytes).is_err() {
            return false;
        }
        let signature = Signature::from_bytes(&sig_bytes);
        let msg = format!("slash:{}:{}:{}", subject, issuer_did, target_seq);
        verifying_key.verify(msg.as_bytes(), &signature).is_ok()
    }
}
