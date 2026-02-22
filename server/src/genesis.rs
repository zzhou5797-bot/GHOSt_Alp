use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use shared::GenesisCredential;

// Hardcoded Genesis Root Keys for Phase 3.2 Bootstrap
// In a real production system, these are carefully guarded cold-storage offline keys.
pub const GENESIS_KEYS_HEX: &[&str] = &[
    "7a2d1237b19877ba382a493547e600e4dbf6b43c79702a5802dbe6b0d5d9e933", // Placeholder Key 1 (DEV Node 0 Pubkey)
    "f2c6c061fc621defa7c41ebdd8a6bebf4cfc3fc3b8398453ef63bc180abebd2f", // Placeholder Key 2
];

pub fn verify_slash_signature(subject: u32, issuer_did: u32, signature_hex: &str) -> bool {
    if (issuer_did as usize) >= GENESIS_KEYS_HEX.len() {
        return false;
    }

    let pubkey_hex = GENESIS_KEYS_HEX[issuer_did as usize];
    let mut pubkey_bytes = [0u8; 32];
    if hex::decode_to_slice(pubkey_hex, &mut pubkey_bytes).is_err() {
        return false;
    }

    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_bytes) else {
        return false;
    };

    let mut sig_bytes = [0u8; 64];
    if hex::decode_to_slice(signature_hex, &mut sig_bytes).is_err() {
        return false;
    }

    let signature = Signature::from_bytes(&sig_bytes);
    let msg = format!("slash:{}:{}", subject, issuer_did);
    verifying_key.verify(msg.as_bytes(), &signature).is_ok()
}

pub fn verify_genesis_credential(vc: &GenesisCredential) -> bool {
    if (vc.pubkey_index as usize) >= GENESIS_KEYS_HEX.len() {
        return false;
    }

    let pubkey_hex = GENESIS_KEYS_HEX[vc.pubkey_index as usize];
    let mut pubkey_bytes = [0u8; 32];
    if hex::decode_to_slice(pubkey_hex, &mut pubkey_bytes).is_err() {
        return false;
    }

    let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_bytes) else {
        return false;
    };

    let mut sig_bytes = [0u8; 64];
    if hex::decode_to_slice(&vc.signature_hex, &mut sig_bytes).is_err() {
        return false;
    }

    let signature = Signature::from_bytes(&sig_bytes);

    let mut anchor_hex = String::new();
    for byte in &vc.anchor_hash {
        anchor_hex.push_str(&format!("{:02x}", byte));
    }

    let msg = format!("{}:{}:{}", vc.subject, vc.request_quota, anchor_hex);
    verifying_key.verify(msg.as_bytes(), &signature).is_ok()
}
