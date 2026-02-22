pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"tailscale-pty"];

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisCredential {
    pub subject: u32,
    pub request_quota: u64,
    pub pubkey_index: u8,
    pub signature_hex: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ControlMessage {
    Authenticate {
        token: String,
        genesis_vc: Option<GenesisCredential>,
    },
    Resize {
        rows: u16,
        cols: u16,
    },
    SetEnv {
        key: String,
        value: String,
    },
    StartShell, // Signal that handshake is complete, ready to spawn PTY
}
