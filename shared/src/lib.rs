pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"tailscale-pty"];

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum ControlMessage {
    Authenticate { token: String },
    Resize { rows: u16, cols: u16 },
    SetEnv { key: String, value: String },
    StartShell, // Signal that handshake is complete, ready to spawn PTY
}
