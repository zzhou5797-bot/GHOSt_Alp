//! Wire types shared between the GhostPTY server and client.

pub mod gp_frame;
pub mod mcp_wire;
pub mod spa;

/// QUIC ALPN token identifying the GhostPTY protocol version 1.
pub const ALPN_GHOSTPTY: &[&[u8]] = &[b"ghostpty/1"];

/// QUIC ALPN token for the structured Ghost MCP transport.
pub const ALPN_GHOST_MCP: &[&[u8]] = &[b"ghostmcp/1"];

use serde::{Deserialize, Serialize};

/// A signed ticket from a Tier-1 validator that authorizes a new DID subject
/// and specifies its initial byte quota.
///
/// The server verifies the Ed25519 signature against the live `ValidatorSet`
/// before inserting a new `AUTH_STATE_MAP` entry.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisCredential {
    /// Numeric DID subject (used as the map key in `AUTH_STATE_MAP`).
    pub subject: u32,
    /// Initial byte quota granted to this subject (bytes).
    pub request_quota: u64,
    /// Index into the `ValidatorSet::genesis_keys` array that signed this credential.
    pub pubkey_index: u8,
    /// 32-byte anchor that binds the credential to the subject's first SPA hash chain.
    pub anchor_hash: [u8; 32],
    /// Hex-encoded Ed25519 signature over `"{subject}:{request_quota}:{anchor_hash_hex}"`.
    pub signature_hex: String,
}

/// Messages sent over the unidirectional control stream during the handshake
/// and post-handshake supervision phase.
#[derive(Serialize, Deserialize, Debug)]
pub enum ControlMessage {
    /// First message from the client.  Must arrive before any other message.
    Authenticate {
        /// Bearer token checked with constant-time comparison.
        token: String,
        /// Optional first-time bootstrap credential for new DID subjects.
        genesis_vc: Option<GenesisCredential>,
    },
    /// Resize the PTY master to the given dimensions.
    Resize {
        rows: u16,
        cols: u16,
    },
    /// Set an environment variable in the shell (allowlist-filtered by server).
    SetEnv {
        key: String,
        value: String,
    },
    /// Signals that the client has finished sending configuration and is ready
    /// for the server to spawn the PTY and open the bidirectional data stream.
    StartShell,
}
