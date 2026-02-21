use anyhow::Result;
use portable_pty::PtySize;
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;

pub struct HandshakeResult {
    pub pty_size: PtySize,
    pub env_vars: HashMap<String, String>,
}

pub async fn perform_handshake(
    mut control_rx: quinn::RecvStream,
    expected_token: &str,
) -> Result<(HandshakeResult, quinn::RecvStream)> {
    let mut env_vars = HashMap::new();
    let mut pty_size = PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    };
    let mut authenticated = false;

    let mut len_buf = [0u8; 4];
    loop {
        // We use loops to read multiple config messages
        match control_rx.read_exact(&mut len_buf).await {
            Ok(_) => {
                let len = u32::from_be_bytes(len_buf) as usize;
                // Fix 1: Bound memory allocation to prevent OOM crash
                if len > 65536 {
                    tracing::error!("Control message too large: {} bytes", len);
                    return Err(anyhow::anyhow!("Control message too large"));
                }

                let mut body = vec![0u8; len];
                control_rx.read_exact(&mut body).await?;

                if let Ok(msg) = serde_json::from_slice::<shared::ControlMessage>(&body) {
                    if !authenticated {
                        match msg {
                            shared::ControlMessage::Authenticate { token } => {
                                let expected_bytes = expected_token.as_bytes();
                                let provided_bytes = token.as_bytes();

                                let mut is_equal = 1u8;
                                if expected_bytes.len() != provided_bytes.len() {
                                    is_equal = 0u8;
                                }

                                let dummy = vec![0u8; expected_bytes.len()];
                                let compare_bytes = if is_equal == 1 {
                                    provided_bytes
                                } else {
                                    dummy.as_slice()
                                };

                                let ct_result = expected_bytes.ct_eq(compare_bytes);

                                if is_equal == 1 && bool::from(ct_result) {
                                    authenticated = true;
                                    tracing::info!("Client authenticated successfully.");
                                } else {
                                    tracing::warn!("Authentication failed: invalid token.");
                                    return Err(anyhow::anyhow!("Invalid token"));
                                }
                            }
                            _ => {
                                tracing::warn!("Expected Authenticate message first.");
                                return Err(anyhow::anyhow!("Unauthenticated"));
                            }
                        }
                    } else {
                        match msg {
                            shared::ControlMessage::Authenticate { .. } => {
                                tracing::warn!("Already authenticated.");
                            }
                            shared::ControlMessage::SetEnv { key, value } => {
                                tracing::debug!("SetEnv: {}={}", key, value);
                                env_vars.insert(key, value);
                            }
                            shared::ControlMessage::Resize { rows, cols } => {
                                tracing::debug!("Resize Init: {}x{}", rows, cols);
                                pty_size.rows = rows;
                                pty_size.cols = cols;
                            }
                            shared::ControlMessage::StartShell => {
                                tracing::info!("Handshake complete. Starting Shell...");
                                break;
                            }
                        }
                    }
                } else {
                    tracing::warn!("Failed to deserialize ControlMessage");
                }
            }
            Err(e) => {
                tracing::error!("Control stream closed during handshake: {}", e);
                return Err(e.into());
            }
        }
    }

    Ok((HandshakeResult { pty_size, env_vars }, control_rx))
}
