use anyhow::Result;
use portable_pty::PtySize;
use std::collections::HashMap;
use tokio::io::AsyncReadExt;

pub struct HandshakeResult {
    pub pty_size: PtySize,
    pub env_vars: HashMap<String, String>,
}

pub async fn perform_handshake(mut control_rx: quinn::RecvStream) -> Result<(HandshakeResult, quinn::RecvStream)> {
    let mut env_vars = HashMap::new();
    let mut pty_size = PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    };

    let mut len_buf = [0u8; 4];
    loop {
        // We use loops to read multiple config messages
        match control_rx.read_exact(&mut len_buf).await {
            Ok(_) => {
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                control_rx.read_exact(&mut body).await?;
                
                if let Ok(msg) = serde_json::from_slice::<shared::ControlMessage>(&body) {
                    match msg {
                        shared::ControlMessage::SetEnv { key, value } => {
                            println!("SetEnv: {}={}", key, value);
                            env_vars.insert(key, value);
                        }
                        shared::ControlMessage::Resize { rows, cols } => {
                            println!("Resize Init: {}x{}", rows, cols);
                            pty_size.rows = rows;
                            pty_size.cols = cols;
                        }
                        shared::ControlMessage::StartShell => {
                            println!("Handshake complete. Starting Shell...");
                            break; 
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Control stream closed during handshake: {}", e);
                return Err(e.into());
            }
        }
    }

    Ok((HandshakeResult { pty_size, env_vars }, control_rx))
}
