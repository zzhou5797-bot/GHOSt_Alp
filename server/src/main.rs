use anyhow::{Context, Result};
use clap::Parser;
use shared::Message;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let addr = format!("0.0.0.0:{}", args.port);
    let listener = TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    println!("Server listening on {}", addr);

    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket).await {
                eprintln!("Connection error: {:?}", e);
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream) -> Result<()> {
    loop {
        // Read length (u32, little endian)
        let mut len_buf = [0u8; 4];
        if socket.read_exact(&mut len_buf).await.is_err() {
            // End of stream or error
            return Ok(());
        }
        let len = u32::from_le_bytes(len_buf) as usize;

        // Read payload
        let mut buf = vec![0u8; len];
        socket.read_exact(&mut buf).await?;

        // Deserialize
        let msg: Message = postcard::from_bytes(&buf)?;

        match msg {
            Message::Command(cmd_str) => {
                println!("Executing: {}", cmd_str);
                let output = Command::new("sh")
                    .arg("-c")
                    .arg(&cmd_str)
                    .output()
                    .await;

                let response = match output {
                    Ok(out) => {
                        if out.status.success() {
                            Message::Output(String::from_utf8_lossy(&out.stdout).to_string())
                        } else {
                            // Combine stdout and stderr for error context
                            let mut err_msg = String::from_utf8_lossy(&out.stderr).to_string();
                            if err_msg.is_empty() {
                                err_msg = String::from_utf8_lossy(&out.stdout).to_string();
                            }
                            Message::Error(err_msg)
                        }
                    }
                    Err(e) => Message::Error(e.to_string()),
                };
                send_message(&mut socket, response).await?;
            }
            Message::Exit => {
                println!("Client requested exit");
                return Ok(());
            }
            _ => {}
        }
    }
}

async fn send_message(socket: &mut TcpStream, msg: Message) -> Result<()> {
    let bytes = postcard::to_stdvec(&msg)?;
    let len = bytes.len() as u32;
    socket.write_all(&len.to_le_bytes()).await?;
    socket.write_all(&bytes).await?;
    Ok(())
}
