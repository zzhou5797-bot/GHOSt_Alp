use anyhow::Result;
use clap::Parser;
use shared::Message;
use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    host: String,
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);
    println!("Connecting to {}...", addr);
    let stream = TcpStream::connect(&addr).await?;
    println!("Connected!");

    let (reader, mut writer) = stream.into_split();
    println!("Stream split");

    // Spawn reader task
    let mut reader = tokio::io::BufReader::new(reader);
    tokio::spawn(async move {
        println!("Reader task started");
        loop {
           let mut len_buf = [0u8; 4];
           if reader.read_exact(&mut len_buf).await.is_err() {
               println!("\n[Connection closed by server]");
               std::process::exit(0);
           }
           let len = u32::from_le_bytes(len_buf) as usize;
           let mut buf = vec![0u8; len];
           if reader.read_exact(&mut buf).await.is_err() {
               println!("\n[Connection error]");
               std::process::exit(1);
           }
           if let Ok(msg) = postcard::from_bytes::<Message>(&buf) {
               match msg {
                   Message::Output(s) => print!("{}", s),
                   Message::Error(s) => eprintln!("Remote Error: {}", s),
                   _ => {}
               }
               // Force flush stdout to ensure we see the output immediately
               let _ = std::io::stdout().flush();
           }
        }
    });

    // Writer loop
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    loop {
        print!("> ");
        let _ = std::io::stdout().flush();
        line.clear();
        if stdin.read_line(&mut line).await? == 0 {
             break; // EOF
        }
        let cmd = line.trim().to_string();
        if cmd == "exit" {
            send_message(&mut writer, Message::Exit).await?;
            break;
        }
        if !cmd.is_empty() {
            send_message(&mut writer, Message::Command(cmd)).await?;
        }
    }
    Ok(())
}

async fn send_message(stream: &mut tokio::net::tcp::OwnedWriteHalf, msg: Message) -> Result<()> {
    let bytes = postcard::to_stdvec(&msg)?;
    let len = bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}
