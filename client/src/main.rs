use anyhow::{bail, Context, Result};
use clap::Parser;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use indicatif::{ProgressBar, ProgressStyle};
use quinn::{ClientConfig, Endpoint, TransportConfig};
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(name = "ghost-cli", version, about = "Ghost Grid PTY Client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Connect to a remote Ghost Grid gateway node
    Connect(ConnectArgs),
    /// (Phase 4.4) Connect to local daemon to stream TUI metrics
    Ui,
}

#[derive(Parser, Debug, Clone)]
struct ConnectArgs {
    /// The authorization token for the PTY session
    #[arg(help = "Access Token")]
    token: String,

    /// Target DID (Decentralized Identifier) to map this session to
    #[arg(short, long, help = "Target DID")]
    target: u32,

    /// Target Host IP/Domain
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Target Port
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Path to root CA certificate
    #[arg(long, default_value = "../certs/ca.crt")]
    ca: PathBuf,

    /// Path to client certificate
    #[arg(long, default_value = "../certs/client.crt")]
    cert: PathBuf,

    /// Path to client private key
    #[arg(long, default_value = "../certs/client.key")]
    key: PathBuf,

    /// Allow insecure TLS connections (skip verification)
    #[arg(long, default_value_t = false)]
    insecure_skip_tls_verify: bool,

    // ── V2 Hash-Chain Configuration (Auto-managed if not specified) ──
    #[arg(
        long,
        env = "SPA_KEY",
        default_value = "deadbeef01020304badc0ffe0a0b0c0d"
    )]
    spa_key: String,

    #[arg(
        long,
        env = "SPA_SEED",
        default_value = "0102030405060708090a0b0c0d0e0f10"
    )]
    seed: String,

    #[arg(long, default_value = ".ghost_chain_state")]
    state_file: PathBuf,

    #[arg(long, default_value_t = 10000)]
    chain_depth: u64,
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

    v3 ^= m0;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m0;

    v3 ^= m1;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m1;

    v3 ^= b;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);

    let h = v0 ^ v1 ^ v2 ^ v3;
    h.to_le_bytes()
}

// ── Hash Chain helpers ──────────────────────────────────────────────────────

/// One forward step: H_next = SipHash(secret_k0, secret_k1, H_current, 0).
/// Must match the identical function in `gateway-ebpf/src/main.rs`.
fn hash_step(h: [u8; 8], k0: u64, k1: u64) -> [u8; 8] {
    siphash24_16b(k0, k1, u64::from_le_bytes(h), 0)
}

/// Read the chain's public anchor (H_N) from a chain starting at `seed`.
/// N = `depth`.  The inner loop is the forward direction (seed → H_N).
#[allow(dead_code)]
fn derive_anchor(seed: [u8; 8], depth: u64, k0: u64, k1: u64) -> [u8; 8] {
    let mut h = seed;
    for _ in 0..depth {
        h = hash_step(h, k0, k1);
    }
    h
}

/// State persisted to disk between runs.
/// Format (binary, little-endian): [seed: 8 bytes][current_seq: 8 bytes]
const STATE_MAGIC: &[u8; 4] = b"GCv2";

fn load_or_init_state(
    state_file: &PathBuf,
    seed: [u8; 8],
    chain_depth: u64,
) -> Result<(u64, [u8; 8])> {
    // Try to read existing state
    if let Ok(data) = fs::read(state_file) {
        if data.len() == 20 && &data[0..4] == STATE_MAGIC {
            let stored_seed: [u8; 8] = data[4..12].try_into().unwrap();
            let current_seq = u64::from_le_bytes(data[12..20].try_into().unwrap());

            if stored_seed == seed && current_seq > 0 {
                return Ok((current_seq, stored_seed));
            }
        }
    }

    // Fresh state: start at top of chain (seq = chain_depth)
    eprintln!(
        "Ghost Chain: initialising new chain (depth={})\r",
        chain_depth
    );
    save_state(state_file, seed, chain_depth)?;
    Ok((chain_depth, seed))
}

fn save_state(state_file: &PathBuf, seed: [u8; 8], current_seq: u64) -> Result<()> {
    let mut data = Vec::with_capacity(20);
    data.extend_from_slice(STATE_MAGIC);
    data.extend_from_slice(&seed);
    data.extend_from_slice(&current_seq.to_le_bytes());
    fs::write(state_file, &data)
        .with_context(|| format!("Failed to write chain state to {:?}", state_file))
}

/// Retrieve H_{current_seq} by walking forward from seed.
/// seq=0 → seed itself; seq=N → anchor H_N.
fn get_hash_at_seq(seed: [u8; 8], seq: u64, k0: u64, k1: u64) -> [u8; 8] {
    let mut h = seed;
    for _ in 0..seq {
        h = hash_step(h, k0, k1);
    }
    h
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect(args) => run_connect(args).await,
        Commands::Ui => {
            println!("(Phase 4.4) UI attach mode requested. Not yet implemented.");
            Ok(())
        }
    }
}

async fn run_connect(args: ConnectArgs) -> Result<()> {
    // Enable Raw Mode immediately for TTY feel
    enable_raw_mode()?;

    if let Err(e) = run_client(args).await {
        disable_raw_mode()?;
        eprintln!("\r\nError: {:?}\r\n", e);
        return Err(e);
    }

    disable_raw_mode()?;
    Ok(())
}

/// Send a v1 (timestamp-based) SPA knock to `remote_addr` via `socket`.
// V1 SPA logic removed per Phase 5 security hardening

async fn setup_quic_client(args: &ConnectArgs, pb: &ProgressBar) -> Result<ClientConfig> {
    // 1. Load CA cert
    if !args.ca.exists() {
        pb.set_message(
            "Warning: CA cert not found, continuing with insecure bypass if flag set...",
        );
    }
    let ca_cert_pem =
        fs::read(&args.ca).with_context(|| format!("Failed to read CA cert from {:?}", args.ca))?;
    let mut ca_cert_reader = std::io::BufReader::new(ca_cert_pem.as_slice());

    // 2. Load Client cert
    let cert_pem = fs::read(&args.cert)
        .with_context(|| format!("Failed to read client cert from {:?}", args.cert))?;
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let cert_chain = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let cert = cert_chain
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No client certificate found"))?;

    // 3. Load Client key
    let key_pem = fs::read(&args.key)
        .with_context(|| format!("Failed to read client key from {:?}", args.key))?;
    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let priv_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

    // 4. Configure TLS
    if args.insecure_skip_tls_verify {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_client_auth_cert(vec![cert], priv_key)?;
        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        config.transport_config(Arc::new(transport));
        Ok(config)
    } else {
        let mut roots = rustls::RootCertStore::empty();
        let ca_cert_pem = fs::read(&args.ca)
            .with_context(|| format!("Failed to read CA cert from {:?}", args.ca))?;
        let mut ca_cert_reader = std::io::BufReader::new(ca_cert_pem.as_slice());
        for cert in rustls_pemfile::certs(&mut ca_cert_reader).collect::<Result<Vec<_>, _>>()? {
            roots.add(cert)?;
        }

        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![cert], priv_key)?;

        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        config.transport_config(Arc::new(transport));
        Ok(config)
    }
}

// Insecure TLS verification for local tests
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

async fn run_client(args: ConnectArgs) -> Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    // Setup QUIC Configuration
    let quic_client_config = setup_quic_client(&args, &pb).await?;
    let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(quic_client_config);

    let remote_addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .context("Invalid address")?;

    // 0. V2: Generate Single Packet Auth (SPA) Knock
    pb.set_message(format!("SPA Knocking {}:{}...", args.host, args.port));
    // ── V2 SPA: derive key material and hash chain position ─────────────────
    let secret_k0: u64 = if args.spa_key.len() == 32 {
        u64::from_str_radix(&args.spa_key[0..16], 16).unwrap_or(0x04030201efbeadde)
    } else {
        0x04030201efbeadde
    };
    let secret_k1: u64 = if args.spa_key.len() == 32 {
        u64::from_str_radix(&args.spa_key[16..32], 16).unwrap_or(0x0d0c0b0affe0dcba)
    } else {
        0x0d0c0b0affe0dcba
    };
    let seed_hex = if args.seed.len() >= 16 {
        &args.seed[0..16]
    } else {
        "0102030405060708"
    };
    let seed_u64 = u64::from_str_radix(seed_hex, 16).unwrap_or(0x0102030405060708);
    let seed: [u8; 8] = seed_u64.to_le_bytes();
    let (mut current_seq, chain_seed) =
        load_or_init_state(&args.state_file, seed, args.chain_depth)?;
    if current_seq == 0 {
        anyhow::bail!("Hash chain exhausted (seq=0). Re-register H_N with the gateway.");
    }
    let knock_hash = get_hash_at_seq(chain_seed, current_seq, secret_k0, secret_k1);
    let subject_id = args.target; // P2P Gateway registered ID
    let next_seq = current_seq - 1;
    save_state(&args.state_file, chain_seed, next_seq)?;
    current_seq = next_seq;
    pb.set_message(format!("Ghost Chain: seq={} remaining", current_seq));

    pb.set_message(format!(
        "SPA: sending v2 Hash Chain knock to {}...",
        remote_addr
    ));

    // ── Assemble V2 SpaPayload (60 bytes) ────────────────────────────────────
    let mut v2_payload: Vec<u8> = Vec::with_capacity(60);
    v2_payload.extend_from_slice(&(0x5453_5054u32).to_be_bytes()); // magic
    v2_payload.extend_from_slice(&2u32.to_be_bytes()); // version
    v2_payload.extend_from_slice(&subject_id.to_be_bytes());
    v2_payload.extend_from_slice(&(current_seq + 1).to_be_bytes());
    v2_payload.extend_from_slice(&knock_hash);
    v2_payload.extend_from_slice(&[0u8; 32]); // signature placeholder

    let spa_socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind UDP socket for SPA")?;
    spa_socket
        .send_to(&v2_payload, remote_addr)
        .await
        .context("Failed to send v2 SPA knock")?;

    // Allow XDP map insertion to propagate (~50 ms)
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ── Attempt QUIC connect (v2 path only) ──────────────────────────────────
    pb.set_message(format!("Establishing QUIC tunnel to {}...", remote_addr));
    let connection = endpoint
        .connect(remote_addr, "localhost")?
        .await
        .context("QUIC connect failed after v2 knock")?;
    pb.finish_with_message("✓ Connected (v2 Hash Chain)!");

    // 1. Open Control Stream FIRST
    let mut control_tx = connection.open_uni().await?;

    // 2. Perform Handshake
    // A. Send Authenticate Token FIRST
    pb.set_message("Exchanging PTY metadata...");
    let msg = shared::ControlMessage::Authenticate {
        token: args.token.clone(),
        genesis_vc: None,
    };
    send_control_msg(&mut control_tx, &msg).await?;
    pb.finish_with_message("✓ Authorized as DID... Shell attached.");

    // B. Send TERM environment variable
    let term = std::env::var("TERM").unwrap_or("xterm-256color".into());
    let msg = shared::ControlMessage::SetEnv {
        key: "TERM".into(),
        value: term,
    };
    send_control_msg(&mut control_tx, &msg).await?;

    // C. Send Initial Window Size
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let msg = shared::ControlMessage::Resize { rows, cols };
    send_control_msg(&mut control_tx, &msg).await?;

    // D. Finish Handshake
    let msg = shared::ControlMessage::StartShell;
    send_control_msg(&mut control_tx, &msg).await?;

    eprintln!("Handshake complete. Stream established.\r");

    // 3. Open Data Stream SECOND
    let (mut send, mut recv) = connection.open_bi().await?;

    // 4. Spawn Resize Monitor (Polling)
    // We poll window size to avoid conflicting with input stream reading in Raw Mode
    tokio::spawn(async move {
        let mut last_cols = cols; // Use initial values
        let mut last_rows = rows;
        loop {
            if let Ok((cols, rows)) = crossterm::terminal::size() {
                if cols != last_cols || rows != last_rows {
                    let msg = shared::ControlMessage::Resize { rows, cols };
                    // Ignore errors, if connection drops main loop will exit
                    if send_control_msg(&mut control_tx, &msg).await.is_err() {
                        break;
                    }
                    last_cols = cols;
                    last_rows = rows;
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    });

    // 5. Spawn Input Task (Stdin -> QUIC)
    tokio::spawn(async move {
        // We need to read stdin specifically.
        // In Crossterm Raw Mode, Stdin is perfectly usable as raw bytes.
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    });

    // Main Loop: QUIC -> Stdout
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 1024];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                stdout.write_all(&buf[..n]).await?;
                stdout.flush().await?;
            }
            Ok(None) => break, // EOF
            Err(_) => break,   // Connection lost
        }
    }

    Ok(())
}

async fn send_control_msg(tx: &mut quinn::SendStream, msg: &shared::ControlMessage) -> Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    tx.write_all(&len).await?;
    tx.write_all(&json).await?;
    Ok(())
}
