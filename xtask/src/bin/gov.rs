//! Ghost Network governance tool — OFFLINE signing + gossipsub injection.
//!
//! # Security model
//!
//! The Tier 0 (founder) private key **never touches any server**.  Governance
//! transactions are produced on an air-gapped machine using `gov sign` and
//! broadcast to the network via `gov inject`, which spins up a short-lived
//! gossipsub peer and exits.  The server has no admin port, no privileged RPC,
//! and no governance-specific endpoint — a signed transaction is just data
//! arriving over the same `ghost_grid_gov` gossipsub topic as other messages.
//!
//! # Commands
//!
//! ```
//! # Generate a new Tier-0 keypair (run OFFLINE, store private key securely)
//! cargo run --bin gov -- gen-key --out founder.key
//!
//! # Sign a governance action (OFFLINE — no network required)
//! cargo run --bin gov -- sign \
//!     --key founder.key \
//!     --action add-slash-key \
//!     --did 42 \
//!     --pubkey <hex> \
//!     --valid-secs 300 \
//!     --out tx.json
//!
//! # Inject the signed tx into the network (can run on any machine)
//! cargo run --bin gov -- inject \
//!     --tx tx.json \
//!     --bootstrap /ip4/1.2.3.4/tcp/PORT/p2p/PEER_ID
//! ```

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use futures::StreamExt;
use libp2p::{gossipsub, noise, swarm::SwarmEvent, tcp, yamux};
use rand::rngs::OsRng;
use shared::{GovernanceAction, GovernanceTx, SignedGovernanceTx};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "gov",
    about = "Ghost Network governance tool — offline signing and gossipsub injection",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Tier-0 Ed25519 keypair (run OFFLINE).
    GenKey {
        /// File path to write the private key (hex, 32 bytes).
        #[arg(long)]
        out: PathBuf,
    },

    /// Sign a governance transaction (run OFFLINE — no network needed).
    Sign {
        /// Path to the private key file produced by gen-key.
        #[arg(long)]
        key: PathBuf,

        /// Governance action to perform.
        #[command(subcommand)]
        action: ActionCmd,

        /// How many seconds this transaction should be valid (default: 300 = 5 min).
        #[arg(long, default_value = "300")]
        valid_secs: u64,

        /// Output path for the signed transaction JSON.
        #[arg(long)]
        out: PathBuf,
    },

    /// Inject a signed transaction into the gossipsub network.
    ///
    /// This spins up a temporary libp2p peer, connects to a bootstrap node,
    /// publishes the transaction once, waits for propagation, then exits.
    Inject {
        /// Path to the signed transaction JSON produced by sign.
        #[arg(long)]
        tx: PathBuf,

        /// Bootstrap peer multiaddr (e.g. /ip4/1.2.3.4/tcp/PORT/p2p/PEER_ID).
        #[arg(long)]
        bootstrap: String,
    },
}

#[derive(Subcommand, Clone)]
enum ActionCmd {
    /// Append a new Tier-1 genesis credential signing key.
    AddGenesisKey {
        #[arg(long)]
        pubkey: String,
    },
    /// Remove a genesis key from the active set.
    RemoveGenesisKey {
        #[arg(long)]
        pubkey: String,
    },
    /// Bind a DID → Ed25519 pubkey for BFT slash voting.
    AddSlashKey {
        #[arg(long)]
        did: u32,
        #[arg(long)]
        pubkey: String,
    },
    /// Remove a DID from the authorized slash-voter set.
    RemoveSlashKey {
        #[arg(long)]
        did: u32,
    },
    /// Change the BFT consensus threshold.
    SetBftThreshold {
        #[arg(long)]
        threshold: u32,
    },
    /// Halt new client connections network-wide.
    EmergencyPause {
        #[arg(long)]
        reason: String,
    },
    /// Lift an emergency pause.
    EmergencyResume,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenKey { out } => cmd_gen_key(out),
        Commands::Sign {
            key,
            action,
            valid_secs,
            out,
        } => cmd_sign(key, action, valid_secs, out),
        Commands::Inject { tx, bootstrap } => cmd_inject(tx, bootstrap).await,
    }
}

// ── gen-key ───────────────────────────────────────────────────────────────────

fn cmd_gen_key(out: PathBuf) -> Result<()> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let privkey_hex = hex::encode(signing_key.to_bytes());
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    std::fs::write(&out, &privkey_hex)
        .with_context(|| format!("Failed to write private key to {:?}", out))?;

    println!("Private key written to: {:?}", out);
    println!("Keep this file OFFLINE and SECRET — it is your Tier-0 founder key.");
    println!();
    println!("Public key (put this in server/src/genesis.rs as FOUNDER_PUBKEY_HEX):");
    println!("  {}", pubkey_hex);
    Ok(())
}

// ── sign ──────────────────────────────────────────────────────────────────────

fn cmd_sign(key: PathBuf, action: ActionCmd, valid_secs: u64, out: PathBuf) -> Result<()> {
    // Load private key
    let privkey_hex = std::fs::read_to_string(&key)
        .with_context(|| format!("Failed to read key file {:?}", key))?;
    let privkey_hex = privkey_hex.trim();
    let mut privkey_bytes = [0u8; 32];
    hex::decode_to_slice(privkey_hex, &mut privkey_bytes)
        .context("Private key must be 32-byte hex")?;
    let signing_key = SigningKey::from_bytes(&privkey_bytes);

    // Build GovernanceTx
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis() as u64;
    let nonce: u64 = rand::random();
    let tx = GovernanceTx {
        action: action_to_governance(action),
        nonce,
        valid_after_ms: now_ms,
        valid_before_ms: now_ms + valid_secs * 1000,
    };

    // Sign: Ed25519 over bincode(tx)
    let tx_bytes = bincode::serialize(&tx).context("Failed to serialize GovernanceTx")?;
    let signature = signing_key.sign(&tx_bytes);
    let sig_hex = hex::encode(signature.to_bytes());

    let signed = SignedGovernanceTx {
        tx,
        signature_hex: sig_hex,
    };

    let json = serde_json::to_string_pretty(&signed)?;
    std::fs::write(&out, json)
        .with_context(|| format!("Failed to write signed tx to {:?}", out))?;

    println!("Signed transaction written to {:?}", out);
    println!("Nonce:       {}", signed.tx.nonce);
    println!(
        "Valid from:  {} ms (unix)",
        signed.tx.valid_after_ms
    );
    println!("Valid until: {} ms (unix)", signed.tx.valid_before_ms);
    Ok(())
}

fn action_to_governance(a: ActionCmd) -> GovernanceAction {
    match a {
        ActionCmd::AddGenesisKey { pubkey } => GovernanceAction::AddGenesisKey { pubkey_hex: pubkey },
        ActionCmd::RemoveGenesisKey { pubkey } => GovernanceAction::RemoveGenesisKey { pubkey_hex: pubkey },
        ActionCmd::AddSlashKey { did, pubkey } => GovernanceAction::AddSlashKey { did, pubkey_hex: pubkey },
        ActionCmd::RemoveSlashKey { did } => GovernanceAction::RemoveSlashKey { did },
        ActionCmd::SetBftThreshold { threshold } => GovernanceAction::SetBftThreshold { threshold },
        ActionCmd::EmergencyPause { reason } => GovernanceAction::EmergencyPause { reason },
        ActionCmd::EmergencyResume => GovernanceAction::EmergencyResume,
    }
}

// ── inject ────────────────────────────────────────────────────────────────────

async fn cmd_inject(tx_path: PathBuf, bootstrap: String) -> Result<()> {
    // Load signed transaction
    let json = std::fs::read_to_string(&tx_path)
        .with_context(|| format!("Failed to read tx file {:?}", tx_path))?;
    let signed_tx: SignedGovernanceTx =
        serde_json::from_str(&json).context("Failed to parse SignedGovernanceTx JSON")?;

    // Serialize as raw bytes for gossipsub publication
    let tx_bytes = bincode::serialize(&signed_tx).context("Failed to serialize SignedGovernanceTx")?;

    // Build a minimal libp2p swarm — same gossipsub config as the server
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let msg_id_fn = |m: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                m.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };
            let config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(msg_id_fn)
                .build()
                .expect("valid gossipsub config");
            let b: gossipsub::Behaviour = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                config,
            )
            .expect("valid gossipsub behaviour");
            b
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    let topic = gossipsub::IdentTopic::new("ghost_grid_gov");
    swarm.behaviour_mut().subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Dial bootstrap peer
    let bootstrap_addr: libp2p::Multiaddr = bootstrap
        .parse()
        .context("Invalid bootstrap multiaddr")?;
    swarm.dial(bootstrap_addr.clone())?;
    println!("Dialing bootstrap peer: {}", bootstrap_addr);

    // Wait for connection + mesh establishment, then publish
    let mut published = false;
    let deadline = sleep(Duration::from_secs(20));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => {
                anyhow::bail!("Timed out waiting to publish governance tx");
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(gossipsub::Event::GossipsubNotSupported { .. }) => {
                        anyhow::bail!("Bootstrap peer does not support gossipsub");
                    }
                    SwarmEvent::Behaviour(gossipsub::Event::Subscribed { .. }) => {
                        // Give the mesh a moment to form, then publish
                        sleep(Duration::from_secs(2)).await;
                        match swarm.behaviour_mut().publish(topic.clone(), tx_bytes.clone()) {
                            Ok(id) => {
                                println!("GovernanceTx published (msg_id={:?})", id);
                                published = true;
                            }
                            Err(e) => {
                                eprintln!("Publish failed: {:?} — retrying in 1s", e);
                                sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("Connected to peer: {}", peer_id);
                    }
                    _ => {}
                }
            }
        }

        if published {
            // Allow propagation before exiting
            println!("Waiting 5s for propagation...");
            sleep(Duration::from_secs(5)).await;
            println!("Done.");
            break;
        }
    }

    Ok(())
}
