# GhostPTY

GhostPTY is a secure, high-performance, remote terminal access solution built with Rust, leveraging QUIC, eBPF, and libp2p. It provides a robust, decentralized, and highly secure infrastructure for establishing remote PTY (Pseudo-Terminal) sessions with embedded DDoS mitigation, zero-trust authentication, and cryptographic quota management.

## Key Features

- **QUIC Protocol**: Uses `quinn` for fast, multiplexed, and secure communication streams over UDP.
- **eBPF Integration**: Incorporates `aya` and custom eBPF programs for high-performance packet filtering, DDoS protection, and rate limiting directly in the Linux kernel.
- **Zero-Trust Security**: Employs mutual TLS (mTLS) via `rustls` with client certificate verification and identity extraction from X.509 CN fields.
- **Cryptographic Metering**: Features a token bucket implementation and cryptographic proof-of-work/hashing algorithms for request validation and quota enforcement.
- **P2P Networking**: Utilizes `libp2p` for decentralized node discovery, gossiping, and swarm management.
- **Cgroups Integration**: Uses Linux cgroups to manage and isolate resources for spawned PTY sessions.
- **DDoS Mitigation (The Guillotine)**: Actively monitors byte consumption and instantly severs connections while evicting malicious actors from eBPF allow-lists when quotas are exceeded.

## Architecture & Components

The workspace is organized into several key crates:

- **`server`**: The core gateway node daemon. It listens for incoming QUIC connections, performs mTLS handshakes, manages eBPF maps, enforces quotas, handles p2p networking, and spawns/manages PTY sessions.
- **`client`**: The client-side application for connecting to a GhostPTY gateway. It handles authenticating to the server, setting up the QUIC connection, and transmitting terminal I/O.
- **`shared`**: Common data structures, enums, and utility functions shared between the client and server (e.g., control messages).
- **`gateway-ebpf`**: The eBPF programs compiled to BPF bytecode. These run in the kernel to perform fast-path network filtering and packet inspection.
- **`gateway-ebpf-common`**: Shared types and constants used by both the user-space server and the kernel-space eBPF programs (e.g., Map structures, constants).
- **`ghost-chain-tests`**: Core cryptographic algorithms, hashing, and token bucket implementations used for metering and request validation.
- **`xtask`**: A custom cargo task runner for building the eBPF programs and other build-related chores.
- **`client/src/bin/ddos_poc.rs`**: A Proof-of-Concept attacker script designed to test the system's resilience against aggressive quota-draining attacks via highly concurrent streams.

## Technology Stack

- **Language**: Rust
- **Networking**: `quinn` (QUIC), `libp2p`, `tokio` (Async runtime)
- **Security**: `rustls` (TLS 1.3), `ed25519-dalek`, `rcgen`, `x509-parser`
- **System**: `portable-pty` (Terminal emulation), `aya` (eBPF), `libc`
- **Build/Tooling**: `cargo`, `xtask`, `rust-analyzer`, `clippy`

## Getting Started

*(Instructions for building, configuring, and running the server and client will go here)*

## Development

To build the eBPF programs:
```bash
cargo xtask build-ebpf
```

To run tests:
```bash
cargo test --workspace
```
