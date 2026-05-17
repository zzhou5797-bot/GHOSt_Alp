# GhostPTY

> **Open-source release** — [github.com/zzhou5797-bot/GHOSt_Alp](https://github.com/zzhou5797-bot/GHOSt_Alp) · Apache-2.0 · Alpha

**A communication protocol and remote terminal that does not require TCP/IP infrastructure — no routable IP address, no CA, no DNS, no coordination server.**

`nmap` shows nothing. Shodan finds nothing. The server is running. This is not a firewall rule. This is cryptography at the NIC layer, before IP.

---

## Why This Exists

TCP/IP is not just a protocol. It is a system built on centralized institutions:

- **IP addresses** are allocated by IANA → regional RIRs → ISPs. Your address is a lease, not property.
- **Routing** is BGP — a system where any AS can advertise any prefix, and the internet routes through it until someone notices. Trust-based by design.
- **Names** are DNS — controlled by ICANN and a hierarchy of registrars that can be legally compelled.
- **Identity** is PKI — your TLS certificate is blessed by a CA that can be compromised, coerced, or simply go out of business.

Every tool built on top of TCP/IP inherits all of these dependencies. Tailscale routes through coordination servers on AWS. Cloudflare Tunnel routes through Cloudflare's AS. Your self-hosted VPN still needs a routable IP and a CA-signed certificate for anyone to trust it. You have moved the centralization around, not eliminated it.

**GhostPTY is an attempt to build a layer underneath TCP/IP's assumptions.**

> **Identity is proved by math, not issued by institutions. A node's existence on the network is not contingent on any third party's cooperation.**

The Ghost Protocol (L1/L2/L3) is designed so that:
- **Authentication requires no CA and no prior channel** — a hash-chain proof embedded in a single frame is sufficient
- **Addressing requires no DNS and no routable IP** — nodes are addressed by DID (a u32 derived from a hash chain), not by IP
- **The link layer is pluggable** — the same protocol frames run over UDP today, and over raw 802.11, LoRa, or serial tomorrow. If the internet goes away, the protocol keeps working
- **Revocation requires consensus** — no single operator can unilaterally remove a node; BFT multi-signature voting is required

GhostPTY is a remote terminal built on this protocol. The terminal is the proof of concept. The protocol is the point.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Client                                                       │
│  SPA knock (UDP) → QUIC mTLS connect → PTY I/O streams       │
└────────────────────────────┬─────────────────────────────────┘
                             │ UDP / QUIC
┌────────────────────────────▼─────────────────────────────────┐
│  NIC / XDP layer  (gateway-ebpf)                             │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ SPA v2 hash-chain verifier                           │    │
│  │ SPA v1 timestamp verifier  (backward compat)         │    │
│  │ Token-bucket rate limiter per DID                    │    │
│  │ ALLOW_LIST_MAP hot-path pass-through                 │    │
│  │ SOVEREIGN_RB ring buffer (filter not in this repo)   │    │
│  └──────────────────────────────────────────────────────┘    │
└────────────────────────────┬─────────────────────────────────┘
                             │ XDP_PASS (authorized QUIC only)
┌────────────────────────────▼─────────────────────────────────┐
│  Server daemon  (server crate)                               │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ QUIC+mTLS   │  │ Handshake /  │  │ PTY session        │  │
│  │ endpoint    │  │ Genesis      │  │ (portable-pty +    │  │
│  │ (quinn)     │  │ bootstrap    │  │  cgroupv2 jail)    │  │
│  └──────┬──────┘  └──────┬───────┘  └────────┬───────────┘  │
│         │                │                    │              │
│  ┌──────▼────────────────▼────────────────────▼───────────┐  │
│  │  Quota engine:  per-session byte counter +             │  │
│  │  SYNC_THRESHOLD flush → AUTH_STATE_MAP (eBPF map)      │  │
│  │  Guillotine: atomic pre-check → hard kill on exhaust   │  │
│  └───────────────────────┬────────────────────────────────┘  │
│                          │                                   │
│  ┌───────────────────────▼────────────────────────────────┐  │
│  │  GC daemon: tombstones dead/exhausted sessions every   │  │
│  │  10 s by setting quota_bytes=0 + revoked=1             │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  audit_execve tracepoint → AuditEvent perf-array       │  │
│  │  Per-CPU reader → binary allowlist → P2P slash vote    │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  libp2p gossipsub control plane                        │  │
│  │   ghost_grid_quota  – cross-node quota sync            │  │
│  │   ghost_grid_slash  – BFT revocation consensus         │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## The Problem with Building on TCP/IP

Every tool in this space is built on top of TCP/IP and inherits its centralized dependencies:

| Dependency | Who controls it | What happens if they act against you |
|------------|----------------|--------------------------------------|
| IP address | IANA → RIR → ISP | Address revoked, traffic rerouted |
| BGP routing | Tier-1 ASes | Route hijack (this has happened) |
| DNS name | ICANN → registrar | Domain seized or suspended |
| TLS certificate | CA (Let's Encrypt, DigiCert…) | Certificate revoked, HTTPS breaks |
| Cloud infra | AWS / GCP / Azure | Account terminated, endpoints gone |

Ghost Protocol is designed to not require any of these. A node is identified by a DID derived from a hash chain — no RIR, no registrar, no CA involved. The link layer is pluggable — no assumption that IP routing is available.

| | Tailscale | Cloudflare Tunnel | WireGuard (self-hosted) | **GhostPTY / Ghost Protocol** |
|---|---|---|---|---|
| Requires routable IP | Yes | Yes | Yes | **No (DID addressing)** |
| Requires CA / PKI | Yes | Yes | Yes (for trust) | **No for L2 auth** |
| Requires coordination server | Yes (their cloud) | Yes (their edge) | No | **No** |
| Requires internet (TCP/IP) | Yes | Yes | Yes | **No — LoRa / 802.11 / serial** |
| Kernel-layer enforcement | No | No | No | **Yes — XDP before IP stack** |
| Revocation by consensus | No | No | No | **Yes — BFT multi-sig** |

---

## How a Session Is Established

1. **SPA knock** — The client sends a single UDP packet to port 8080 containing a `SpaPayload` (magic, version, DID subject, descending sequence number, SipHash-2-4 chain tag). The XDP program verifies the chain, updates `AUTH_STATE_MAP`, binds the client IP in `ALLOW_LIST_MAP`, and silently drops the knock packet.

2. **QUIC connect** — With the IP now whitelisted, the client opens a QUIC connection (mTLS, ALPN `ghostpty/1`). The server reads the X.509 CN field to extract the numeric DID subject.

3. **Handshake** — A unidirectional control stream carries `ControlMessage` frames: `Authenticate` (bearer token + optional `GenesisCredential`), `SetEnv`, `Resize`, `StartShell`. The token is verified with constant-time comparison.

4. **Genesis bootstrap** — If the DID subject has no `AUTH_STATE_MAP` entry, the server checks the `GenesisCredential` signature against the live `ValidatorSet` (Tier-1 Ed25519 keys). On success it writes an initial quota entry and gossips the allocation to peer nodes.

5. **PTY spawn** — A `portable-pty` pair is opened. The shell process is re-exec'd through the server binary itself so it can join a per-session cgroupv2 directory before becoming `sh`. The cgroup ID is registered in `AUDIT_CGROUP_MAP`.

6. **I/O routing** — Two bidirectional QUIC streams bridge the PTY master. Byte consumption is tracked atomically; every 64 KB (`SYNC_THRESHOLD`) the quota is flushed to the eBPF map and gossiped to peers.

7. **Guillotine** — If either the atomic counter or the eBPF map quota reaches zero, the relevant async task exits immediately, causing the QUIC stream to close.

---

## Security Layers

### XDP / Kernel Layer

| Mechanism | Description |
|-----------|-------------|
| SPA v2 (hash chain) | Each knock carries `H_{N-x}` — a SipHash-2-4 preimage relative to the current anchor. Verifier does at most 10 hash steps, O(1) bounded. |
| SPA v1 (timestamp) | Legacy 60-second recency window + LRU replay filter (`REPLAY_FILTER_MAP`). |
| Token bucket | Per-DID kernel-side rate limiter. 512-token burst, 1-token/ms refill. Applied on every packet in the hot path. |
| Revocation | `auth_state.revoked > 0` causes `XDP_DROP` for all packets from that DID at NIC speed. |

### QUIC / mTLS Layer

- TLS 1.3 enforced via `rustls 0.23`
- Client certificate required; verified against the CA
- CN field parsed as `u32` DID; multiple CNs rejected
- Constant-time token comparison (`subtle`)
- Control message size capped at 64 KB to prevent OOM

### Cgroup Audit Layer

- Each session gets its own cgroupv2 directory under `/sys/fs/cgroup/ghostpty_sessions/`
- The `audit_execve` tracepoint fires on every `execve` syscall inside tracked cgroups
- A binary allowlist is checked; unknown binaries trigger a P2P slash vote

### P2P / BFT Consensus

| Topic | Purpose |
|-------|---------|
| `ghost_grid_quota` | Propagates per-DID quota consumption deltas to all nodes |
| `ghost_grid_slash` | Carries Ed25519-signed revocation votes; BFT threshold applies |

Slash votes are verified with `verify_slash_signature()` against the live `ValidatorSet`. When `votes.len() >= bft_threshold`, the subject's `revoked` flag is set in the local eBPF map.

### ValidatorSet (Tier-1 Governance)

`ValidatorSet` holds the Ed25519 genesis signing keys, slash voter pubkeys, BFT threshold, and the network pause flag. It is initialized from compile-time bootstrap constants and mutated at runtime through the gossipsub slash consensus path.

Governance of the `ValidatorSet` itself — adding or removing Tier-1 keys — is an on-chain operation outside this repository. The design intent is that no single party, including the original authors, can unilaterally modify the validator set: doing so requires the same BFT threshold as any other governance action. The current bootstrap set is embedded in `server/src/genesis.rs` and is visible in the open-source code.

---

## Workspace Crates

| Crate | Role |
|-------|------|
| `server` | Gateway daemon: QUIC endpoint, eBPF map management, session lifecycle, GC, audit |
| `shared` | Wire types shared between server and client: `ControlMessage`, `GenesisCredential`, and the **Ghost Protocol frame codec** (`gp_frame`) |
| `gateway-ebpf` | Kernel BPF programs: XDP SPA verifier + rate limiter, `audit_execve` tracepoint |
| `gateway-ebpf-common` | `no_std` types shared between eBPF and userspace: `AuthState`, `AuditEvent`, `SpaPayload`, `SovereignItem` |
| `ghost-chain-tests` | Integration test harness: hash-chain / quota subsystems + Ghost Protocol real-UDP stack tests |
| `xtask` | Build automation: `cargo xtask build-ebpf` compiles the BPF target; `cargo run --bin gov` manages Tier-1 validator keys |

---

## Ghost Protocol

GhostPTY is built on top of the **Ghost Protocol** — a substrate-agnostic, three-layer communication protocol designed for a post-centralized-internet environment.

The core design goal: **a node should be able to prove its identity to another node and establish a secure channel using only shared cryptographic state, with no reliance on any third-party infrastructure.** No CA, no DNS, no NTP, no coordination server.

```
┌──────────────────────────────────────────┐
│  L3  SessionFrame  — stream mux + PTY    │
│      PtyData / PtyResize / Meta /        │
│      StreamFin                           │
├──────────────────────────────────────────┤
│  L2  GhostFrame   — DID addressing +     │
│      hash-chain self-authentication      │
│      Magic "GPF1" | type | flags |       │
│      did_src | did_dst | chain_seq |     │
│      chain_tag | payload_len | payload   │
├──────────────────────────────────────────┤
│  L1  Substrate    — any byte carrier     │
│      current: UdpSubstrate               │
│      planned: raw 802.11, LoRa, serial   │
└──────────────────────────────────────────┘
```

### L1 — Substrate: why it matters

The `Substrate` trait abstracts the link layer down to two operations: `send(dst: &[u8], bytes)` and `recv() -> (src, bytes)`. The address is opaque bytes — an IPv4+port tuple for UDP, a MAC address for raw 802.11, a device ID for LoRa.

This means Ghost Protocol is not tied to IP networking. Planned implementations:

| Substrate | Use case |
|-----------|----------|
| `UdpSubstrate` | Standard IP networks (current) |
| `XdpSubstrate` | Bypass kernel IP stack entirely via AF_XDP |
| `Ieee80211Substrate` | Direct node-to-node over raw 802.11 Ad-hoc frames, no AP, no DHCP |
| `LoraSubstrate` | Off-grid, long-range ISM-band radio, no SIM card, no carrier |
| `SerialSubstrate` | Cross-domain links across physically isolated networks |

If your ISP goes down, if BGP is hijacked, if you are managing infrastructure in a location without internet connectivity — the protocol still runs, as long as two nodes can exchange bytes by any means.

### L2 — GhostFrame: self-certifying identity

Every L2 frame is self-authenticating. The `chain_tag` field is a SipHash-2-4 HMAC over `H_{chain_seq}` derived from the shared SPA seed:

```
chain_tag = SipHash-2-4(H_{chain_seq}, shared_seed)
```

The receiver can verify the sender's identity at L2 before any TLS session exists. The `Knock` frame IS the authentication — not a precursor to it. There is no CA involved in this step.

### L2 Wire Layout (little-endian, 34-byte header)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic: `GPF1` (0x47 0x50 0x46 0x31) |
| 4 | 1 | `frame_type`: `Knock=0x01` `Data=0x02` `Ctrl=0x03` `Ack=0x04` `Fin=0x05` |
| 5 | 1 | `flags` (reserved, must be 0) |
| 6 | 2 | reserved |
| 8 | 4 | `did_src` (u32 LE) |
| 12 | 4 | `did_dst` (u32 LE) |
| 16 | 8 | `chain_seq` (u64 LE, descending — replay protection) |
| 24 | 8 | `chain_tag` (u64 LE, SipHash-2-4 proof over `H_{chain_seq}`) |
| 32 | 2 | `payload_len` (u16 LE) |
| 34 | N | payload |

### L3 Wire Layout (little-endian, 5-byte header, inside L2 payload)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | `stream_id` (u16 LE) |
| 2 | 1 | `session_type`: `PtyData=0x01` `PtyResize=0x02` `Meta=0x03` `StreamFin=0x04` |
| 3 | 2 | `payload_len` (u16 LE) |
| 5 | N | payload |

### Mapping to existing primitives

| Ghost Protocol | Current implementation |
|----------------|------------------------|
| `Knock` frame | SPA v2 UDP payload (XDP-verified) |
| `Data` channel | QUIC connection |
| L3 Session | QUIC streams + `ControlMessage` |
| DID addressing | u32 DID parsed from mTLS X.509 CN |
| Hash-chain proof | SipHash-2-4 chain in `gateway-ebpf` |

> **Note on the mTLS layer**: the QUIC connection (post-knock) still uses X.509 certificates for mutual TLS. These require a CA. The hash-chain authentication at L2 is CA-free and operates before the TLS session; the X.509 layer provides an additional binding between the DID and a certificate. In future Substrate implementations (e.g. LoRa) the QUIC/TLS layer would be replaced by a lighter-weight construction using only the L2 chain-tag proof.

## Building

### Prerequisites

- Rust nightly (required by `aya` eBPF target)
- `bpf-linker`: `cargo install bpf-linker`
- Linux kernel ≥ 5.15 (cgroupv2 + BPF ring buffer)
- Root or `CAP_BPF + CAP_NET_ADMIN` at runtime

### Build

```bash
# Build the eBPF kernel programs (cross-compiles to bpfel-unknown-none)
cargo xtask build-ebpf

# Build all userspace crates
cargo build --workspace --exclude gateway-ebpf
```

### Certificates

> **WARNING**: The `certs/` directory contains **self-signed development-only test certificates**.
> They are tracked in git solely to allow zero-configuration local testing.
> **Never use these certificates in production.** Generate your own CA and sign fresh server/client
> certificates for any real deployment.

```bash
# Generate CA + server cert + client cert
# (see certs/ directory for scripts)
openssl ...
```

### Run

```bash
# Server (requires root for XDP attach)
sudo GATEWAY_TOKEN=<token> cargo run -p server -- --iface eth0 --port 8080

# Client
cargo run -p client -- --server 1.2.3.4:8080 --token <token>
```

---

---

## Operational Notes

### Health Probe

A plain HTTP server listens on `:8081`. `GET /` returns `200 OK`. Suitable for Kubernetes liveness/readiness probes or any external health-check system. Limited to 10 concurrent connections.

### Key Configuration

| Flag / Env | Default | Description |
|------------|---------|-------------|
| `--port` | `8080` | QUIC listen port |
| `--iface` | `lo` | Network interface for XDP attach |
| `--ca` | `../certs/ca.crt` | CA certificate for mTLS |
| `--cert` | `../certs/server.crt` | Server TLS certificate |
| `--key` | `../certs/server.key` | Server TLS private key |
| `GATEWAY_TOKEN` | _(required, no default)_ | Bearer token checked in handshake — must be set; server refuses to start without it |
| `--bootstrap-peers` | _(none)_ | Comma-separated libp2p multiaddrs for P2P mesh |
| `DEV_PRIV_KEY` | _(none)_ | Hex-encoded Ed25519 key for signing slash votes |

---

## License

See [LICENSE](LICENSE).
