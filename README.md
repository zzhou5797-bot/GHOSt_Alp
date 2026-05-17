# GhostPTY

> **Open-source release** — hosted at [github.com/zzhou5797-bot/GHOSt_Alp](https://github.com/zzhou5797-bot/GHOSt_Alp)

GhostPTY is a zero-trust, kernel-enforced remote terminal gateway built in Rust. It combines QUIC transport, eBPF kernel programs, and a libp2p gossip network to provide authenticated, metered, and audited PTY sessions with no exposure of traditional listening ports.

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

`ValidatorSet` holds the Tier-1 genesis signing keys, slash voter pubkeys, BFT threshold, and the network pause flag. It is initialized from compile-time bootstrap constants and mutated at runtime through the gossipsub slash consensus path. Governance of the validator set itself is handled by a separate closed-source mechanism with no network-visible entry point.

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

GhostPTY implements a three-layer substrate-agnostic protocol for authenticated, self-certifying communication. The Ghost Protocol is implemented in `shared::gp_frame`.

```
┌──────────────────────────────────────────┐
│  L3  SessionFrame  — stream mux + PTY    │
│      PtyData / PtyResize / Meta /        │
│      StreamFin                           │
├──────────────────────────────────────────┤
│  L2  GhostFrame   — DID addressing +    │
│      hash-chain self-authentication      │
│      Magic "GPF1" | type | flags |       │
│      did_src | did_dst | chain_seq |     │
│      chain_tag | payload_len | payload   │
├──────────────────────────────────────────┤
│  L1  Substrate    — any byte carrier     │
│      current: UdpSubstrate (tech-val)    │
│      planned: XDP, LoRa, raw 802.11      │
└──────────────────────────────────────────┘
```

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

### Self-authenticating frames

Every Ghost Frame is self-authenticating: the `chain_tag` is a SipHash-2-4 HMAC over `H_{chain_seq}` using the shared SPA seed. The receiver validates this at L2 without requiring a prior TLS handshake. The `Knock` frame IS the authentication step — equivalent to SPA v2 in the existing XDP path.

### Mapping to existing primitives

| Ghost Protocol | Existing implementation |
|----------------|------------------------|
| `Knock` frame | SPA v2 UDP payload |
| `Data` channel | QUIC connection |
| L3 Session | QUIC streams + `ControlMessage` |
| DID addressing | u32 DID from X.509 CN |
| Self-certification | hash-chain + GCv3 state file |

---

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

## Key Configuration

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

## Health Probe

A plain HTTP server listens on `:8081`. `GET /` returns `200 OK`. Suitable for Kubernetes liveness/readiness probes. Limited to 10 concurrent connections.

---

## License

See [LICENSE](LICENSE).
