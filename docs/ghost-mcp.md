# Ghost MCP bridge

`ghost-mcp` exposes Desktop Commander-style MCP tools and can run in two transport modes.

```text
Development mode
MCP client -> stdio MCP -> ghost-mcp -> QUIC+mTLS -> ghost-mcp-agent -> host

Full Ghost gateway mode
MCP client -> stdio MCP -> ghost-mcp -> SPA v2 hash-chain -> XDP/eBPF
           -> QUIC+mTLS (ALPN ghostmcp/1) -> Ghost gateway tool plane -> host
```

Available tools are `system_info`, `list_directory`, `read_file`, `write_file`,
and `run_command`.

## Shared tool policy

`ghost-mcp-tools` contains the filesystem and command policy used by both the
standalone development agent and the full gateway. File paths are canonicalized
under one configured root, including symlink-escape checks. UTF-8 file/command
output is size capped.

`run_command` is off by default. The standalone agent enables it with
`--enable-command`; the gateway uses `--mcp-enable-command`. A denylist blocks
privilege-management and destructive system commands.

In full gateway mode command children are re-executed through the server wrapper,
join a per-MCP-session cgroup before `sh -lc`, and are registered in the existing
`AUDIT_CGROUP_MAP`. Existing Ghost exec allowlist/slash policy therefore still
applies; the MCP path does not bypass kernel auditing.

## Development mode (no root)

```bash
cargo build -p ghost-mcp-agent -p ghost-mcp
export GHOST_MCP_TOKEN='replace-with-a-random-secret'

./target/debug/ghost-mcp-agent \
  --listen 127.0.0.1:9080 \
  --root "$PWD"

./target/debug/ghost-mcp --host 127.0.0.1 --port 9080
```

The checked-in certificates are development fixtures. Do not expose the standalone
agent externally with those keys.
## Full Ghost gateway mode

The gateway advertises both `ghostpty/1` and `ghostmcp/1`. The negotiated ALPN
selects the interactive PTY path or the structured MCP path. MCP traffic uses the
same DID certificate validation, network pause state, AUTH_STATE_MAP quota,
ALLOW_LIST_MAP lease, P2P quota gossip, and optional cgroup audit infrastructure.

The MCP bridge must send an SPA knock before every new QUIC tool connection:

```bash
export GHOST_MCP_TOKEN='replace-with-a-random-secret'

./target/debug/ghost-mcp \
  --gateway \
  --host 127.0.0.1 \
  --port 8080 \
  --target 1 \
  --cert /path/to/did-1.crt \
  --key /path/to/did-1.key \
  --state-file ~/.ghost_mcp_chain_state
```

The mTLS client certificate CN must be the same numeric DID supplied by `--target`.
The repository's existing `certs/client.crt` has `CN=client`, so it is suitable for
the standalone development agent but not the full gateway DID check.

The default development SPA key string is
`deadbeef01020304badce0ff0a0b0c0d`. It is parsed as little-endian key bytes so
it exactly matches the XDP constants. The gateway seeds dev DID 1 with H_N and
clients send H_(N-1) first, matching the XDP strict descending-sequence verifier.

Existing pinned zero-anchor dev state is migrated once. Existing revoked or
zero-quota state is not automatically revived on server restart.

## Tests

Non-root smoke test:

```bash
bash tests/mcp_smoke.sh
```

It covers MCP initialization, read/write, command execution, absolute and symlink
path escape rejection, gateway-mode SPA state generation, and bad-token rejection.

Full SPA -> XDP -> mTLS -> MCP gateway test requires root, cgroupv2, and a nightly Rust toolchain with `rust-src` for the BPF target. The repository now provides a working `cargo xtask build-ebpf` alias; install the toolchain with `rustup toolchain install nightly --component rust-src` (or set `GHOST_BPF_CARGO` to a nightly Cargo executable).

```bash
make test-mcp-gateway
# or: bash tests/mcp_gateway_e2e.sh
```

The full test builds the eBPF program, generates a temporary CA-signed `CN=1`
client certificate, starts the real Ghost gateway, and exercises system info,
file I/O, audited command execution, and path confinement.
