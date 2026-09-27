# Ghost MCP bridge

`ghost-mcp` is an experimental Desktop Commander-style MCP bridge built on the
Ghost repository's Rust + QUIC + mutual-TLS stack.

```text
MCP client
   |
   | stdio MCP (rmcp)
   v
ghost-mcp
   |
   | QUIC + mTLS, ALPN ghostmcp/1
   v
ghost-mcp-agent
   |
   +-- system_info
   +-- list_directory
   +-- read_file
   +-- write_file
   +-- run_command (disabled by default)
```

This milestone separates the MCP tool plane from the existing root-only XDP/eBPF
GhostPTY server so the complete MCP -> Ghost transport -> host tool cycle can run
without root. The existing GhostPTY XDP/SPA path is unchanged.

## Security model

- Mutual TLS is required, followed by a bearer token.
- File tools are constrained to `--root`; canonical-path checks reject escapes.
- `run_command` is disabled unless `--enable-command` is passed.
- A denylist blocks privilege-management and destructive system commands.
- `run_command` is not filesystem-sandboxed; keep it disabled for untrusted callers.
- The certificates committed under `certs/` are public development fixtures.
- The current bridge does not yet perform the Ghost SPA/hash-chain/XDP gate.
  Bind to localhost for development; production exposure should use the full gateway.

## Build and run

```bash
cargo build -p ghost-mcp-agent -p ghost-mcp
export GHOST_MCP_TOKEN='replace-with-a-random-secret'

./target/debug/ghost-mcp-agent \
  --listen 127.0.0.1:9080 \
  --root "$PWD"

# Add --enable-command only when command execution is intended.
./target/debug/ghost-mcp --host 127.0.0.1 --port 9080
```

The bridge uses stdio, so stdout is reserved for MCP protocol frames.

## Smoke test

```bash
bash tests/mcp_smoke.sh
```

The smoke test performs separate MCP sessions for system info, write/read,
command execution, path-escape rejection, and bad-token rejection. Separate
sessions make ordering explicit because independent MCP tool calls may run
concurrently.
