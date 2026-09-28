# Ghost MCP shell

The MCP surface is intentionally minimal: it exposes one tool, `shell`.

```text
MCP client
   -> ghost-mcp
   -> optional SPA v2 knock
   -> Ghost QUIC + mTLS
   -> /bin/sh -lc "<command>"
   -> stdout / stderr / exit code
```

There are no MCP file, directory, search, or process-management tools. Use normal
shell commands for those jobs.

## Tool

`shell` accepts:

- `command` — required shell command
- `cwd` — optional working directory
- `timeout_ms` — optional timeout, default 30s, maximum 300s

The command runs with the operating-system privileges of the Ghost process that
executes it. If the full Ghost gateway runs as root, the MCP shell is therefore
a root shell. Authentication remains Ghost's responsibility: SPA/XDP, mTLS DID,
token, quota/revocation, and QUIC transport.

## Standalone development mode

```bash
cargo build -p ghost-mcp-agent -p ghost-mcp
export GHOST_MCP_TOKEN='replace-with-a-random-secret'

./target/debug/ghost-mcp-agent --listen 127.0.0.1:9080
./target/debug/ghost-mcp --host 127.0.0.1 --port 9080
```

## Full Ghost gateway mode

Use a client certificate whose CN is the numeric DID passed as `--target`:

```bash
./target/debug/ghost-mcp \
  --gateway \
  --host 127.0.0.1 \
  --port 8080 \
  --target 1 \
  --cert /path/to/did-1.crt \
  --key /path/to/did-1.key
```

## Tests

```bash
bash tests/mcp_smoke.sh
make test-mcp-gateway
```

The first test is non-root. The second exercises the real SPA/XDP gateway path
and therefore requires the normal Ghost eBPF prerequisites.
