# Ghost MCP shell

The MCP surface is intentionally minimal: it exposes one tool, `shell`.

```text
ChatGPT
   -> HTTPS Streamable MCP
   -> OAuth 2.1 + PKCE
   -> Ghost plugin server
   -> ghost-shell-proxy
   -> Ghost QUIC + mTLS
   -> ghost-mcp-agent
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
executes it.

## Independent ChatGPT plugin

The standalone plugin lives in `ghost-plugin/`. It exposes a Streamable HTTP MCP
endpoint at `/mcp` and implements a small single-owner OAuth 2.1 authorization
server with PKCE.

The public ChatGPT-facing side is:

- `GET /.well-known/oauth-protected-resource`
- `GET /.well-known/oauth-authorization-server`
- `GET /authorize`
- `POST /authorize`
- `POST /token`
- `POST|GET|DELETE /mcp`
- `GET /healthz`

Only ChatGPT CIMD client identifiers and ChatGPT redirect URIs are accepted by
the authorization endpoint. The owner password and HMAC signing key are generated
locally under `target/` with mode 0600 and are never committed.

### Start it as a user service

```bash
bash scripts/install-ghost-plugin-service.sh
```

The service builds the Ghost proxy/agent, installs the MCP Node dependencies,
starts the local Ghost agent, starts the HTTPS ingress, then starts the remote
MCP server.

Useful local checks:

```bash
systemctl --user status ghost-plugin.service
cat target/ghost-plugin-url
cat target/.ghost-plugin-password
```

The password is only for the browser-based OAuth consent screen. Do not paste it
into chat.

### Development ingress

The development supervisor uses an outbound TCP/443 SSH ingress because this host
blocks Cloudflare Tunnel port 7844. The anonymous development ingress may rotate.

For a stable deployment, put the plugin behind your own stable HTTPS reverse proxy
and set:

```bash
GHOST_PLUGIN_PUBLIC_ORIGIN=https://ghost.example.com
```

When `GHOST_PLUGIN_PUBLIC_ORIGIN` is set, the supervisor does not need to create
a temporary public URL.

## ChatGPT connection

In ChatGPT developer mode, create a personal plugin using the HTTPS URL in:

```bash
cat target/ghost-plugin-url
```

On first use ChatGPT follows OAuth discovery and opens the Ghost authorization
page. Read `target/.ghost-plugin-password` locally on the host and enter it in
that page. ChatGPT then receives a scoped `shell:execute` access token.

The runtime path after connection is independent of Desktop Commander and does
not use Desktop Commander calls or quota.

## Local stdio development mode

The original stdio MCP bridge is still available for local testing:

```bash
cargo build -p ghost-mcp-agent -p ghost-mcp
export GHOST_MCP_TOKEN='replace-with-a-random-secret'

./target/debug/ghost-mcp-agent --listen 127.0.0.1:9080
./target/debug/ghost-mcp --host 127.0.0.1 --port 9080
```

## Tests

```bash
bash tests/mcp_smoke.sh
make test-mcp-gateway
```

The non-root smoke verifies shell, cwd, normal shell features, SPA generation,
and bad-token rejection. The root gateway test exercises the real SPA/XDP path.

The remote plugin has also been self-tested end to end with OAuth authorization
code + PKCE, MCP initialize, `tools/list`, and a remote `shell` call.
