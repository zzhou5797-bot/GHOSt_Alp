#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Ghost MCP gateway e2e requires root." >&2
  exit 1
fi

PORT="$(printenv GHOST_MCP_GATEWAY_TEST_PORT 2>/dev/null || echo 19090)"
TOKEN="ghost-mcp-gateway-e2e"
TMP="$(mktemp -d)"
SERVER_LOG="$TMP/server.log"
STATE_FILE="$TMP/chain-state"
CLIENT_KEY="$TMP/did1.key"
CLIENT_CSR="$TMP/did1.csr"
CLIENT_CERT="$TMP/did1.crt"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "[1/5] build userspace + eBPF"
cargo build -p server -p ghost-mcp
cargo xtask build-ebpf

echo "[2/5] create DID=1 client certificate"
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "/CN=1" >/dev/null 2>&1
openssl x509 -req -in "$CLIENT_CSR" -CA certs/ca.crt -CAkey certs/ca.key \
  -set_serial 9001 -days 1 -out "$CLIENT_CERT" >/dev/null 2>&1

echo "[3/5] start full Ghost gateway"
GATEWAY_TOKEN="$TOKEN" ./target/debug/server \
  --port "$PORT" --iface lo \
  --ca certs/ca.crt --cert certs/server.crt --key certs/server.key \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  if grep -q "QUIC Server listening" "$SERVER_LOG"; then break; fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then cat "$SERVER_LOG" >&2; exit 1; fi
  sleep 0.1
done

mcp_shell() {
  local id="$1"
  local command="$2"
  local cwd_json="$3"
  GHOST_MCP_TOKEN="$TOKEN" GHOST_MCP_PORT="$PORT" GHOST_MCP_GATEWAY=true \
  GHOST_MCP_TARGET=1 GHOST_MCP_CERT="$CLIENT_CERT" GHOST_MCP_KEY="$CLIENT_KEY" \
  GHOST_MCP_STATE_FILE="$STATE_FILE" timeout 10 ./target/debug/ghost-mcp <<EOF2
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ghost-gateway-e2e","version":"0.1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":$id,"method":"tools/call","params":{"name":"shell","arguments":{"command":$command,"cwd":$cwd_json,"timeout_ms":5000}}}
EOF2
}

echo "[4/5] Ghost gateway shell"
OUT="$(mcp_shell 2 '"printf gateway-shell-ok"' null)"
grep -q "gateway-shell-ok" <<<"$OUT"
grep -q "exit_code" <<<"$OUT"

echo "[5/5] cwd"
OUT="$(mcp_shell 3 '"pwd"' '"/tmp"')"
grep -q "/tmp" <<<"$OUT"

echo "Ghost MCP full gateway shell e2e: PASS"
