#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TOKEN="ghost-mcp-smoke-token"
PORT="$(printenv GHOST_MCP_SMOKE_PORT 2>/dev/null || echo 19080)"
AGENT_LOG="/tmp/ghost_mcp_agent_smoke.log"
SPA_STATE="/tmp/ghost_mcp_spa_smoke_$$"

cargo build -p ghost-mcp-agent -p ghost-mcp >/dev/null

GHOST_MCP_TOKEN="$TOKEN" ./target/debug/ghost-mcp-agent   --listen "127.0.0.1:$PORT"   >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!

cleanup() {
  kill "$AGENT_PID" 2>/dev/null || true
  wait "$AGENT_PID" 2>/dev/null || true
  rm -f "$SPA_STATE"
}
trap cleanup EXIT

for _ in $(seq 1 40); do
  if grep -q "Ghost shell agent ready" "$AGENT_LOG" 2>/dev/null; then break; fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then cat "$AGENT_LOG" >&2; exit 1; fi
  sleep 0.1
done

mcp_call() {
  local token="$1"
  local id="$2"
  local command="$3"
  local cwd_json="$4"
  GHOST_MCP_TOKEN="$token" GHOST_MCP_PORT="$PORT" timeout 10 ./target/debug/ghost-mcp <<EOF2
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ghost-mcp-smoke","version":"0.1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":$id,"method":"tools/call","params":{"name":"shell","arguments":{"command":$command,"cwd":$cwd_json,"timeout_ms":5000}}}
EOF2
}

echo "[1/5] shell"
OUT="$(mcp_call "$TOKEN" 2 '"printf ghost-shell-ok"' null)"
grep -q "ghost-shell-ok" <<<"$OUT"
grep -q "exit_code" <<<"$OUT"

echo "[2/5] cwd"
OUT="$(mcp_call "$TOKEN" 3 '"pwd"' '"/tmp"')"
grep -q '/tmp' <<<"$OUT"

echo "[3/5] normal shell features"
OUT="$(mcp_call "$TOKEN" 4 '"printf alpha | tr a-z A-Z"' null)"
grep -q "ALPHA" <<<"$OUT"

echo "[4/5] gateway-mode SPA generation"
OUT="$(GHOST_MCP_GATEWAY=true GHOST_MCP_STATE_FILE="$SPA_STATE" mcp_call "$TOKEN" 5 '"printf spa-ok"' null)"
grep -q "spa-ok" <<<"$OUT"
test "$(wc -c < "$SPA_STATE")" -eq 28
SPA_SEQ="$(python3 -c 'import struct,sys; d=open(sys.argv[1],"rb").read(); print(struct.unpack("<Q", d[12:20])[0])' "$SPA_STATE")"
test "$SPA_SEQ" -eq 9999

echo "[5/5] bad token rejection"
OUT="$(mcp_call wrong-token 6 '"printf should-not-run"' null || true)"
grep -q '"isError":true' <<<"$OUT"
grep -q "authentication" <<<"$OUT"

echo "Ghost MCP shell smoke test: PASS"
