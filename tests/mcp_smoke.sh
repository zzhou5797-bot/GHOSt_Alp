#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TOKEN="ghost-mcp-smoke-token"
PORT="$(printenv GHOST_MCP_SMOKE_PORT 2>/dev/null || echo 19080)"
PROBE="target/ghost_mcp_probe.txt"
ESCAPE_DIR="/tmp/ghost_mcp_escape_$$"
ESCAPE_LINK="target/ghost_mcp_escape_link"
AGENT_LOG="/tmp/ghost_mcp_agent_smoke.log"
SPA_STATE="/tmp/ghost_mcp_spa_smoke_$$"

cargo build -p ghost-mcp-agent -p ghost-mcp >/dev/null

GHOST_MCP_TOKEN="$TOKEN" ./target/debug/ghost-mcp-agent \
  --listen "127.0.0.1:$PORT" \
  --root "$ROOT" \
  --enable-command \
  >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!

cleanup() {
  kill "$AGENT_PID" 2>/dev/null || true
  wait "$AGENT_PID" 2>/dev/null || true
  rm -f "$PROBE" "$ESCAPE_LINK" "$SPA_STATE"
  rm -rf "$ESCAPE_DIR"
}
trap cleanup EXIT

mkdir -p "$ESCAPE_DIR"
rm -f "$ESCAPE_LINK"
ln -s "$ESCAPE_DIR" "$ESCAPE_LINK"

for _ in $(seq 1 40); do
  if grep -q "Ghost MCP agent ready" "$AGENT_LOG" 2>/dev/null; then break; fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then cat "$AGENT_LOG" >&2; exit 1; fi
  sleep 0.1
done
mcp_call() {
  local token="$1"
  local id="$2"
  local name="$3"
  local args_json="$4"
  GHOST_MCP_TOKEN="$token" GHOST_MCP_PORT="$PORT" timeout 10 ./target/debug/ghost-mcp <<EOF2
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ghost-mcp-smoke","version":"0.1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":$id,"method":"tools/call","params":{"name":"$name","arguments":$args_json}}
EOF2
}

echo "[1/8] system_info"
OUT="$(mcp_call "$TOKEN" 2 system_info '{}')"
grep -q "hostname" <<<"$OUT"

echo "[2/8] write_file"
OUT="$(mcp_call "$TOKEN" 3 write_file '{"path":"target/ghost_mcp_probe.txt","content":"ghost-mcp-write-ok\\nsecond-line","create_parents":true}')"
grep -q "bytes_written" <<<"$OUT"
test -f "$PROBE"

echo "[3/8] read_file"
OUT="$(mcp_call "$TOKEN" 4 read_file '{"path":"target/ghost_mcp_probe.txt","offset":0,"length":10}')"
grep -q "ghost-mcp-write-ok" <<<"$OUT"

echo "[4/8] run_command"
OUT="$(mcp_call "$TOKEN" 5 run_command '{"command":"printf ghost-mcp-command-ok","cwd":".","timeout_ms":5000}')"
grep -q "ghost-mcp-command-ok" <<<"$OUT"
grep -q "exit_code" <<<"$OUT"
echo "[5/8] absolute path escape rejection"
OUT="$(mcp_call "$TOKEN" 6 read_file '{"path":"/etc/passwd","offset":0,"length":2}')"
grep -q '"isError":true' <<<"$OUT"
grep -q "path escapes configured root" <<<"$OUT"

echo "[6/8] symlink write escape rejection"
OUT="$(mcp_call "$TOKEN" 7 write_file '{"path":"target/ghost_mcp_escape_link/created/probe.txt","content":"must-not-escape","create_parents":true}')"
grep -q '"isError":true' <<<"$OUT"
grep -q "path escapes configured root" <<<"$OUT"
test ! -e "$ESCAPE_DIR/created/probe.txt"
test ! -d "$ESCAPE_DIR/created"

echo "[7/8] gateway-mode SPA generation"
OUT="$(GHOST_MCP_GATEWAY=true GHOST_MCP_STATE_FILE="$SPA_STATE" mcp_call "$TOKEN" 8 system_info '{}')"
grep -q "hostname" <<<"$OUT"
test "$(wc -c < "$SPA_STATE")" -eq 28
SPA_SEQ="$(python3 -c 'import struct,sys; d=open(sys.argv[1],"rb").read(); print(struct.unpack("<Q", d[12:20])[0])' "$SPA_STATE")"
test "$SPA_SEQ" -eq 9999

echo "[8/8] bad token rejection"
OUT="$(mcp_call wrong-token 9 system_info '{}' || true)"
grep -q '"isError":true' <<<"$OUT"
grep -q "authentication failed" <<<"$OUT"

echo "Ghost MCP smoke test: PASS"
