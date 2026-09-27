#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Ghost MCP gateway e2e requires root for XDP/eBPF + cgroupv2." >&2
  exit 1
fi

for cmd in cargo openssl timeout; do
  command -v "$cmd" >/dev/null || { echo "ERROR: missing required command: $cmd" >&2; exit 1; }
done

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
  if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
  rm -rf /sys/fs/bpf/ghostpty 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "[1/7] build userspace + eBPF"
cargo build -p server -p ghost-mcp
cargo xtask build-ebpf

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
grep -qs cgroup2 /proc/mounts || mount -t cgroup2 none /sys/fs/cgroup
rm -rf /sys/fs/bpf/ghostpty
echo "[2/7] create DID=1 development client certificate"
openssl req -new -newkey rsa:2048 -nodes -keyout "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "/CN=1" >/dev/null 2>&1
openssl x509 -req -in "$CLIENT_CSR" -CA certs/ca.crt -CAkey certs/ca.key -set_serial 9001 -days 1 -out "$CLIENT_CERT" >/dev/null 2>&1

echo "[3/7] start full Ghost gateway"
GATEWAY_TOKEN="$TOKEN" ./target/debug/server \
  --port "$PORT" \
  --iface lo \
  --ca certs/ca.crt \
  --cert certs/server.crt \
  --key certs/server.key \
  --mcp-root "$ROOT" \
  --mcp-enable-command \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  if grep -q "QUIC Server listening" "$SERVER_LOG"; then break; fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then cat "$SERVER_LOG" >&2; exit 1; fi
  sleep 0.1
done

mcp_call() {
  local id="$1"
  local name="$2"
  local args_json="$3"
  GHOST_MCP_TOKEN="$TOKEN" GHOST_MCP_PORT="$PORT" GHOST_MCP_GATEWAY=true GHOST_MCP_TARGET=1 \
  GHOST_MCP_CERT="$CLIENT_CERT" GHOST_MCP_KEY="$CLIENT_KEY" GHOST_MCP_STATE_FILE="$STATE_FILE" \
  timeout 10 ./target/debug/ghost-mcp <<EOF2
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ghost-gateway-e2e","version":"0.1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":$id,"method":"tools/call","params":{"name":"$name","arguments":$args_json}}
EOF2
}
echo "[4/7] SPA -> XDP -> mTLS -> MCP system_info"
OUT="$(mcp_call 2 system_info '{}')"
grep -q "hostname" <<<"$OUT"

echo "[5/7] root-scoped write/read"
OUT="$(mcp_call 3 write_file '{"path":"target/gateway_mcp_probe.txt","content":"gateway-write-ok","create_parents":true}')"
grep -q "bytes_written" <<<"$OUT"
OUT="$(mcp_call 4 read_file '{"path":"target/gateway_mcp_probe.txt","offset":0,"length":5}')"
grep -q "gateway-write-ok" <<<"$OUT"
rm -f target/gateway_mcp_probe.txt

echo "[6/7] audited command execution"
OUT="$(mcp_call 5 run_command '{"command":"printf gateway-command-ok","cwd":".","timeout_ms":5000}')"
grep -q "gateway-command-ok" <<<"$OUT"

echo "[7/7] path escape rejection"
OUT="$(mcp_call 6 read_file '{"path":"/etc/passwd","offset":0,"length":2}')"
grep -q '"isError":true' <<<"$OUT"
grep -q "path escapes configured root" <<<"$OUT"

echo "Ghost MCP full gateway e2e: PASS"
