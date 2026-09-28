#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PLUGIN_DIR="$ROOT/ghost-plugin"
TARGET="$ROOT/target"
AGENT_ADDR="${GHOST_SHELL_ADDR:-127.0.0.1:19085}"
PLUGIN_ADDR="${GHOST_PLUGIN_HOST:-127.0.0.1}"
PLUGIN_PORT="${GHOST_PLUGIN_PORT:-8787}"
CF_LOG="$TARGET/ghost-plugin-cloudflared.log"
PLUGIN_LOG="$TARGET/ghost-plugin-server.log"
AGENT_LOG="$TARGET/ghost-plugin-agent.log"
URL_FILE="$TARGET/ghost-plugin-url"

mkdir -p "$TARGET"
umask 077

secret_file() {
  local file="$1"
  local bytes="$2"
  if [[ ! -s "$file" ]]; then
    openssl rand -hex "$bytes" > "$file"
  fi
  chmod 600 "$file"
}

secret_file "$TARGET/.ghost-shell-token" 32
secret_file "$TARGET/.ghost-plugin-password" 24
secret_file "$TARGET/.ghost-plugin-signing-key" 32

echo "[ghost-plugin] building Ghost shell binaries"
cargo build -p ghost-mcp --bin ghost-shell-proxy -p ghost-mcp-agent

if [[ ! -d "$PLUGIN_DIR/node_modules/@modelcontextprotocol" ]]; then
  echo "[ghost-plugin] installing MCP server dependencies"
  npm install --prefix "$PLUGIN_DIR" --no-audit --no-fund
fi

cleanup() {
  for pid in "${PLUGIN_PID:-}" "${CF_PID:-}" "${AGENT_PID:-}"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT INT TERM

echo "[ghost-plugin] starting local Ghost agent"
GHOST_MCP_TOKEN="$(cat "$TARGET/.ghost-shell-token")"   "$TARGET/debug/ghost-mcp-agent"   --listen "$AGENT_ADDR"   >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!

for _ in $(seq 1 60); do
  if grep -q "Ghost shell agent ready" "$AGENT_LOG" 2>/dev/null; then break; fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    cat "$AGENT_LOG" >&2
    exit 1
  fi
  sleep 0.1
done

: > "$CF_LOG"
echo "[ghost-plugin] starting HTTPS ingress"
cloudflared tunnel --no-autoupdate --url "http://$PLUGIN_ADDR:$PLUGIN_PORT"   >"$CF_LOG" 2>&1 &
CF_PID=$!

PUBLIC_ORIGIN=""
for _ in $(seq 1 120); do
  PUBLIC_ORIGIN="$(grep -Eo 'https://[-a-z0-9]+\.trycloudflare\.com' "$CF_LOG" | head -1 || true)"
  if [[ -n "$PUBLIC_ORIGIN" ]]; then break; fi
  if ! kill -0 "$CF_PID" 2>/dev/null; then
    cat "$CF_LOG" >&2
    exit 1
  fi
  sleep 0.25
done

if [[ -z "$PUBLIC_ORIGIN" ]]; then
  echo "ERROR: cloudflared did not provide a public URL" >&2
  cat "$CF_LOG" >&2
  exit 1
fi

printf '%s/mcp\n' "$PUBLIC_ORIGIN" > "$URL_FILE"
chmod 600 "$URL_FILE"

echo "[ghost-plugin] starting Streamable HTTP MCP"
GHOST_PLUGIN_REPO="$ROOT" GHOST_PLUGIN_PUBLIC_ORIGIN="$PUBLIC_ORIGIN" GHOST_PLUGIN_HOST="$PLUGIN_ADDR" GHOST_PLUGIN_PORT="$PLUGIN_PORT" GHOST_SHELL_ADDR="$AGENT_ADDR" node "$PLUGIN_DIR/server.mjs"   >"$PLUGIN_LOG" 2>&1 &
PLUGIN_PID=$!

for _ in $(seq 1 80); do
  if curl -fsS "http://$PLUGIN_ADDR:$PLUGIN_PORT/healthz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$PLUGIN_PID" 2>/dev/null; then
    cat "$PLUGIN_LOG" >&2
    exit 1
  fi
  sleep 0.1
done

echo
echo "Ghost Shell plugin is ready."
echo "MCP URL: $PUBLIC_ORIGIN/mcp"
echo "OAuth owner password file: $TARGET/.ghost-plugin-password"
echo "Runtime is independent of Desktop Commander once this supervisor is running."
echo

wait -n "$PLUGIN_PID" "$CF_PID" "$AGENT_PID"
