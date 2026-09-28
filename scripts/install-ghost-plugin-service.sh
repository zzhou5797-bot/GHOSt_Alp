#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="$HOME/.config/systemd/user"
mkdir -p "$UNIT_DIR"

sed "s|%h/work/GHOSt_Alp|$ROOT|g" "$ROOT/ghost-plugin/ghost-plugin.service"   > "$UNIT_DIR/ghost-plugin.service"

systemctl --user daemon-reload
systemctl --user enable --now ghost-plugin.service

echo "Ghost plugin service enabled."
echo "Status: systemctl --user status ghost-plugin.service"
echo "URL:    cat $ROOT/target/ghost-plugin-url"
echo "OAuth password: cat $ROOT/target/.ghost-plugin-password"
