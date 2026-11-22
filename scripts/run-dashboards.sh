#!/usr/bin/env bash
# Launch both DNS (:8787) and Firewall (:8788) dashboards together.
# Usage:
#   ./scripts/run-dashboards.sh --demo
#   ./scripts/run-dashboards.sh --router-name "WRT1900ACv2"

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNS_PORT="${DNS_PORT:-8787}"
FW_PORT="${FW_PORT:-8788}"

cleanup() {
  echo ""
  echo "[stop] Shutting down both dashboards..."
  kill "${DNS_PID:-}" "${FW_PID:-}" 2>/dev/null || true
  wait "${DNS_PID:-}" "${FW_PID:-}" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "[start] DNS Dashboard      -> http://127.0.0.1:${DNS_PORT}"
echo "[start] Firewall Dashboard -> http://127.0.0.1:${FW_PORT}"
echo "[info]  Press Ctrl+C to stop both."

python3 "${ROOT_DIR}/dns-dashboard/server.py" --port "${DNS_PORT}" "$@" &
DNS_PID=$!

python3 "${ROOT_DIR}/firewall-dashboard/server.py" --port "${FW_PORT}" "$@" &
FW_PID=$!

wait
