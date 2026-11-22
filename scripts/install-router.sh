#!/usr/bin/env bash
# Preflight & safe installer for deploying nflogd + archive-logs.sh to a DD-WRT router.
# Does NOT overwrite your existing rc_startup / rc_firewall NVRAM hooks automatically;
# prints the exact snippets to merge once deployment succeeds.
#
# Usage:
#   ./scripts/install-router.sh --router root@192.168.1.1 --ssh-port 2222 --ssh-key ~/.ssh/id_ed25519_router
#   ./scripts/install-router.sh --router root@192.168.1.1 --dry-run

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROUTER="${ROUTER:-root@192.168.1.1}"
SSH_PORT="${SSH_PORT:-22}"
SSH_KEY="${SSH_KEY:-}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.ddwrt/nflogd.token}"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --router)     ROUTER="$2"; shift 2 ;;
    --ssh-port)   SSH_PORT="$2"; shift 2 ;;
    --ssh-key)    SSH_KEY="$2"; shift 2 ;;
    --token-file) TOKEN_FILE="$2"; shift 2 ;;
    --dry-run)    DRY_RUN=1; shift ;;
    -h|--help)
      sed -n '2,10p' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

SSH_CMD=(ssh -p "${SSH_PORT}" -o BatchMode=yes -o ConnectTimeout=10)
[[ -n "${SSH_KEY}" ]] && SSH_CMD+=(-i "${SSH_KEY}")
SSH_CMD+=("${ROUTER}")

echo "[1/5] Checking router compatibility (${ROUTER}:${SSH_PORT})..."
INFO="$("${SSH_CMD[@]}" 'echo "ARCH=$(uname -m)"; grep -q nfnetlink_log /proc/net/netfilter/nf_log 2>/dev/null && echo "NFLOG=yes" || echo "NFLOG=no"; df -k /jffs 2>/dev/null | awk "NR==2{print \"JFFS_AVAIL_KB=\"\$4}"')"
echo "${INFO}"

ARCH="$(echo "${INFO}" | awk -F= '/^ARCH=/{print $2}')"
NFLOG="$(echo "${INFO}" | awk -F= '/^NFLOG=/{print $2}')"
JFFS_KB="$(echo "${INFO}" | awk -F= '/^JFFS_AVAIL_KB=/{print $2}')"

if [[ "${NFLOG}" != "yes" ]]; then
  echo "ERROR: nfnetlink_log not detected in /proc/net/netfilter/nf_log on router." >&2
  exit 1
fi
if [[ -z "${JFFS_KB}" || "${JFFS_KB}" -lt 8192 ]]; then
  echo "ERROR: /jffs needs at least 8 MB free (detected: ${JFFS_KB:-0} KB)." >&2
  exit 1
fi

case "${ARCH}" in
  armv7*) TARGET="armv7" ;;
  aarch64|arm64) TARGET="arm64" ;;
  mips*) TARGET="mipsle" ;;
  *) echo "ERROR: Unsupported router architecture: ${ARCH}" >&2; exit 1 ;;
esac

BIN_PATH="${ROOT_DIR}/nflogd/dist/nflogd-${TARGET}"
echo "[2/5] Selected binary target: ${TARGET} (${BIN_PATH})"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "[dry-run] Preflight passed. Skipping build and upload."
  exit 0
fi

if [[ ! -x "${BIN_PATH}" ]]; then
  echo "[3/5] Building nflogd-${TARGET} via make build-${TARGET}..."
  make -C "${ROOT_DIR}" "build-${TARGET}"
else
  echo "[3/5] Using existing binary: ${BIN_PATH}"
fi

echo "[4/5] Ensuring local Bearer token at ${TOKEN_FILE}..."
mkdir -p "$(dirname "${TOKEN_FILE}")"
chmod 700 "$(dirname "${TOKEN_FILE}")"
if [[ ! -f "${TOKEN_FILE}" ]]; then
  python3 -c "import os, secrets, sys; p=sys.argv[1]; open(p,'w').write(secrets.token_hex(32)+'\n'); os.chmod(p, 0o600)" "${TOKEN_FILE}"
  echo "      Generated new 256-bit Bearer token."
fi

echo "[5/5] Uploading token, nflogd binary, and archive-logs.sh to /jffs..."
"${SSH_CMD[@]}" 'mkdir -p /jffs/bin /jffs/etc /jffs/scripts /jffs/logs && chmod 700 /jffs/etc'
"${SSH_CMD[@]}" 'cat > /jffs/etc/nflogd.token && chmod 600 /jffs/etc/nflogd.token' < "${TOKEN_FILE}"
"${SSH_CMD[@]}" 'kill $(pidof nflogd) 2>/dev/null || true; sleep 1; cat > /jffs/bin/nflogd && chmod 755 /jffs/bin/nflogd' < "${BIN_PATH}"
"${SSH_CMD[@]}" 'cat > /jffs/scripts/archive-logs.sh && chmod 755 /jffs/scripts/archive-logs.sh' < "${ROOT_DIR}/router-scripts/archive-logs.sh"

echo ""
echo "Deployment complete. Next, merge the DD-WRT hooks from router-scripts/:"
echo "  - Startup:  router-scripts/rc_startup.sh"
echo "  - Firewall: router-scripts/rc_firewall.sh"
echo "  - Shutdown: /jffs/scripts/archive-logs.sh >/dev/null 2>&1"
echo "  - Dnsmasq:  router-scripts/dnsmasq_options.conf"
echo "  - Cron:     router-scripts/cron_jobs.txt"
echo ""
echo "Then start both local dashboards with:"
echo "  make run"
