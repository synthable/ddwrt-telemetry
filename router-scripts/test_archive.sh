#!/bin/sh
# Automated tests for router-scripts/archive-logs.sh:
#  1) Failed archive write/verification preserves rotated sources and leaves no corrupt .gz
#  2) Subsequent retry merges new live records with preserved sources and recovers 100% of records
#  3) Verified archival cleans rotated sources and writes valid gzip snapshots

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARCHIVE_SCRIPT="${SCRIPT_DIR}/archive-logs.sh"

TMP_ROOT=$(mktemp -d)
trap 'chmod -R u+w "$TMP_ROOT" 2>/dev/null || true; rm -rf "$TMP_ROOT"' EXIT

LOG_DIR="${TMP_ROOT}/jffs/logs"
RAM_DIR="${TMP_ROOT}/tmp"
SYSLOG_DIR="${TMP_ROOT}/varlog"
mkdir -p "$LOG_DIR" "$RAM_DIR" "$SYSLOG_DIR"

DNS_LOG="${RAM_DIR}/dns.log"
FW_ACCEPT_LOG="${RAM_DIR}/fw-accept.log"
FW_DROP_LOG="${RAM_DIR}/fw-drop.log"

# Create a failing gzip wrapper that emits truncated/corrupt output and exits non-zero
FAIL_GZIP="${TMP_ROOT}/fail-gzip.sh"
cat > "$FAIL_GZIP" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-c" ]; then
  printf 'corrupt-partial-bytes'
  exit 1
fi
exec gzip "$@"
EOF
chmod +x "$FAIL_GZIP"

# Create a gzip wrapper that exits 0 on -c but produces corrupt bytes (fails gzip -t)
CORRUPT_GZIP="${TMP_ROOT}/corrupt-gzip.sh"
cat > "$CORRUPT_GZIP" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-c" ]; then
  printf 'not-a-valid-gzip-stream'
  exit 0
fi
exec gzip "$@"
EOF
chmod +x "$CORRUPT_GZIP"

# Seed initial logs
printf 'Nov 22 03:00:01 dnsmasq[1]: query[A] first.example.com from 192.168.1.10\n' > "$DNS_LOG"
printf 'Nov 22 03:00:02 router kern.info kernel: [1.0] DROP IN=wan OUT= SRC=198.51.100.1 DST=203.0.113.1 LEN=40 TTL=55 PROTO=TCP SPT=12345 DPT=22 SYN\n' > "$FW_DROP_LOG"
printf 'Nov 22 03:00:03 router daemon.info dropbear[1]: test syslog line\n' > "${SYSLOG_DIR}/messages"

# --- Test 1: Failing gzip preserves rotated sources and writes no .log.gz ---
if LOG_DIR="$LOG_DIR" DNS_LOG="$DNS_LOG" FW_ACCEPT_LOG="$FW_ACCEPT_LOG" \
   FW_DROP_LOG="$FW_DROP_LOG" SYSLOG_DIR="$SYSLOG_DIR" JFFS_MOUNT="${TMP_ROOT}/no-jffs" \
   GZIP_BIN="$FAIL_GZIP" SKIP_SIGNALS=1 MAX_JFFS_PCT=100 \
   sh "$ARCHIVE_SCRIPT" 2>/dev/null; then
  echo "FAIL: expected archive-logs.sh to exit non-zero on gzip failure" >&2
  exit 1
fi

if [ ! -s "${DNS_LOG}.rot" ] || [ ! -s "${FW_DROP_LOG}.rot" ]; then
  echo "FAIL: rotated source logs were deleted despite archive failure" >&2
  exit 1
fi

if ls "${LOG_DIR}/"*.log.gz >/dev/null 2>&1; then
  echo "FAIL: partial .log.gz archive left behind after failure" >&2
  exit 1
fi

if ls "${LOG_DIR}/"*.tmp.* >/dev/null 2>&1; then
  echo "FAIL: temporary archive file left behind after failure" >&2
  exit 1
fi

# --- Test 2: Corrupt gzip stream caught by gzip -t preserves sources ---
printf 'Nov 22 03:05:01 dnsmasq[1]: query[A] second.example.com from 192.168.1.10\n' > "$DNS_LOG"
if LOG_DIR="$LOG_DIR" DNS_LOG="$DNS_LOG" FW_ACCEPT_LOG="$FW_ACCEPT_LOG" \
   FW_DROP_LOG="$FW_DROP_LOG" SYSLOG_DIR="$SYSLOG_DIR" JFFS_MOUNT="${TMP_ROOT}/no-jffs" \
   GZIP_BIN="$CORRUPT_GZIP" SKIP_SIGNALS=1 MAX_JFFS_PCT=100 \
   sh "$ARCHIVE_SCRIPT" 2>/dev/null; then
  echo "FAIL: expected archive-logs.sh to reject corrupt gzip stream" >&2
  exit 1
fi

if [ ! -s "${DNS_LOG}.prev" ] || [ ! -s "${DNS_LOG}.rot" ]; then
  echo "FAIL: expected prior .rot to be preserved in .prev and new live log in .rot" >&2
  exit 1
fi

if ls "${LOG_DIR}/"*.log.gz >/dev/null 2>&1; then
  echo "FAIL: corrupt .log.gz archive was moved into LOG_DIR" >&2
  exit 1
fi

# --- Test 3: Successful retry recovers ALL records (first + second + third) and cleans sources ---
printf 'Nov 22 03:10:01 dnsmasq[1]: query[A] third.example.com from 192.168.1.10\n' > "$DNS_LOG"
printf 'Nov 22 03:10:02 router kern.info kernel: [2.0] ACCEPT IN=br0 OUT=wan SRC=192.168.1.10 DST=140.82.113.5 LEN=60 TTL=63 PROTO=TCP SPT=51000 DPT=443 SYN\n' > "$FW_ACCEPT_LOG"

LOG_DIR="$LOG_DIR" DNS_LOG="$DNS_LOG" FW_ACCEPT_LOG="$FW_ACCEPT_LOG" \
FW_DROP_LOG="$FW_DROP_LOG" SYSLOG_DIR="$SYSLOG_DIR" JFFS_MOUNT="${TMP_ROOT}/no-jffs" \
GZIP_BIN=gzip SKIP_SIGNALS=1 MAX_JFFS_PCT=100 \
sh "$ARCHIVE_SCRIPT"

# Verify sources were cleaned up after verified archival
for F in "${DNS_LOG}.prev" "${DNS_LOG}.rot" "${FW_DROP_LOG}.prev" "${FW_DROP_LOG}.rot" "${FW_ACCEPT_LOG}.prev" "${FW_ACCEPT_LOG}.rot"; do
  if [ -e "$F" ]; then
    echo "FAIL: rotated source $F was not cleaned up after verified archival" >&2
    exit 1
  fi
done

# Verify gzip integrity and full record recovery
DNS_ARCHIVE=$(ls "${LOG_DIR}"/dns-*.log.gz | head -n 1)
FW_DROP_ARCHIVE=$(ls "${LOG_DIR}"/fw-drop-*.log.gz | head -n 1)
FW_ACCEPT_ARCHIVE=$(ls "${LOG_DIR}"/fw-accept-*.log.gz | head -n 1)
SYSLOG_ARCHIVE=$(ls "${LOG_DIR}"/syslog-*.log.gz | head -n 1)

gzip -t "$DNS_ARCHIVE" "$FW_DROP_ARCHIVE" "$FW_ACCEPT_ARCHIVE" "$SYSLOG_ARCHIVE"

DNS_CONTENT=$(gzip -dc "$DNS_ARCHIVE")
for DOMAIN in first.example.com second.example.com third.example.com; do
  case "$DNS_CONTENT" in
    *"$DOMAIN"*) ;;
    *)
      echo "FAIL: recovered DNS archive missing record for $DOMAIN" >&2
      exit 1
      ;;
  esac
done

DROP_CONTENT=$(gzip -dc "$FW_DROP_ARCHIVE")
case "$DROP_CONTENT" in
  *"198.51.100.1"*) ;;
  *)
    echo "FAIL: recovered fw-drop archive missing preserved DROP record" >&2
    exit 1
    ;;
esac

ACCEPT_CONTENT=$(gzip -dc "$FW_ACCEPT_ARCHIVE")
case "$ACCEPT_CONTENT" in
  *"140.82.113.5"*) ;;
  *)
    echo "FAIL: recovered fw-accept archive missing ACCEPT record" >&2
    exit 1
    ;;
esac

echo "PASS: archive-logs.sh verified (failure preservation, corruption rejection, retry recovery)"
