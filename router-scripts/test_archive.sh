#!/bin/sh
# Automated tests for router-scripts/archive-logs.sh:
#  1) Failed archive write/verification preserves rotated sources and leaves no corrupt .gz
#  2) Subsequent retry merges new live records with preserved sources and recovers 100% of records
#  3) Verified archival cleans rotated sources and writes valid gzip snapshots
#  4) Hourly ramcheck with existing .prev and failed archive write exits non-zero, preserves BOTH
#     old and new DNS records, recovers both on retry, and bounds RAM usage under repeated failures

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

# --- Test 4: Hourly ramcheck with existing .prev and failed archive write ---
# Must exit non-zero, preserve BOTH old (.prev) and new (live) records, and archive both on retry.
RAM_LOG_DIR="${TMP_ROOT}/jffs/ramcheck-logs"
RAM_DNS="${RAM_DIR}/ram-dns.log"
mkdir -p "$RAM_LOG_DIR"

# 4a) First ramcheck rotates old record into .prev
python3 -c 'print("Nov 22 01:00:01 dnsmasq[1]: query[A] old-ramcheck.example.com from 192.168.1.10\n" + "# " + "A" * 2048)' > "$RAM_DNS"
LOG_DIR="$RAM_LOG_DIR" DNS_LOG="$RAM_DNS" JFFS_MOUNT="${TMP_ROOT}/no-jffs" \
  GZIP_BIN=gzip SKIP_SIGNALS=1 MAX_RAM_KB=1 MAX_JFFS_PCT=100 \
  sh "$ARCHIVE_SCRIPT" ramcheck

[ -s "${RAM_DNS}.prev" ] || { echo "FAIL: first ramcheck did not rotate live DNS log to .prev" >&2; exit 1; }

# 4b) Second ramcheck with new record and failing gzip must fail visibly (exit non-zero) and preserve both
python3 -c 'print("Nov 22 02:00:01 dnsmasq[1]: query[A] new-ramcheck.example.com from 192.168.1.10\n" + "# " + "B" * 2048)' > "$RAM_DNS"
if LOG_DIR="$RAM_LOG_DIR" DNS_LOG="$RAM_DNS" JFFS_MOUNT="${TMP_ROOT}/no-jffs" \
   GZIP_BIN="$FAIL_GZIP" SKIP_SIGNALS=1 MAX_RAM_KB=1 MAX_JFFS_PCT=100 \
   sh "$ARCHIVE_SCRIPT" ramcheck 2>/dev/null; then
  echo "FAIL: expected ramcheck to exit non-zero when archive write fails" >&2
  exit 1
fi

if ls "${RAM_LOG_DIR}/"*.log.gz >/dev/null 2>&1; then
  echo "FAIL: ramcheck published an unverified archive on failure" >&2
  exit 1
fi

# Verify both old and new records remain recoverable in RAM files
COMBINED_PENDING=$(cat "${RAM_DNS}.prev" "${RAM_DNS}.rot" 2>/dev/null)
for REC in old-ramcheck.example.com new-ramcheck.example.com; do
  case "$COMBINED_PENDING" in
    *"$REC"*) ;;
    *)
      echo "FAIL: pending RAM logs lost $REC after failed ramcheck archive write" >&2
      exit 1
      ;;
  esac
done

# 4c) Retry ramcheck with working gzip must archive BOTH old and new records and clean up .prev/.rot
LOG_DIR="$RAM_LOG_DIR" DNS_LOG="$RAM_DNS" JFFS_MOUNT="${TMP_ROOT}/no-jffs" \
  GZIP_BIN=gzip SKIP_SIGNALS=1 MAX_RAM_KB=1 MAX_JFFS_PCT=100 \
  sh "$ARCHIVE_SCRIPT" ramcheck

if [ -e "${RAM_DNS}.prev" ] || [ -e "${RAM_DNS}.rot" ]; then
  echo "FAIL: ramcheck retry did not clean up .prev/.rot after verified archive" >&2
  exit 1
fi

RAM_ARCH=$(ls "${RAM_LOG_DIR}"/dns-*.log.gz | head -n 1)
gzip -t "$RAM_ARCH"
RAM_ARCH_CONTENT=$(gzip -dc "$RAM_ARCH")
for REC in old-ramcheck.example.com new-ramcheck.example.com; do
  case "$RAM_ARCH_CONTENT" in
    *"$REC"*) ;;
    *)
      echo "FAIL: ramcheck retry archive missing $REC" >&2
      exit 1
      ;;
  esac
done

# 4d) Verify line-safe RAM cap, visible loss accounting, and record integrity after recovery
rm -f "${RAM_LOG_DIR}/"*.log.gz "${RAM_DNS}" "${RAM_DNS}.prev" "${RAM_DNS}.rot"
STDERR_LOG="${TMP_ROOT}/ramcheck-overflow.stderr"
: > "$STDERR_LOG"
TOTAL_GENERATED_RECS=0
TOTAL_GENERATED_BYTES=0

for BATCH in 1 2 3 4 5; do
  python3 - "$BATCH" > "$RAM_DNS" <<'PYEOF'
import sys
b = sys.argv[1]
for i in range(1, 16):
    print(f"Nov 22 03:0{b}:{i:02d} dnsmasq[1]: query[A] batch-{b}-rec-{i:02d}.example.com from 192.168.1.10")
PYEOF
  BATCH_LINES=$(wc -l < "$RAM_DNS" | tr -d ' ')
  BATCH_BYTES=$(wc -c < "$RAM_DNS" | tr -d ' ')
  TOTAL_GENERATED_RECS=$((TOTAL_GENERATED_RECS + BATCH_LINES))
  TOTAL_GENERATED_BYTES=$((TOTAL_GENERATED_BYTES + BATCH_BYTES))

  LOG_DIR="$RAM_LOG_DIR" DNS_LOG="$RAM_DNS" JFFS_MOUNT="${TMP_ROOT}/no-jffs" \
    GZIP_BIN="$FAIL_GZIP" SKIP_SIGNALS=1 MAX_RAM_KB=1 MAX_JFFS_PCT=100 \
    sh "$ARCHIVE_SCRIPT" ramcheck 2>>"$STDERR_LOG" || true
done

PREV_BYTES=$(wc -c < "${RAM_DNS}.prev" | tr -d ' ')
if [ "$PREV_BYTES" -gt 2048 ]; then
  echo "FAIL: repeated failed ramcheck runs exceeded 2*MAX_RAM_KB cap ($PREV_BYTES > 2048)" >&2
  exit 1
fi

if ! grep -q "RAM_CAP_OVERFLOW" "$STDERR_LOG"; then
  echo "FAIL: expected RAM_CAP_OVERFLOW warning on stderr when RAM cap trimmed old lines" >&2
  exit 1
fi

# Now recover with working gzip and verify:
#  - In-band RAM_CAP_OVERFLOW header reports exact discarded_records and discarded_bytes
#  - Multiple recent batches survive (not just batch 5)
#  - Every surviving DNS line is a complete, unsplit record
LOG_DIR="$RAM_LOG_DIR" DNS_LOG="$RAM_DNS" JFFS_MOUNT="${TMP_ROOT}/no-jffs" \
  GZIP_BIN=gzip SKIP_SIGNALS=1 MAX_RAM_KB=1 MAX_JFFS_PCT=100 \
  sh "$ARCHIVE_SCRIPT" ramcheck

OVERFLOW_ARCH=$(ls "${RAM_LOG_DIR}"/dns-*.log.gz | head -n 1)
gzip -t "$OVERFLOW_ARCH"

python3 - "$OVERFLOW_ARCH" "$TOTAL_GENERATED_RECS" "$TOTAL_GENERATED_BYTES" <<'PYEOF'
import gzip, re, sys

arch_path = sys.argv[1]
total_recs = int(sys.argv[2])
total_bytes = int(sys.argv[3])

with gzip.open(arch_path, "rt", encoding="utf-8") as fh:
    lines = fh.readlines()

assert lines, "recovered archive is empty"
hdr = lines[0].rstrip("\n")
m = re.match(
    r"^# archive-logs: RAM_CAP_OVERFLOW discarded_records=(\d+) discarded_bytes=(\d+) max_prev_bytes=2048$",
    hdr,
)
assert m, f"missing or malformed overflow header in recovered archive: {hdr!r}"
disc_recs = int(m.group(1))
disc_bytes = int(m.group(2))

surviving = lines[1:]
assert disc_recs > 0 and disc_bytes > 0, f"expected positive discard counts, got {disc_recs}, {disc_bytes}"
assert disc_recs + len(surviving) == total_recs, (
    f"discarded_records ({disc_recs}) + surviving ({len(surviving)}) != total ({total_recs})"
)
surviving_bytes = sum(len(x.encode("utf-8")) for x in surviving)
assert disc_bytes + surviving_bytes == total_bytes, (
    f"discarded_bytes ({disc_bytes}) + surviving_bytes ({surviving_bytes}) != total_bytes ({total_bytes})"
)

line_re = re.compile(
    r"^Nov 22 03:0([1-5]):\d{2} dnsmasq\[1\]: query\[A\] batch-([1-5])-rec-\d{2}\.example\.com from 192\.168\.1\.10\n$"
)
batches_seen = set()
for idx, line in enumerate(surviving, start=2):
    lm = line_re.match(line)
    assert lm, f"corrupted or split record at line {idx}: {line!r}"
    batches_seen.add(int(lm.group(2)))

assert 4 in batches_seen and 5 in batches_seen, f"expected surviving records from batches 4 and 5, got {batches_seen}"
PYEOF

# 4e) Partial-write failure in trim helper must retain original .prev bytes and return error to ramcheck
rm -f "${RAM_LOG_DIR}/"*.log.gz "${RAM_DNS}" "${RAM_DNS}.prev" "${RAM_DNS}.rot"
PARTIAL_AWK="${TMP_ROOT}/partial-awk.sh"
cat > "$PARTIAL_AWK" <<'EOF'
#!/bin/sh
# Intercept the trim helper (invoked with -v out_file=...) to write a partial temp file and exit non-zero
OUT_FILE=""
for ARG in "$@"; do
  case "$ARG" in
    out_file=*) OUT_FILE=${ARG#out_file=} ;;
  esac
done
if [ -n "$OUT_FILE" ]; then
  printf 'partial-corrupt-trim-bytes\n' > "$OUT_FILE"
  exit 1
fi
exec awk "$@"
EOF
chmod +x "$PARTIAL_AWK"

python3 -c '
for i in range(1, 25):
    print(f"Nov 22 04:01:{i:02d} dnsmasq[1]: query[A] orig-prev-{i:02d}.example.com from 192.168.1.10")
' > "${RAM_DNS}.prev"
python3 -c '
for i in range(1, 25):
    print(f"Nov 22 04:02:{i:02d} dnsmasq[1]: query[A] orig-rot-{i:02d}.example.com from 192.168.1.10")
' > "${RAM_DNS}.rot"
python3 -c '
for i in range(1, 25):
    print(f"Nov 22 04:03:{i:02d} dnsmasq[1]: query[A] orig-live-{i:02d}.example.com from 192.168.1.10")
' > "$RAM_DNS"

ORIG_PREV_SNAP="${TMP_ROOT}/orig-prev.snap"
ORIG_ROT_SNAP="${TMP_ROOT}/orig-rot.snap"
cp "${RAM_DNS}.prev" "$ORIG_PREV_SNAP"
cp "${RAM_DNS}.rot" "$ORIG_ROT_SNAP"

if LOG_DIR="$RAM_LOG_DIR" DNS_LOG="$RAM_DNS" JFFS_MOUNT="${TMP_ROOT}/no-jffs" \
   AWK_BIN="$PARTIAL_AWK" GZIP_BIN=gzip SKIP_SIGNALS=1 MAX_RAM_KB=1 MAX_JFFS_PCT=100 \
   sh "$ARCHIVE_SCRIPT" ramcheck 2>/dev/null; then
  echo "FAIL: expected ramcheck to fail when trim helper writes partial file and exits non-zero" >&2
  exit 1
fi

if ! cmp -s "${RAM_DNS}.prev" "$ORIG_PREV_SNAP"; then
  echo "FAIL: failed trim helper corrupted or replaced original dns.log.prev" >&2
  exit 1
fi
if ! cmp -s "${RAM_DNS}.rot" "$ORIG_ROT_SNAP"; then
  echo "FAIL: failed trim helper corrupted or lost original dns.log.rot" >&2
  exit 1
fi
if ls "${RAM_DNS}.prev.cap."* >/dev/null 2>&1; then
  echo "FAIL: temporary trim cap file left behind after failure" >&2
  exit 1
fi

# 4f) Daily recovery must NOT truncate pending firewall logs even when MAX_RAM_KB=1
FW_RECOVERY_DIR="${TMP_ROOT}/jffs/fw-recovery-logs"
mkdir -p "$FW_RECOVERY_DIR"
rm -f "${DNS_LOG}" "${DNS_LOG}.prev" "${DNS_LOG}.rot"
python3 -c 'print("DROP-ROT " + "R" * 5120)' > "${FW_DROP_LOG}.rot"
python3 -c 'print("DROP-LIVE " + "L" * 1024)' > "${FW_DROP_LOG}"
EXPECTED_FW_BYTES=$(( $(wc -c < "${FW_DROP_LOG}.rot" | tr -d ' ') + $(wc -c < "${FW_DROP_LOG}" | tr -d ' ') ))

LOG_DIR="$FW_RECOVERY_DIR" DNS_LOG="$DNS_LOG" FW_ACCEPT_LOG="$FW_ACCEPT_LOG" \
  FW_DROP_LOG="$FW_DROP_LOG" SYSLOG_DIR="$SYSLOG_DIR" JFFS_MOUNT="${TMP_ROOT}/no-jffs" \
  GZIP_BIN=gzip SKIP_SIGNALS=1 MAX_RAM_KB=1 MAX_JFFS_PCT=100 \
  sh "$ARCHIVE_SCRIPT"

FW_REC_ARCH=$(ls "${FW_RECOVERY_DIR}"/fw-drop-*.log.gz | head -n 1)
ACTUAL_FW_BYTES=$(gzip -dc "$FW_REC_ARCH" | wc -c | tr -d ' ')
if [ "$ACTUAL_FW_BYTES" -ne "$EXPECTED_FW_BYTES" ]; then
  echo "FAIL: daily firewall recovery truncated bytes ($ACTUAL_FW_BYTES != $EXPECTED_FW_BYTES)" >&2
  exit 1
fi

echo "PASS: archive-logs.sh verified (failure preservation, corruption rejection, retry recovery, ramcheck failure visibility + recovery + RAM cap)"
