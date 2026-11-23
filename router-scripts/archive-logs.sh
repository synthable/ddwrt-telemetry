#!/bin/sh
# Rotate RAM DNS & NFLOG firewall logs and archive compressed snapshots to /jffs/logs.
# Minimizes internal NAND flash wear (1 write/day + clean shutdown) while guarding RAM and /jffs.
# Install on router at: /jffs/scripts/archive-logs.sh (chmod 755)
#
# Overflow Policy (hourly ramcheck):
# - Up to 2 * MAX_RAM_KB of unarchived rotated DNS logs are held losslessly in
#   ${DNS_LOG}.prev + ${DNS_LOG}.rot across transient archive write failures.
# - If repeated archive failures cause ${DNS_LOG}.prev to exceed 2 * MAX_RAM_KB when
#   merging a prior unarchived .rot, the oldest complete log lines are evicted on
#   newline boundaries (never splitting a record), and the exact cumulative counts are
#   reported on stderr and recorded in an in-band header line at the top of ${DNS_LOG}.prev
#   (# archive-logs: RAM_CAP_OVERFLOW discarded_records=<N> discarded_bytes=<B> max_prev_bytes=<M>)
#   so the recovered archive explicitly records how much data was discarded.

LOG_DIR="${LOG_DIR:-/jffs/logs}"
DNS_LOG="${DNS_LOG:-/tmp/dns.log}"
FW_ACCEPT_LOG="${FW_ACCEPT_LOG:-/tmp/fw-accept.log}"
FW_DROP_LOG="${FW_DROP_LOG:-/tmp/fw-drop.log}"
SYSLOG_DIR="${SYSLOG_DIR:-/var/log}"
JFFS_MOUNT="${JFFS_MOUNT:-/jffs}"
NFLOGD_BIN="${NFLOGD_BIN:-/jffs/bin/nflogd}"
GZIP_BIN="${GZIP_BIN:-gzip}"
AWK_BIN="${AWK_BIN:-awk}"
TMP_STATE_DIR="${TMPDIR:-/tmp}"
MAX_KEEP="${MAX_KEEP:-14}"          # keep last 14 daily archives per log type
MAX_JFFS_PCT="${MAX_JFFS_PCT:-70}"  # prune oldest archives if /jffs reaches 70%
MAX_RAM_KB="${MAX_RAM_KB:-16384}"   # 16 MB RAM cap for live /tmp/dns.log
SKIP_SIGNALS="${SKIP_SIGNALS:-0}"

reopen_dnsmasq() {
  [ "$SKIP_SIGNALS" = "1" ] && return 0
  PID=$(pidof dnsmasq 2>/dev/null)
  [ -n "$PID" ] && kill -USR2 $PID 2>/dev/null
}

reopen_nflogd() {
  [ "$SKIP_SIGNALS" = "1" ] && return 0
  PID=$(pidof nflogd 2>/dev/null)
  [ -n "$PID" ] && kill -USR1 $PID 2>/dev/null
}

ensure_nflogd() {
  [ "$SKIP_SIGNALS" = "1" ] && return 0
  [ -x "$NFLOGD_BIN" ] || return 0
  pidof nflogd >/dev/null 2>&1 || ("$NFLOGD_BIN" </dev/null >/dev/null 2>&1 &)
}

# Preserve any leftover .rot from a prior failed archive run before rotating a fresh live log.
rotate_live_log() {
  SRC="$1"
  [ -s "$SRC" ] || return 1
  if [ -s "${SRC}.rot" ]; then
    if cat "${SRC}.rot" >> "${SRC}.prev"; then
      rm -f "${SRC}.rot"
    else
      echo "archive-logs: failed to merge prior ${SRC}.rot into ${SRC}.prev; skipping rotation" >&2
      return 1
    fi
  fi
  mv "$SRC" "${SRC}.rot"
}

# Trim ${DNS_LOG}.prev on whole-line boundaries when repeated ramcheck archive failures
# exceed 2 * MAX_RAM_KB, recording exact cumulative discarded_records and discarded_bytes
# both on stderr and in an in-band header line preserved in the recovered archive.
# Requires a zero exit status and valid numeric loss counts before promoting the temp file.
trim_dns_prev_lines() {
  PREV_FILE="${DNS_LOG}.prev"
  [ -s "$PREV_FILE" ] || return 0
  MAX_PREV_BYTES=$((MAX_RAM_KB * 2048))
  CUR_BYTES=$(wc -c < "$PREV_FILE" 2>/dev/null | tr -d ' ')
  [ -n "$CUR_BYTES" ] && [ "$CUR_BYTES" -gt "$MAX_PREV_BYTES" ] || return 0

  CAP_TMP="${PREV_FILE}.cap.$$"
  rm -f "$CAP_TMP"
  if ! OVERFLOW_INFO=$("$AWK_BIN" -v max_bytes="$MAX_PREV_BYTES" -v out_file="$CAP_TMP" '
    NR == 1 && /^# archive-logs: RAM_CAP_OVERFLOW / {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^discarded_records=/) {
          split($i, a, "=")
          prev_recs = a[2] + 0
        } else if ($i ~ /^discarded_bytes=/) {
          split($i, a, "=")
          prev_bytes = a[2] + 0
        }
      }
      next
    }
    {
      count++
      lines[count] = $0
      lens[count] = length($0) + 1
      total_len += lens[count]
    }
    END {
      budget = max_bytes - 128
      if (budget < 1) budget = 1
      drop = 0
      while (drop < count && total_len > budget) {
        drop++
        total_len -= lens[drop]
        dropped_bytes += lens[drop]
      }
      tot_recs = prev_recs + drop
      tot_bytes = prev_bytes + dropped_bytes
      hdr = sprintf("# archive-logs: RAM_CAP_OVERFLOW discarded_records=%d discarded_bytes=%d max_prev_bytes=%d", tot_recs, tot_bytes, max_bytes)
      while (drop < count && (length(hdr) + 1 + total_len) > max_bytes) {
        drop++
        total_len -= lens[drop]
        tot_recs++
        tot_bytes += lens[drop]
        hdr = sprintf("# archive-logs: RAM_CAP_OVERFLOW discarded_records=%d discarded_bytes=%d max_prev_bytes=%d", tot_recs, tot_bytes, max_bytes)
      }
      print hdr > out_file
      for (j = drop + 1; j <= count; j++) {
        print lines[j] > out_file
      }
      printf "%d|%d\n", tot_recs, tot_bytes
    }
  ' "$PREV_FILE"); then
    rm -f "$CAP_TMP"
    echo "archive-logs: trim helper failed for ${PREV_FILE}; retaining original log" >&2
    return 1
  fi

  case "$OVERFLOW_INFO" in
    *"|"*) ;;
    *)
      rm -f "$CAP_TMP"
      echo "archive-logs: missing loss counts from trim helper for ${PREV_FILE}; retaining original log" >&2
      return 1
      ;;
  esac

  DISC_RECS=${OVERFLOW_INFO%%|*}
  DISC_BYTES=${OVERFLOW_INFO#*|}
  if [ -z "$DISC_RECS" ] || [ -z "$DISC_BYTES" ]; then
    rm -f "$CAP_TMP"
    echo "archive-logs: blank loss counts from trim helper for ${PREV_FILE}; retaining original log" >&2
    return 1
  fi
  case "${DISC_RECS}${DISC_BYTES}" in
    *[!0-9]*)
      rm -f "$CAP_TMP"
      echo "archive-logs: invalid loss counts (${OVERFLOW_INFO}) for ${PREV_FILE}; retaining original log" >&2
      return 1
      ;;
  esac

  if [ ! -s "$CAP_TMP" ]; then
    rm -f "$CAP_TMP"
    echo "archive-logs: empty trim output for ${PREV_FILE}; retaining original log" >&2
    return 1
  fi

  if mv -f "$CAP_TMP" "$PREV_FILE"; then
    echo "archive-logs: RAM_CAP_OVERFLOW on ${PREV_FILE}: discarded_records=${DISC_RECS} discarded_bytes=${DISC_BYTES} max_prev_bytes=${MAX_PREV_BYTES}" >&2
    return 0
  fi

  rm -f "$CAP_TMP"
  echo "archive-logs: unable to replace ${PREV_FILE} with trimmed log; retaining original log" >&2
  return 1
}

# Rotate live DNS log during hourly ramcheck: if a prior ramcheck archive failed and left
# .rot pending, merge .rot into .prev and bound .prev on whole-line boundaries at 2 * MAX_RAM_KB
# so repeated ramcheck failures cannot exhaust /tmp RAM. If trimming fails, retain the original
# .prev and .rot files untouched and return non-zero. Daily rotation uses rotate_live_log (uncapped).
rotate_dns_for_ramcheck() {
  [ -s "$DNS_LOG" ] || return 1
  if [ -s "${DNS_LOG}.rot" ]; then
    PREV_BAK="${DNS_LOG}.prev.bak.$$"
    rm -f "$PREV_BAK"
    if [ -s "${DNS_LOG}.prev" ]; then
      cp -p "${DNS_LOG}.prev" "$PREV_BAK" 2>/dev/null || cp "${DNS_LOG}.prev" "$PREV_BAK" || return 1
    fi
    if cat "${DNS_LOG}.rot" >> "${DNS_LOG}.prev"; then
      if trim_dns_prev_lines; then
        rm -f "$PREV_BAK" "${DNS_LOG}.rot"
      else
        if [ -f "$PREV_BAK" ]; then
          mv -f "$PREV_BAK" "${DNS_LOG}.prev"
        else
          rm -f "${DNS_LOG}.prev"
        fi
        return 1
      fi
    else
      if [ -f "$PREV_BAK" ]; then
        mv -f "$PREV_BAK" "${DNS_LOG}.prev"
      else
        rm -f "${DNS_LOG}.prev"
      fi
      echo "archive-logs: failed to merge prior ${DNS_LOG}.rot into ${DNS_LOG}.prev; skipping rotation" >&2
      return 1
    fi
  fi
  mv "$DNS_LOG" "${DNS_LOG}.rot"
}

# Compress non-empty source files to a temp archive, verify gzip integrity, and atomically move into place.
archive_files() {
  DEST="$1"
  shift

  HAVE_SRC=0
  for S in "$@"; do
    if [ -s "$S" ]; then
      HAVE_SRC=1
      break
    fi
  done
  [ "$HAVE_SRC" -eq 1 ] || return 0

  TMP="${DEST}.tmp.$$"
  CAT_ERR_FILE="${TMP_STATE_DIR}/archive-logs-cat-err.$$"
  rm -f "$TMP" "$CAT_ERR_FILE"

  (
    for S in "$@"; do
      if [ -s "$S" ]; then
        cat "$S" || { echo 1 > "$CAT_ERR_FILE"; exit 1; }
      fi
    done
  ) | "$GZIP_BIN" -c > "$TMP"
  GZ_RC=$?

  CAT_ERR=0
  [ -f "$CAT_ERR_FILE" ] && CAT_ERR=1
  rm -f "$CAT_ERR_FILE"

  if [ "$GZ_RC" -eq 0 ] && [ "$CAT_ERR" -eq 0 ] && [ -s "$TMP" ] && "$GZIP_BIN" -t "$TMP" >/dev/null 2>&1; then
    if mv -f "$TMP" "$DEST"; then
      return 0
    fi
  fi

  rm -f "$TMP"
  echo "archive-logs: failed to write or verify ${DEST}; preserving source logs" >&2
  return 1
}

prune_archives() {
  # Prune beyond MAX_KEEP per log type
  for PREFIX in dns fw-drop fw-accept syslog; do
    COUNT=$(ls -1 "${LOG_DIR}/${PREFIX}-"*.log.gz 2>/dev/null | wc -l)
    if [ "$COUNT" -gt "$MAX_KEEP" ]; then
      DEL=$((COUNT - MAX_KEEP))
      ls -1 "${LOG_DIR}/${PREFIX}-"*.log.gz 2>/dev/null | head -n "$DEL" | while read -r F; do
        rm -f "$F"
      done
    fi
  done

  # Hard /jffs capacity guard
  if [ -d "$JFFS_MOUNT" ]; then
    while true; do
      PCT=$(df -k "$JFFS_MOUNT" 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
      [ -z "$PCT" ] || [ "$PCT" -lt "$MAX_JFFS_PCT" ] && break
      OLDEST=$(ls -1tr "${LOG_DIR}/"*.log.gz 2>/dev/null | head -n 1)
      [ -z "$OLDEST" ] && break
      rm -f "$OLDEST"
    done
  fi
}

case "$1" in
  ramcheck)
    ensure_nflogd
    NEED_ROTATE=0
    if [ -f "$DNS_LOG" ]; then
      KB=$(du -k "$DNS_LOG" 2>/dev/null | awk '{print $1}')
      if [ -n "$KB" ] && [ "$KB" -ge "$MAX_RAM_KB" ]; then
        NEED_ROTATE=1
      fi
    fi

    if [ "$NEED_ROTATE" -eq 1 ]; then
      if [ ! -s "${DNS_LOG}.prev" ] && [ ! -s "${DNS_LOG}.rot" ]; then
        # First threshold crossing: rotate live DNS log to .prev in RAM
        mv -f "$DNS_LOG" "${DNS_LOG}.prev" 2>/dev/null && reopen_dnsmasq
        exit 0
      fi
      # .prev or .rot already exists: rotate live log to .rot (preserving any prior .rot into .prev)
      # so neither old nor new records are lost if archival fails.
      if rotate_dns_for_ramcheck; then
        reopen_dnsmasq
      else
        exit 1
      fi
    fi

    # Flush pending .prev + .rot to a verified archive whenever a second rotation occurred
    # or a previous ramcheck archive write failed and left .rot pending.
    if [ -s "${DNS_LOG}.rot" ] || ( [ "$NEED_ROTATE" -eq 1 ] && [ -s "${DNS_LOG}.prev" ] ); then
      mkdir -p "$LOG_DIR" 2>/dev/null || {
        echo "archive-logs: ramcheck unable to create ${LOG_DIR}; preserving rotated logs" >&2
        exit 1
      }
      TS=$(date +%Y%m%d-%H%M%S)
      if archive_files "${LOG_DIR}/dns-${TS}.log.gz" "${DNS_LOG}.prev" "${DNS_LOG}.rot"; then
        rm -f "${DNS_LOG}.prev" "${DNS_LOG}.rot"
        prune_archives
        exit 0
      fi
      exit 1
    fi
    exit 0
    ;;
esac

mkdir -p "$LOG_DIR" || {
  echo "archive-logs: unable to create ${LOG_DIR}" >&2
  exit 1
}
TS=$(date +%Y%m%d-%H%M%S)
FAILED=0

# 1. Rotate & compress DNS query log
if [ -s "$DNS_LOG" ] || [ -s "${DNS_LOG}.prev" ] || [ -s "${DNS_LOG}.rot" ]; then
  if rotate_live_log "$DNS_LOG"; then
    reopen_dnsmasq
  fi
  if [ -s "${DNS_LOG}.prev" ] || [ -s "${DNS_LOG}.rot" ]; then
    if archive_files "${LOG_DIR}/dns-${TS}.log.gz" "${DNS_LOG}.prev" "${DNS_LOG}.rot"; then
      rm -f "${DNS_LOG}.prev" "${DNS_LOG}.rot"
    else
      FAILED=1
    fi
  fi
fi

# 2. Rotate & compress NFLOG firewall logs (ACCEPT + DROP)
NEED_NFLOG_REOPEN=0
if [ -s "$FW_ACCEPT_LOG" ]; then
  if rotate_live_log "$FW_ACCEPT_LOG"; then
    NEED_NFLOG_REOPEN=1
  fi
fi
if [ -s "$FW_DROP_LOG" ]; then
  if rotate_live_log "$FW_DROP_LOG"; then
    NEED_NFLOG_REOPEN=1
  fi
fi
[ "$NEED_NFLOG_REOPEN" -eq 1 ] && reopen_nflogd

if [ -s "${FW_ACCEPT_LOG}.prev" ] || [ -s "${FW_ACCEPT_LOG}.rot" ]; then
  if archive_files "${LOG_DIR}/fw-accept-${TS}.log.gz" "${FW_ACCEPT_LOG}.prev" "${FW_ACCEPT_LOG}.rot"; then
    rm -f "${FW_ACCEPT_LOG}.prev" "${FW_ACCEPT_LOG}.rot"
  else
    FAILED=1
  fi
fi
if [ -s "${FW_DROP_LOG}.prev" ] || [ -s "${FW_DROP_LOG}.rot" ]; then
  if archive_files "${LOG_DIR}/fw-drop-${TS}.log.gz" "${FW_DROP_LOG}.prev" "${FW_DROP_LOG}.rot"; then
    rm -f "${FW_DROP_LOG}.prev" "${FW_DROP_LOG}.rot"
  else
    FAILED=1
  fi
fi

# 3. Snapshot current syslog (Wi-Fi/hostapd, dropbear, kernel notices)
if [ -s "${SYSLOG_DIR}/messages.0" ] || [ -s "${SYSLOG_DIR}/messages" ]; then
  if ! archive_files "${LOG_DIR}/syslog-${TS}.log.gz" "${SYSLOG_DIR}/messages.0" "${SYSLOG_DIR}/messages"; then
    FAILED=1
  fi
fi

# 4. Prune beyond MAX_KEEP and enforce /jffs capacity guard
prune_archives

exit "$FAILED"
