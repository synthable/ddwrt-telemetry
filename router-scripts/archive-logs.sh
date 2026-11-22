#!/bin/sh
# Rotate RAM DNS & NFLOG firewall logs and archive compressed snapshots to /jffs/logs.
# Minimizes internal NAND flash wear (1 write/day + clean shutdown) while guarding RAM and /jffs.
# Install on router at: /jffs/scripts/archive-logs.sh (chmod 755)

LOG_DIR="${LOG_DIR:-/jffs/logs}"
DNS_LOG="${DNS_LOG:-/tmp/dns.log}"
FW_ACCEPT_LOG="${FW_ACCEPT_LOG:-/tmp/fw-accept.log}"
FW_DROP_LOG="${FW_DROP_LOG:-/tmp/fw-drop.log}"
SYSLOG_DIR="${SYSLOG_DIR:-/var/log}"
JFFS_MOUNT="${JFFS_MOUNT:-/jffs}"
NFLOGD_BIN="${NFLOGD_BIN:-/jffs/bin/nflogd}"
GZIP_BIN="${GZIP_BIN:-gzip}"
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

case "$1" in
  ramcheck)
    ensure_nflogd
    if [ -f "$DNS_LOG" ]; then
      KB=$(du -k "$DNS_LOG" 2>/dev/null | awk '{print $1}')
      if [ -n "$KB" ] && [ "$KB" -ge "$MAX_RAM_KB" ]; then
        if [ -s "${DNS_LOG}.prev" ]; then
          if mv "$DNS_LOG" "${DNS_LOG}.ramtmp" 2>/dev/null; then
            reopen_dnsmasq
            if cat "${DNS_LOG}.ramtmp" >> "${DNS_LOG}.prev"; then
              rm -f "${DNS_LOG}.ramtmp"
            fi
          fi
        else
          mv "$DNS_LOG" "${DNS_LOG}.prev" 2>/dev/null && reopen_dnsmasq
        fi
      fi
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

# 4. Prune beyond MAX_KEEP per log type
for PREFIX in dns fw-drop fw-accept syslog; do
  COUNT=$(ls -1 "${LOG_DIR}/${PREFIX}-"*.log.gz 2>/dev/null | wc -l)
  if [ "$COUNT" -gt "$MAX_KEEP" ]; then
    DEL=$((COUNT - MAX_KEEP))
    ls -1 "${LOG_DIR}/${PREFIX}-"*.log.gz 2>/dev/null | head -n "$DEL" | while read -r F; do
      rm -f "$F"
    done
  fi
done

# 5. Hard /jffs capacity guard
if [ -d "$JFFS_MOUNT" ]; then
  while true; do
    PCT=$(df -k "$JFFS_MOUNT" 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
    [ -z "$PCT" ] || [ "$PCT" -lt "$MAX_JFFS_PCT" ] && break
    OLDEST=$(ls -1tr "${LOG_DIR}/"*.log.gz 2>/dev/null | head -n 1)
    [ -z "$OLDEST" ] && break
    rm -f "$OLDEST"
  done
fi

exit "$FAILED"
