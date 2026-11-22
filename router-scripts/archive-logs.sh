#!/bin/sh
# Rotate RAM DNS & NFLOG firewall logs and archive compressed snapshots to /jffs/logs.
# Minimizes internal NAND flash wear (1 write/day + clean shutdown) while guarding RAM and /jffs.
# Install on router at: /jffs/scripts/archive-logs.sh (chmod 755)

LOG_DIR="/jffs/logs"
DNS_LOG="/tmp/dns.log"
FW_ACCEPT_LOG="/tmp/fw-accept.log"
FW_DROP_LOG="/tmp/fw-drop.log"
MAX_KEEP=14          # keep last 14 daily archives per log type
MAX_JFFS_PCT=70      # prune oldest archives if /jffs reaches 70%
MAX_RAM_KB=16384     # 16 MB RAM cap for live /tmp/dns.log

reopen_dnsmasq() {
  PID=$(pidof dnsmasq)
  [ -n "$PID" ] && kill -USR2 $PID 2>/dev/null
}

reopen_nflogd() {
  PID=$(pidof nflogd)
  [ -n "$PID" ] && kill -USR1 $PID 2>/dev/null
}

ensure_nflogd() {
  [ -x /jffs/bin/nflogd ] || return 0
  pidof nflogd >/dev/null 2>&1 || (/jffs/bin/nflogd </dev/null >/dev/null 2>&1 &)
}

case "$1" in
  ramcheck)
    ensure_nflogd
    if [ -f "$DNS_LOG" ]; then
      KB=$(du -k "$DNS_LOG" 2>/dev/null | awk '{print $1}')
      if [ -n "$KB" ] && [ "$KB" -ge "$MAX_RAM_KB" ]; then
        mv "$DNS_LOG" "${DNS_LOG}.prev" 2>/dev/null
        reopen_dnsmasq
      fi
    fi
    exit 0
    ;;
esac

mkdir -p "$LOG_DIR"
TS=$(date +%Y%m%d-%H%M%S)

# 1. Rotate & compress DNS query log
if [ -s "$DNS_LOG" ] || [ -s "${DNS_LOG}.prev" ]; then
  if [ -s "$DNS_LOG" ]; then
    mv "$DNS_LOG" "${DNS_LOG}.rot" 2>/dev/null
    reopen_dnsmasq
  fi
  cat "${DNS_LOG}.prev" "${DNS_LOG}.rot" 2>/dev/null | gzip -c > "${LOG_DIR}/dns-${TS}.log.gz"
  rm -f "${DNS_LOG}.prev" "${DNS_LOG}.rot"
fi

# 2. Rotate & compress NFLOG firewall logs (ACCEPT + DROP)
NEED_NFLOG_REOPEN=0
if [ -s "$FW_ACCEPT_LOG" ] || [ -s "${FW_ACCEPT_LOG}.prev" ]; then
  if [ -s "$FW_ACCEPT_LOG" ]; then
    mv "$FW_ACCEPT_LOG" "${FW_ACCEPT_LOG}.rot" 2>/dev/null
    NEED_NFLOG_REOPEN=1
  fi
fi
if [ -s "$FW_DROP_LOG" ] || [ -s "${FW_DROP_LOG}.prev" ]; then
  if [ -s "$FW_DROP_LOG" ]; then
    mv "$FW_DROP_LOG" "${FW_DROP_LOG}.rot" 2>/dev/null
    NEED_NFLOG_REOPEN=1
  fi
fi
[ "$NEED_NFLOG_REOPEN" -eq 1 ] && reopen_nflogd

if [ -s "${FW_ACCEPT_LOG}.prev" ] || [ -s "${FW_ACCEPT_LOG}.rot" ]; then
  cat "${FW_ACCEPT_LOG}.prev" "${FW_ACCEPT_LOG}.rot" 2>/dev/null | gzip -c > "${LOG_DIR}/fw-accept-${TS}.log.gz"
  rm -f "${FW_ACCEPT_LOG}.prev" "${FW_ACCEPT_LOG}.rot"
fi
if [ -s "${FW_DROP_LOG}.prev" ] || [ -s "${FW_DROP_LOG}.rot" ]; then
  cat "${FW_DROP_LOG}.prev" "${FW_DROP_LOG}.rot" 2>/dev/null | gzip -c > "${LOG_DIR}/fw-drop-${TS}.log.gz"
  rm -f "${FW_DROP_LOG}.prev" "${FW_DROP_LOG}.rot"
fi

# 3. Snapshot current syslog (Wi-Fi/hostapd, dropbear, kernel notices)
if [ -s /var/log/messages.0 ] || [ -s /var/log/messages ]; then
  cat /var/log/messages.0 /var/log/messages 2>/dev/null | gzip -c > "${LOG_DIR}/syslog-${TS}.log.gz"
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
while true; do
  PCT=$(df -k /jffs | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
  [ -z "$PCT" ] || [ "$PCT" -lt "$MAX_JFFS_PCT" ] && break
  OLDEST=$(ls -1tr "${LOG_DIR}/"*.log.gz 2>/dev/null | head -n 1)
  [ -z "$OLDEST" ] && break
  rm -f "$OLDEST"
done
