#!/bin/sh
# DD-WRT Firewall Script (Administration -> Commands -> Save Firewall)
# Routes ACCEPT -> NFLOG group 1 (/tmp/fw-accept.log) and DROP/REJECT -> NFLOG group 2 (/tmp/fw-drop.log).
# Completely bypasses dmesg and /var/log/messages so Wi-Fi/SSH/kernel logs stay clean.
#
# Scope: Configures IPv4 iptables chains only (IPv6 ip6tables is not modified).
# Safety: Checks kernel nfnetlink_log + iptables NFLOG support before modifying any chain,
# preserves custom user rules and terminal verdicts without flushing live chains, and
# supports safe removal via: rc_firewall.sh rollback

IPTABLES_BIN="${IPTABLES_BIN:-iptables}"
NF_LOG_PROC="${NF_LOG_PROC:-/proc/net/netfilter/nf_log}"
NFLOGD_BIN="${NFLOGD_BIN:-/jffs/bin/nflogd}"
NFLOGD_LISTEN="${NFLOGD_LISTEN:-192.168.1.1:8789}"
NFLOGD_TZ="${NFLOGD_TZ:-America/Los_Angeles}"
SLEEP_SEC="${SLEEP_SEC:-5}"
SKIP_DAEMON="${SKIP_DAEMON:-0}"

check_nflog_support() {
  if [ ! -r "$NF_LOG_PROC" ] || ! grep -q "nfnetlink_log" "$NF_LOG_PROC" 2>/dev/null; then
    echo "rc_firewall: kernel nfnetlink_log unavailable in ${NF_LOG_PROC}; leaving iptables unchanged" >&2
    return 1
  fi

  PROBE_CHAIN="nflog_probe_$$"
  "$IPTABLES_BIN" -N "$PROBE_CHAIN" 2>/dev/null || {
    echo "rc_firewall: unable to create probe chain ${PROBE_CHAIN}; leaving iptables unchanged" >&2
    return 1
  }

  if "$IPTABLES_BIN" -A "$PROBE_CHAIN" -j NFLOG --nflog-group 2 --nflog-prefix "PROBE " 2>/dev/null; then
    "$IPTABLES_BIN" -F "$PROBE_CHAIN" 2>/dev/null || true
    "$IPTABLES_BIN" -X "$PROBE_CHAIN" 2>/dev/null || true
    return 0
  fi

  "$IPTABLES_BIN" -F "$PROBE_CHAIN" 2>/dev/null || true
  "$IPTABLES_BIN" -X "$PROBE_CHAIN" 2>/dev/null || true
  echo "rc_firewall: iptables -j NFLOG probe failed; leaving iptables unchanged" >&2
  return 1
}

chain_exists() {
  "$IPTABLES_BIN" -L "$1" -n >/dev/null 2>&1
}

# Find the last terminal verdict rule in a chain so NFLOG rules insert immediately
# before it without disturbing custom rules above or ever dropping the verdict.
find_terminal_pos() {
  "$IPTABLES_BIN" -L "$1" -n --line-numbers 2>/dev/null | \
    awk '$1 ~ /^[0-9]+$/ && ($2=="ACCEPT" || $2=="DROP" || $2=="REJECT" || $2=="logdrop") { pos=$1 } END { if (pos != "") print pos }'
}

# Insert an NFLOG rule idempotently before the chain's terminal verdict (never flushes chain).
ensure_nflog_rule() {
  CHAIN="$1"
  shift
  chain_exists "$CHAIN" || return 0
  if "$IPTABLES_BIN" -C "$CHAIN" "$@" 2>/dev/null; then
    return 0
  fi
  TERM_POS=$(find_terminal_pos "$CHAIN")
  if [ -n "$TERM_POS" ]; then
    "$IPTABLES_BIN" -I "$CHAIN" "$TERM_POS" "$@"
  else
    "$IPTABLES_BIN" -A "$CHAIN" "$@"
  fi
}

# Remove all matching telemetry NFLOG rules from a chain without touching custom or verdict rules.
remove_nflog_rule() {
  CHAIN="$1"
  shift
  chain_exists "$CHAIN" || return 0
  while "$IPTABLES_BIN" -C "$CHAIN" "$@" 2>/dev/null; do
    "$IPTABLES_BIN" -D "$CHAIN" "$@" || return 1
  done
  return 0
}

rollback_rules() {
  RC=0
  remove_nflog_rule logaccept -m state --state NEW -j NFLOG --nflog-group 1 --nflog-prefix "ACCEPT " || RC=1
  remove_nflog_rule logdrop -m state --state NEW -j NFLOG --nflog-group 2 --nflog-prefix "DROP " || RC=1
  remove_nflog_rule logdrop -m state --state INVALID -j NFLOG --nflog-group 2 --nflog-prefix "DROP " || RC=1
  remove_nflog_rule logreject -j NFLOG --nflog-group 2 --nflog-prefix "REJECT " || RC=1
  remove_nflog_rule logreject_tcp -j NFLOG --nflog-group 2 --nflog-prefix "REJECT " || RC=1
  remove_nflog_rule portscan -j NFLOG --nflog-group 2 --nflog-prefix "portscan:" || RC=1

  if chain_exists logbrute; then
    N=$("$IPTABLES_BIN" -L logbrute -n --line-numbers 2>/dev/null | awk '$1 ~ /^[0-9]+$/ && $2=="NFLOG" { print $1; exit }')
    if [ -n "$N" ]; then
      "$IPTABLES_BIN" -R logbrute "$N" -j LOG --log-prefix "[DROP BRUTEFORCE] : " || RC=1
    fi
  fi
  return "$RC"
}

if [ "${1:-}" = "rollback" ]; then
  rollback_rules
  exit $?
fi

if [ "$SLEEP_SEC" -gt 0 ] 2>/dev/null; then
  sleep "$SLEEP_SEC"
fi

if [ "$SKIP_DAEMON" != "1" ]; then
  if [ ! -x "$NFLOGD_BIN" ]; then
    exit 0
  fi
fi

# Verify kernel + iptables NFLOG support before starting daemon or touching any live chain.
check_nflog_support || exit 1

if [ "$SKIP_DAEMON" != "1" ]; then
  pidof nflogd >/dev/null 2>&1 || \
    ("$NFLOGD_BIN" -http-listen "$NFLOGD_LISTEN" -tz "$NFLOGD_TZ" </dev/null >/dev/null 2>&1 &)
fi

# Apply NFLOG rules in-place without flushing chains or removing custom/terminal rules.
ensure_nflog_rule logaccept -m state --state NEW -j NFLOG --nflog-group 1 --nflog-prefix "ACCEPT " || exit 1

ensure_nflog_rule logdrop -m state --state NEW -j NFLOG --nflog-group 2 --nflog-prefix "DROP " || exit 1
ensure_nflog_rule logdrop -m state --state INVALID -j NFLOG --nflog-group 2 --nflog-prefix "DROP " || exit 1

ensure_nflog_rule logreject -j NFLOG --nflog-group 2 --nflog-prefix "REJECT " || exit 1
ensure_nflog_rule logreject_tcp -j NFLOG --nflog-group 2 --nflog-prefix "REJECT " || exit 1
ensure_nflog_rule portscan -j NFLOG --nflog-group 2 --nflog-prefix "portscan:" || exit 1

if chain_exists logbrute; then
  if ! "$IPTABLES_BIN" -C logbrute -j NFLOG --nflog-group 2 --nflog-prefix "[DROP BRUTEFORCE] : " 2>/dev/null; then
    N=$("$IPTABLES_BIN" -L logbrute -n --line-numbers 2>/dev/null | awk '$1 ~ /^[0-9]+$/ && $2=="LOG" { print $1; exit }')
    if [ -n "$N" ]; then
      "$IPTABLES_BIN" -R logbrute "$N" -j NFLOG --nflog-group 2 --nflog-prefix "[DROP BRUTEFORCE] : " || exit 1
    fi
  fi
fi
