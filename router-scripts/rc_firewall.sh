#!/bin/sh
# DD-WRT Firewall Script (Administration -> Commands -> Save Firewall)
# Routes ACCEPT -> NFLOG group 1 (/tmp/fw-accept.log) and DROP/REJECT -> NFLOG group 2 (/tmp/fw-drop.log).
# Completely bypasses dmesg and /var/log/messages so Wi-Fi/SSH/kernel logs stay clean.
#
# Scope: Configures IPv4 iptables chains only (IPv6 ip6tables is not modified).
# Safety: Checks kernel nfnetlink_log + iptables NFLOG support before modifying any chain,
# preserves custom user rules (including filtered custom LOG rules sharing a stock prefix)
# and terminal verdicts without flushing live chains, snapshots all unfiltered stock
# DD-WRT LOG rules (including duplicate instances and exact positions) to BACKUP_FILE
# before deleting them, and supports exact restoration via:
#   rc_firewall.sh rollback

IPTABLES_BIN="${IPTABLES_BIN:-iptables}"
NF_LOG_PROC="${NF_LOG_PROC:-/proc/net/netfilter/nf_log}"
NFLOGD_BIN="${NFLOGD_BIN:-/jffs/bin/nflogd}"
NFLOGD_LISTEN="${NFLOGD_LISTEN:-192.168.1.1:8789}"
NFLOGD_TZ="${NFLOGD_TZ:-America/Los_Angeles}"
BACKUP_FILE="${BACKUP_FILE:-/tmp/ddwrt-telemetry-rc_firewall.backup}"
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

# Find the last unconditional terminal verdict rule in a chain so telemetry rules insert
# immediately before it without mistaking filtered custom rules for the terminal verdict.
find_terminal_pos() {
  "$IPTABLES_BIN" -L "$1" -n --line-numbers 2>/dev/null | \
    awk '
      $1 ~ /^[0-9]+$/ && ($2=="ACCEPT" || $2=="DROP" || $2=="REJECT" || $2=="logdrop") && $5=="0.0.0.0/0" && $6=="0.0.0.0/0" {
        pos=$1
      }
      END { if (pos != "") print pos }
    '
}

# List all unfiltered stock DD-WRT LOG rules in CHAIN matching the exact log prefix.
# Outputs one "<line_num>|<state_kind>" line per occurrence (state_kind: NEW, INVALID, or NONE).
# Never matches a custom LOG rule that specifies source/destination IPs, interfaces,
# protocols, ports, or any match criteria other than stock -m state --state NEW|INVALID.
list_stock_log_rules() {
  CHAIN="$1"
  PFX="$2"
  "$IPTABLES_BIN" -L "$CHAIN" -n --line-numbers 2>/dev/null | \
    awk -v pfx="$PFX" '
      $1 ~ /^[0-9]+$/ && $2 == "LOG" && $3 == "all" && $4 == "--" && $5 == "0.0.0.0/0" && $6 == "0.0.0.0/0" {
        if (index($0, "prefix \"" pfx "\"") == 0) next
        rest = $0
        sub(/^[[:space:]]*[0-9]+[[:space:]]+LOG[[:space:]]+all[[:space:]]+--[[:space:]]+0\.0\.0\.0\/0[[:space:]]+0\.0\.0\.0\/0[[:space:]]*/, "", rest)
        idx = index(rest, "LOG flags")
        if (idx == 0) next
        pre = substr(rest, 1, idx - 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", pre)
        if (pre == "") {
          print $1 "|NONE"
        } else if (pre == "state NEW" || pre == "-m state --state NEW") {
          print $1 "|NEW"
        } else if (pre == "state INVALID" || pre == "-m state --state INVALID") {
          print $1 "|INVALID"
        }
      }
    '
}

find_stock_log_rule() {
  list_stock_log_rules "$1" "$2" | head -n 1
}

# Locate the exact telemetry NFLOG rule in CHAIN matching both group and prefix.
find_nflog_line() {
  CHAIN="$1"
  GRP="$2"
  PFX="$3"
  "$IPTABLES_BIN" -L "$CHAIN" -n --line-numbers 2>/dev/null | \
    awk -v grp="$GRP" -v pfx="$PFX" '
      $1 ~ /^[0-9]+$/ && $2 == "NFLOG" && $3 == "all" && $5 == "0.0.0.0/0" && $6 == "0.0.0.0/0" {
        has_grp = ($0 ~ ("(nflog-group|--nflog-group)[[:space:]]+" grp "([^0-9]|$)"))
        has_pfx = (index($0, "\"" pfx "\"") > 0)
        if (has_grp && has_pfx) {
          print $1
          exit
        }
      }
    '
}

# Insert a rule idempotently before the chain's terminal verdict (never flushes chain).
ensure_rule_before_terminal() {
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

count_saved_stock_logs_for_chain() {
  CHAIN_ARG="$1"
  [ -f "$BACKUP_FILE" ] || { echo 0; return 0; }
  awk -F'|' -v c="$CHAIN_ARG" '$1 == c { n++ } END { print n + 0 }' "$BACKUP_FILE"
}

chain_rule_count() {
  "$IPTABLES_BIN" -L "$1" -n --line-numbers 2>/dev/null | \
    awk '$1 ~ /^[0-9]+$/ { n = $1 } END { print n + 0 }'
}

# Atomically snapshot all unfiltered stock LOG rules in CHAIN (preserving duplicate instances
# and exact 1-based positions) into BACKUP_FILE BEFORE modifying CHAIN.
# If BACKUP_FILE is unwritable, returns non-zero before any rule is inserted or deleted.
snapshot_stock_logs_for_chain() {
  CHAIN="$1"
  GRP="$2"
  NFLOG_PFX="$3"
  STOCK_PFX="$4"
  chain_exists "$CHAIN" || return 0

  HAS_NFLOG=$(find_nflog_line "$CHAIN" "$GRP" "$NFLOG_PFX")
  SAVED_COUNT=$(count_saved_stock_logs_for_chain "$CHAIN")

  # If the chain already has our telemetry NFLOG rule and BACKUP_FILE already holds
  # saved stock rules for this chain, keep the existing baseline snapshot (ordinary rerun
  # or resume after mid-chain interruption), but verify BACKUP_FILE remains writable.
  if [ -n "$HAS_NFLOG" ] && [ "$SAVED_COUNT" -gt 0 ]; then
    ( : >> "$BACKUP_FILE" ) 2>/dev/null || {
      echo "rc_firewall: backup file ${BACKUP_FILE} is not writable" >&2
      return 1
    }
    return 0
  fi

  RULES=$(list_stock_log_rules "$CHAIN" "$STOCK_PFX")
  TMP_BKP="${BACKUP_FILE}.tmp.$$"
  rm -f "$TMP_BKP"

  if [ -f "$BACKUP_FILE" ]; then
    awk -F'|' -v c="$CHAIN" '$1 != c { print $0 }' "$BACKUP_FILE" > "$TMP_BKP" 2>/dev/null || {
      rm -f "$TMP_BKP"
      echo "rc_firewall: unable to stage backup file ${TMP_BKP}" >&2
      return 1
    }
  else
    ( : > "$TMP_BKP" ) 2>/dev/null || {
      echo "rc_firewall: unable to create backup file ${TMP_BKP}" >&2
      return 1
    }
  fi

  if [ -n "$RULES" ]; then
    printf '%s\n' "$RULES" | while IFS='|' read -r POS KIND; do
      [ -n "$POS" ] || continue
      printf '%s|%s|%s|%s\n' "$CHAIN" "$POS" "$KIND" "$STOCK_PFX"
    done >> "$TMP_BKP" 2>/dev/null || {
      rm -f "$TMP_BKP"
      echo "rc_firewall: failed writing stock LOG backup to ${TMP_BKP}" >&2
      return 1
    }
  fi

  mv -f "$TMP_BKP" "$BACKUP_FILE" 2>/dev/null || {
    rm -f "$TMP_BKP"
    echo "rc_firewall: unable to commit backup file ${BACKUP_FILE}" >&2
    return 1
  }
  return 0
}

# Remove unfiltered stock DD-WRT LOG rules matching the exact prefix after they have been
# safely snapshotted in BACKUP_FILE. Custom LOG rules are never matched or removed.
remove_stock_log_rules() {
  CHAIN="$1"
  PFX="$2"
  chain_exists "$CHAIN" || return 0
  while true; do
    FOUND=$(find_stock_log_rule "$CHAIN" "$PFX")
    [ -n "$FOUND" ] || break
    N=${FOUND%%|*}
    "$IPTABLES_BIN" -D "$CHAIN" "$N" || return 1
  done
  return 0
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

insert_rule_at_pos() {
  CHAIN="$1"
  POS="$2"
  shift 2
  MAX_POS=$(( $(chain_rule_count "$CHAIN") + 1 ))
  if [ "$POS" -lt 1 ] 2>/dev/null; then
    POS=1
  elif [ "$POS" -gt "$MAX_POS" ] 2>/dev/null; then
    POS="$MAX_POS"
  fi
  "$IPTABLES_BIN" -I "$CHAIN" "$POS" "$@"
}

restore_saved_stock_logs() {
  [ -f "$BACKUP_FILE" ] || return 0
  RC_RESTORE=0

  # For each chain that has saved entries in BACKUP_FILE, remove any remaining partial
  # unfiltered stock LOG rules (e.g., if an earlier install was interrupted mid-deletion)
  # before re-inserting the complete saved set at their exact original 1-based positions.
  for CHAIN_PAIR in "logaccept:ACCEPT " "logdrop:DROP " "logreject:REJECT " "logreject_tcp:REJECT " "portscan:portscan:"; do
    C_NAME=${CHAIN_PAIR%%:*}
    C_PFX=${CHAIN_PAIR#*:}
    if [ "$(count_saved_stock_logs_for_chain "$C_NAME")" -gt 0 ] && chain_exists "$C_NAME"; then
      remove_stock_log_rules "$C_NAME" "$C_PFX" || RC_RESTORE=1
    fi
  done

  while IFS='|' read -r CHAIN ORIG_POS KIND PFX; do
    [ -n "$CHAIN" ] || continue
    chain_exists "$CHAIN" || continue
    case "$KIND" in
      NEW)
        insert_rule_at_pos "$CHAIN" "$ORIG_POS" -m state --state NEW -j LOG --log-prefix "$PFX" || RC_RESTORE=1
        ;;
      INVALID)
        insert_rule_at_pos "$CHAIN" "$ORIG_POS" -m state --state INVALID -j LOG --log-prefix "$PFX" || RC_RESTORE=1
        ;;
      NONE)
        insert_rule_at_pos "$CHAIN" "$ORIG_POS" -j LOG --log-prefix "$PFX" || RC_RESTORE=1
        ;;
    esac
  done < "$BACKUP_FILE"
  return "$RC_RESTORE"
}

rollback_rules() {
  RC=0
  remove_nflog_rule logaccept -m state --state NEW -j NFLOG --nflog-group 1 --nflog-prefix "ACCEPT " || RC=1
  remove_nflog_rule logdrop -m state --state NEW -j NFLOG --nflog-group 2 --nflog-prefix "DROP " || RC=1
  remove_nflog_rule logdrop -m state --state INVALID -j NFLOG --nflog-group 2 --nflog-prefix "DROP " || RC=1
  remove_nflog_rule logreject -j NFLOG --nflog-group 2 --nflog-prefix "REJECT " || RC=1
  remove_nflog_rule logreject_tcp -j NFLOG --nflog-group 2 --nflog-prefix "REJECT " || RC=1
  remove_nflog_rule portscan -j NFLOG --nflog-group 2 --nflog-prefix "portscan:" || RC=1

  restore_saved_stock_logs || RC=1

  if chain_exists logbrute; then
    N=$(find_nflog_line logbrute 2 "[DROP BRUTEFORCE] : ")
    if [ -n "$N" ]; then
      "$IPTABLES_BIN" -R logbrute "$N" -j LOG --log-prefix "[DROP BRUTEFORCE] : " || RC=1
    fi
  fi

  [ "$RC" -eq 0 ] && rm -f "$BACKUP_FILE"
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

# Snapshot each chain's unfiltered stock LOG rules to BACKUP_FILE BEFORE modifying the chain,
# insert telemetry NFLOG rules before the terminal verdict, and then remove the stock LOG rules.
snapshot_stock_logs_for_chain logaccept 1 "ACCEPT " "ACCEPT " || exit 1
ensure_rule_before_terminal logaccept -m state --state NEW -j NFLOG --nflog-group 1 --nflog-prefix "ACCEPT " || exit 1
remove_stock_log_rules logaccept "ACCEPT " || exit 1

snapshot_stock_logs_for_chain logdrop 2 "DROP " "DROP " || exit 1
ensure_rule_before_terminal logdrop -m state --state NEW -j NFLOG --nflog-group 2 --nflog-prefix "DROP " || exit 1
ensure_rule_before_terminal logdrop -m state --state INVALID -j NFLOG --nflog-group 2 --nflog-prefix "DROP " || exit 1
remove_stock_log_rules logdrop "DROP " || exit 1

snapshot_stock_logs_for_chain logreject 2 "REJECT " "REJECT " || exit 1
ensure_rule_before_terminal logreject -j NFLOG --nflog-group 2 --nflog-prefix "REJECT " || exit 1
remove_stock_log_rules logreject "REJECT " || exit 1

snapshot_stock_logs_for_chain logreject_tcp 2 "REJECT " "REJECT " || exit 1
ensure_rule_before_terminal logreject_tcp -j NFLOG --nflog-group 2 --nflog-prefix "REJECT " || exit 1
remove_stock_log_rules logreject_tcp "REJECT " || exit 1

snapshot_stock_logs_for_chain portscan 2 "portscan:" "portscan:" || exit 1
ensure_rule_before_terminal portscan -j NFLOG --nflog-group 2 --nflog-prefix "portscan:" || exit 1
remove_stock_log_rules portscan "portscan:" || exit 1

if chain_exists logbrute; then
  if [ -z "$(find_nflog_line logbrute 2 "[DROP BRUTEFORCE] : ")" ]; then
    FOUND=$(find_stock_log_rule logbrute "[DROP BRUTEFORCE] : ")
    N=${FOUND%%|*}
    if [ -n "$N" ]; then
      "$IPTABLES_BIN" -R logbrute "$N" -j NFLOG --nflog-group 2 --nflog-prefix "[DROP BRUTEFORCE] : " || exit 1
    fi
  fi
fi
