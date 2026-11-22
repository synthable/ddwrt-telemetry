#!/bin/sh
# Automated tests for router-scripts/rc_firewall.sh using a stateful mock iptables binary:
#  1) Unsupported kernel (nfnetlink_log absent) leaves all chains untouched
#  2) Failed iptables -j NFLOG probe leaves all chains untouched and cleans up probe chain
#  3) Install preserves custom rules — including a filtered custom LOG rule sharing a stock prefix
#     ("DROP ") and custom NFLOG rules — deactivates unfiltered stock LOG rules, is idempotent,
#     and never flushes live chains
#  4) Rollback restores the exact pre-install ordered rules across all chains
#  5) Mid-run interruption preserves custom rules, filters, positions, and terminal verdicts,
#     and subsequent rollback restores the exact pre-install ordered rules across all chains

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FW_SCRIPT="${SCRIPT_DIR}/rc_firewall.sh"

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TMP_ROOT"' EXIT

STATE_FILE="${TMP_ROOT}/iptables-state.json"
BACKUP_FILE="${TMP_ROOT}/rc_firewall.backup"
MOCK_IPT="${TMP_ROOT}/mock-iptables"

cat > "$MOCK_IPT" <<'PYEOF'
#!/usr/bin/env python3
"""Stateful mock iptables supporting -N, -X, -F, -L, -C, -A, -I, -R, -D (spec or line num)."""
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ["MOCK_IPT_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
chains = state["chains"]
meta = state["meta"]

args = sys.argv[1:]
if not args:
    sys.exit(2)

op = args[0]

def save():
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

def parse_rule(tokens):
    target = ""
    i = 0
    while i < len(tokens):
        if tokens[i] == "-j" and i + 1 < len(tokens):
            target = tokens[i + 1]
            i += 2
        else:
            i += 1
    return {"target": target, "spec": tokens}

def format_rule_columns(rule):
    """Render realistic Linux iptables -L -n columns (prot, source, destination, detail)."""
    tokens = rule["spec"]
    target = rule["target"]
    prot = "all"
    src = "0.0.0.0/0"
    dst = "0.0.0.0/0"
    parts = []
    i = 0
    log_prefix = None
    nflog_group = None
    nflog_prefix = None
    while i < len(tokens):
        t = tokens[i]
        if t == "-j" and i + 1 < len(tokens):
            i += 2
        elif t == "-s" and i + 1 < len(tokens):
            src = tokens[i + 1]
            i += 2
        elif t == "-d" and i + 1 < len(tokens):
            dst = tokens[i + 1]
            i += 2
        elif t == "-p" and i + 1 < len(tokens):
            prot = tokens[i + 1]
            i += 2
        elif t == "-m" and i + 3 < len(tokens) and tokens[i + 1] == "state" and tokens[i + 2] == "--state":
            parts.append(f"state {tokens[i + 3]}")
            i += 4
        elif t == "--log-prefix" and i + 1 < len(tokens):
            log_prefix = tokens[i + 1]
            i += 2
        elif t == "--nflog-group" and i + 1 < len(tokens):
            nflog_group = tokens[i + 1]
            i += 2
        elif t == "--nflog-prefix" and i + 1 < len(tokens):
            nflog_prefix = tokens[i + 1]
            i += 2
        else:
            parts.append(t)
            i += 1
    if target == "LOG":
        parts.append("LOG flags 0 level 4")
        if log_prefix is not None:
            parts.append(f'prefix "{log_prefix}"')
    elif target == "NFLOG":
        if nflog_prefix is not None:
            parts.append(f'nflog-prefix  "{nflog_prefix}"')
        if nflog_group is not None:
            parts.append(f"nflog-group {nflog_group}")
    return prot, src, dst, " ".join(parts)

def check_fail_after(chain):
    limit = int(os.environ.get("MOCK_IPT_FAIL_AFTER", "0") or "0")
    if limit > 0 and not chain.startswith("nflog_probe_"):
        meta["live_mutations"] = meta.get("live_mutations", 0) + 1
        save()
        if meta["live_mutations"] >= limit:
            sys.stderr.write("mock-iptables: simulated interruption\n")
            sys.exit(1)

if op == "-N":
    chain = args[1]
    if chain in chains:
        sys.exit(1)
    chains[chain] = []
    save()
    sys.exit(0)

if op == "-X":
    chain = args[1]
    if chain not in chains or chains[chain]:
        sys.exit(1)
    del chains[chain]
    save()
    sys.exit(0)

if op == "-F":
    chain = args[1]
    if chain not in chains:
        sys.exit(1)
    if not chain.startswith("nflog_probe_"):
        meta["flushed_live"].append(chain)
    chains[chain] = []
    save()
    sys.exit(0)

if op == "-L":
    chain = args[1]
    if chain not in chains:
        sys.exit(1)
    line_nums = "--line-numbers" in args
    print(f"Chain {chain} (1 references)")
    if line_nums:
        print("num  target     prot opt source               destination")
    else:
        print("target     prot opt source               destination")
    for idx, rule in enumerate(chains[chain], start=1):
        prot, src, dst, detail = format_rule_columns(rule)
        if line_nums:
            print(f"{idx:<4} {rule['target']:<10} {prot:<4} --  {src:<20} {dst:<20} {detail}")
        else:
            print(f"{rule['target']:<10} {prot:<4} --  {src:<20} {dst:<20} {detail}")
    sys.exit(0)

if op == "-C":
    chain = args[1]
    spec = args[2:]
    if chain not in chains:
        sys.exit(1)
    for r in chains[chain]:
        if r["spec"] == spec:
            sys.exit(0)
    sys.exit(1)

if op == "-A":
    chain = args[1]
    spec = args[2:]
    if chain not in chains:
        sys.exit(1)
    if os.environ.get("MOCK_IPT_REJECT_NFLOG") == "1" and "NFLOG" in spec:
        sys.stderr.write("iptables: No chain/target/match by that name.\n")
        sys.exit(1)
    check_fail_after(chain)
    chains[chain].append(parse_rule(spec))
    save()
    sys.exit(0)

if op == "-I":
    chain = args[1]
    pos = int(args[2])
    spec = args[3:]
    if chain not in chains or pos < 1 or pos > len(chains[chain]) + 1:
        sys.exit(1)
    check_fail_after(chain)
    chains[chain].insert(pos - 1, parse_rule(spec))
    save()
    sys.exit(0)

if op == "-R":
    chain = args[1]
    pos = int(args[2])
    spec = args[3:]
    if chain not in chains or pos < 1 or pos > len(chains[chain]):
        sys.exit(1)
    check_fail_after(chain)
    chains[chain][pos - 1] = parse_rule(spec)
    save()
    sys.exit(0)

if op == "-D":
    chain = args[1]
    if chain not in chains:
        sys.exit(1)
    if len(args) == 3 and args[2].isdigit():
        pos = int(args[2])
        if pos < 1 or pos > len(chains[chain]):
            sys.exit(1)
        check_fail_after(chain)
        del chains[chain][pos - 1]
        save()
        sys.exit(0)
    spec = args[2:]
    for idx, r in enumerate(chains[chain]):
        if r["spec"] == spec:
            check_fail_after(chain)
            del chains[chain][idx]
            save()
            sys.exit(0)
    sys.exit(1)

sys.stderr.write(f"mock-iptables: unsupported args {args}\n")
sys.exit(2)
PYEOF
chmod +x "$MOCK_IPT"

init_state() {
  rm -f "$BACKUP_FILE"
  cat > "$STATE_FILE" <<'JSONEOF'
{
  "meta": {
    "flushed_live": [],
    "live_mutations": 0
  },
  "chains": {
    "logaccept": [
      {"target": "RETURN", "spec": ["-s", "192.168.1.250", "-j", "RETURN"]},
      {"target": "LOG", "spec": ["-p", "tcp", "--dport", "8443", "-j", "LOG", "--log-prefix", "ACCEPT "]},
      {"target": "LOG", "spec": ["-m", "state", "--state", "NEW", "-j", "LOG", "--log-prefix", "ACCEPT "]},
      {"target": "ACCEPT", "spec": ["-j", "ACCEPT"]}
    ],
    "logdrop": [
      {"target": "ACCEPT", "spec": ["-s", "192.168.1.50", "-j", "ACCEPT"]},
      {"target": "LOG", "spec": ["-m", "state", "--state", "NEW", "-j", "LOG", "--log-prefix", "DROP "]},
      {"target": "LOG", "spec": ["-s", "192.168.1.77", "-j", "LOG", "--log-prefix", "DROP "]},
      {"target": "ACCEPT", "spec": ["-s", "192.168.1.60", "-j", "ACCEPT"]},
      {"target": "LOG", "spec": ["-s", "192.168.1.88", "-j", "LOG", "--log-prefix", "CUSTOM_AUDIT "]},
      {"target": "LOG", "spec": ["-m", "state", "--state", "INVALID", "-j", "LOG", "--log-prefix", "DROP "]},
      {"target": "DROP", "spec": ["-j", "DROP"]}
    ],
    "logreject": [
      {"target": "LOG", "spec": ["-j", "LOG", "--log-prefix", "REJECT "]},
      {"target": "REJECT", "spec": ["-j", "REJECT", "--reject-with", "icmp-port-unreachable"]}
    ],
    "logreject_tcp": [
      {"target": "LOG", "spec": ["-j", "LOG", "--log-prefix", "REJECT "]},
      {"target": "REJECT", "spec": ["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]}
    ],
    "portscan": [
      {"target": "RETURN", "spec": ["-s", "192.168.1.99", "-j", "RETURN"]},
      {"target": "LOG", "spec": ["-j", "LOG", "--log-prefix", "portscan:"]},
      {"target": "logdrop", "spec": ["-j", "logdrop"]}
    ],
    "logbrute": [
      {"target": "NFLOG", "spec": ["-s", "10.0.0.0/8", "-j", "NFLOG", "--nflog-group", "99", "--nflog-prefix", "CUSTOM_TAP "]},
      {"target": "LOG", "spec": ["-j", "LOG", "--log-prefix", "[DROP BRUTEFORCE] : "]},
      {"target": "DROP", "spec": ["-j", "DROP"]}
    ]
  }
}
JSONEOF
}

PROC_NO_NFLOG="${TMP_ROOT}/nf_log_disabled"
printf ' 2 NONE\n' > "$PROC_NO_NFLOG"

PROC_OK="${TMP_ROOT}/nf_log_enabled"
printf ' 2 nfnetlink_log (nfnetlink_log)\n' > "$PROC_OK"

# --- Test 1: Missing nfnetlink_log aborts without modifying chains ---
init_state
BEFORE=$(cat "$STATE_FILE")
if IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_NO_NFLOG" \
   BACKUP_FILE="$BACKUP_FILE" SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT" 2>/dev/null; then
  echo "FAIL: expected rc_firewall.sh to fail when nfnetlink_log is absent" >&2
  exit 1
fi
AFTER=$(cat "$STATE_FILE")
[ "$BEFORE" = "$AFTER" ] || { echo "FAIL: chains changed despite missing nfnetlink_log" >&2; exit 1; }

# --- Test 2: Failing NFLOG probe aborts cleanly and removes probe chain ---
init_state
if IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
   BACKUP_FILE="$BACKUP_FILE" MOCK_IPT_REJECT_NFLOG=1 SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT" 2>/dev/null; then
  echo "FAIL: expected rc_firewall.sh to fail when iptables -j NFLOG probe fails" >&2
  exit 1
fi
python3 - "$STATE_FILE" <<'PYEOF'
import json, sys
s = json.loads(open(sys.argv[1]).read())
assert not any(k.startswith("nflog_probe_") for k in s["chains"]), f"probe chain leaked: {list(s['chains'])}"
assert s["meta"]["flushed_live"] == [], f"live chains flushed: {s['meta']['flushed_live']}"
assert len(s["chains"]["logdrop"]) == 7, f"logdrop mutated on failed probe: {s['chains']['logdrop']}"
PYEOF

# --- Test 3: Install + idempotent re-run preserve filtered custom LOG rules sharing stock prefixes ---
init_state
ORIG_CHAINS="${TMP_ROOT}/orig-chains.json"
python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["chains"], indent=2))' "$STATE_FILE" > "$ORIG_CHAINS"

IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
  BACKUP_FILE="$BACKUP_FILE" SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT"
# Re-run to verify idempotency
IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
  BACKUP_FILE="$BACKUP_FILE" SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT"

python3 - "$STATE_FILE" <<'PYEOF'
import json, sys
s = json.loads(open(sys.argv[1]).read())
c = s["chains"]
assert s["meta"]["flushed_live"] == [], f"live chains must never be flushed: {s['meta']['flushed_live']}"

# Unfiltered stock LOG rules must be removed, while filtered custom LOG rules sharing stock prefixes survive in position!
assert c["logaccept"][0]["spec"] == ["-s", "192.168.1.250", "-j", "RETURN"]
assert c["logaccept"][1]["spec"] == ["-p", "tcp", "--dport", "8443", "-j", "LOG", "--log-prefix", "ACCEPT "]
assert c["logaccept"][2]["spec"] == ["-m", "state", "--state", "NEW", "-j", "NFLOG", "--nflog-group", "1", "--nflog-prefix", "ACCEPT "]
assert c["logaccept"][3]["spec"] == ["-j", "ACCEPT"]
assert len(c["logaccept"]) == 4

assert c["logdrop"][0]["spec"] == ["-s", "192.168.1.50", "-j", "ACCEPT"]
assert c["logdrop"][1]["spec"] == ["-s", "192.168.1.77", "-j", "LOG", "--log-prefix", "DROP "]
assert c["logdrop"][2]["spec"] == ["-s", "192.168.1.60", "-j", "ACCEPT"]
assert c["logdrop"][3]["spec"] == ["-s", "192.168.1.88", "-j", "LOG", "--log-prefix", "CUSTOM_AUDIT "]
assert c["logdrop"][4]["spec"] == ["-m", "state", "--state", "NEW", "-j", "NFLOG", "--nflog-group", "2", "--nflog-prefix", "DROP "]
assert c["logdrop"][5]["spec"] == ["-m", "state", "--state", "INVALID", "-j", "NFLOG", "--nflog-group", "2", "--nflog-prefix", "DROP "]
assert c["logdrop"][6]["spec"] == ["-j", "DROP"]
assert len(c["logdrop"]) == 7

# logbrute: custom group-99 NFLOG stays untouched at index 0, telemetry group-2 NFLOG replaces stock LOG at index 1
assert c["logbrute"][0]["spec"] == ["-s", "10.0.0.0/8", "-j", "NFLOG", "--nflog-group", "99", "--nflog-prefix", "CUSTOM_TAP "]
assert c["logbrute"][1]["spec"] == ["-j", "NFLOG", "--nflog-group", "2", "--nflog-prefix", "[DROP BRUTEFORCE] : "]
assert c["logbrute"][2]["spec"] == ["-j", "DROP"]
PYEOF

# --- Test 4: Rollback restores exact ordered rules across ALL chains ---
IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
  BACKUP_FILE="$BACKUP_FILE" SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT" rollback

python3 - "$STATE_FILE" "$ORIG_CHAINS" <<'PYEOF'
import json, sys
after = json.loads(open(sys.argv[1]).read())["chains"]
orig = json.loads(open(sys.argv[2]).read())
assert after == orig, f"Ordered rules after rollback differ from pre-install!\nAfter: {json.dumps(after, indent=2)}\nOrig:  {json.dumps(orig, indent=2)}"
PYEOF

# --- Test 4b: Rebuilt chains without reboot (retaining BACKUP_FILE) reconcile cleanly ---
init_state
IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
  BACKUP_FILE="$BACKUP_FILE" SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT"
# Simulate DD-WRT rebuilding stock chains without rebooting (BACKUP_FILE remains in /tmp)
SAVED_BKP=$(cat "$BACKUP_FILE")
init_state
printf '%s\n' "$SAVED_BKP" > "$BACKUP_FILE"
# Re-run rc_firewall.sh after chain rebuild, then rollback
IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
  BACKUP_FILE="$BACKUP_FILE" SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT"
IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
  BACKUP_FILE="$BACKUP_FILE" SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT" rollback

python3 - "$STATE_FILE" "$ORIG_CHAINS" <<'PYEOF'
import json, sys
after = json.loads(open(sys.argv[1]).read())["chains"]
orig = json.loads(open(sys.argv[2]).read())
assert after == orig, f"Ordered rules after chain rebuild + install + rollback differ from pre-install!\nAfter: {json.dumps(after, indent=2)}\nOrig:  {json.dumps(orig, indent=2)}"
PYEOF

# --- Test 5: Mid-run interruption preserves custom rules & positions, and rollback restores exact pre-install rules ---
init_state
if IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
   BACKUP_FILE="$BACKUP_FILE" MOCK_IPT_FAIL_AFTER=5 SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT" 2>/dev/null; then
  echo "FAIL: expected simulated mid-run interruption to exit non-zero" >&2
  exit 1
fi

python3 - "$STATE_FILE" <<'PYEOF'
import json, sys
s = json.loads(open(sys.argv[1]).read())
c = s["chains"]
assert s["meta"]["flushed_live"] == [], f"live chains flushed before interruption: {s['meta']['flushed_live']}"
# Custom rules, their filters, and their positions must survive at the moment of interruption
assert c["logaccept"][0]["spec"] == ["-s", "192.168.1.250", "-j", "RETURN"]
assert c["logaccept"][1]["spec"] == ["-p", "tcp", "--dport", "8443", "-j", "LOG", "--log-prefix", "ACCEPT "]
assert c["logaccept"][-1]["target"] == "ACCEPT"
assert c["logdrop"][0]["spec"] == ["-s", "192.168.1.50", "-j", "ACCEPT"]
assert c["logdrop"][-1]["target"] == "DROP"
assert any(r["spec"] == ["-s", "192.168.1.77", "-j", "LOG", "--log-prefix", "DROP "] for r in c["logdrop"])
assert any(r["spec"] == ["-s", "192.168.1.60", "-j", "ACCEPT"] for r in c["logdrop"])
assert any(r["spec"] == ["-s", "192.168.1.88", "-j", "LOG", "--log-prefix", "CUSTOM_AUDIT "] for r in c["logdrop"])
assert c["logreject"][-1]["target"] == "REJECT"
assert c["logreject_tcp"][-1]["target"] == "REJECT"
assert c["portscan"][0]["spec"] == ["-s", "192.168.1.99", "-j", "RETURN"]
assert c["portscan"][-1]["target"] == "logdrop"
assert c["logbrute"][0]["spec"] == ["-s", "10.0.0.0/8", "-j", "NFLOG", "--nflog-group", "99", "--nflog-prefix", "CUSTOM_TAP "]
assert c["logbrute"][-1]["target"] == "DROP"
PYEOF

# Now run rollback after the interrupted install and verify exact restoration of all ordered rules
IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
  BACKUP_FILE="$BACKUP_FILE" SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT" rollback

python3 - "$STATE_FILE" "$ORIG_CHAINS" <<'PYEOF'
import json, sys
after = json.loads(open(sys.argv[1]).read())["chains"]
orig = json.loads(open(sys.argv[2]).read())
assert after == orig, f"Ordered rules after interrupted install + rollback differ from pre-install!\nAfter: {json.dumps(after, indent=2)}\nOrig:  {json.dumps(orig, indent=2)}"
PYEOF

echo "PASS: rc_firewall.sh verified (NFLOG precheck, filtered custom LOG sharing stock prefix preserved, exact ordered rollback after normal and interrupted install)"
