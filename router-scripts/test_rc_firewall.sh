#!/bin/sh
# Automated tests for router-scripts/rc_firewall.sh using a stateful mock iptables binary:
#  1) Unsupported kernel (nfnetlink_log absent) leaves all chains untouched
#  2) Failed iptables -j NFLOG probe leaves all chains untouched and cleans up probe chain
#  3) Install preserves custom rules and terminal verdicts, is idempotent, and never flushes live chains
#  4) Mid-run interruption preserves custom rules and all terminal verdicts
#  5) Rollback removes only telemetry NFLOG rules while preserving custom rules and terminal verdicts

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FW_SCRIPT="${SCRIPT_DIR}/rc_firewall.sh"

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TMP_ROOT"' EXIT

STATE_FILE="${TMP_ROOT}/iptables-state.json"
MOCK_IPT="${TMP_ROOT}/mock-iptables"

cat > "$MOCK_IPT" <<'PYEOF'
#!/usr/bin/env python3
"""Stateful mock iptables supporting -N, -X, -F, -L, -C, -A, -I, -R, -D."""
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
    extra = []
    i = 0
    while i < len(tokens):
        if tokens[i] == "-j" and i + 1 < len(tokens):
            target = tokens[i + 1]
            i += 2
        else:
            extra.append(tokens[i])
            i += 1
    return {"target": target, "spec": tokens}

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
        spec_str = " ".join(rule["spec"])
        if line_nums:
            print(f"{idx:<4} {rule['target']:<10} all  --  0.0.0.0/0            0.0.0.0/0            {spec_str}")
        else:
            print(f"{rule['target']:<10} all  --  0.0.0.0/0            0.0.0.0/0            {spec_str}")
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
    spec = args[2:]
    if chain not in chains:
        sys.exit(1)
    for idx, r in enumerate(chains[chain]):
        if r["spec"] == spec:
            del chains[chain][idx]
            save()
            sys.exit(0)
    sys.exit(1)

sys.stderr.write(f"mock-iptables: unsupported args {args}\n")
sys.exit(2)
PYEOF
chmod +x "$MOCK_IPT"

init_state() {
  cat > "$STATE_FILE" <<'JSONEOF'
{
  "meta": {
    "flushed_live": [],
    "live_mutations": 0
  },
  "chains": {
    "logaccept": [
      {"target": "RETURN", "spec": ["-s", "192.168.1.250", "-j", "RETURN"]},
      {"target": "ACCEPT", "spec": ["-j", "ACCEPT"]}
    ],
    "logdrop": [
      {"target": "ACCEPT", "spec": ["-s", "192.168.1.50", "-j", "ACCEPT"]},
      {"target": "DROP", "spec": ["-j", "DROP"]}
    ],
    "logreject": [
      {"target": "REJECT", "spec": ["-j", "REJECT", "--reject-with", "icmp-port-unreachable"]}
    ],
    "logreject_tcp": [
      {"target": "REJECT", "spec": ["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]}
    ],
    "portscan": [
      {"target": "RETURN", "spec": ["-s", "192.168.1.99", "-j", "RETURN"]},
      {"target": "logdrop", "spec": ["-j", "logdrop"]}
    ],
    "logbrute": [
      {"target": "LOG", "spec": ["-j", "LOG", "--log-prefix", "[DROP BRUTEFORCE] : "]},
      {"target": "DROP", "spec": ["-j", "DROP"]}
    ]
  }
}
JSONEOF
}

PROC_NO_NFLOG="${TMP_ROOT}/nf_log_disabled"
printf ' 2 NONE (nfnetlink_log)\n' > "$PROC_NO_NFLOG"
printf ' 2 NONE\n' > "$PROC_NO_NFLOG"

PROC_OK="${TMP_ROOT}/nf_log_enabled"
printf ' 2 nfnetlink_log (nfnetlink_log)\n' > "$PROC_OK"

# --- Test 1: Missing nfnetlink_log aborts without modifying chains ---
init_state
BEFORE=$(cat "$STATE_FILE")
if IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_NO_NFLOG" \
   SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT" 2>/dev/null; then
  echo "FAIL: expected rc_firewall.sh to fail when nfnetlink_log is absent" >&2
  exit 1
fi
AFTER=$(cat "$STATE_FILE")
[ "$BEFORE" = "$AFTER" ] || { echo "FAIL: chains changed despite missing nfnetlink_log" >&2; exit 1; }

# --- Test 2: Failing NFLOG probe aborts cleanly and removes probe chain ---
init_state
if IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
   MOCK_IPT_REJECT_NFLOG=1 SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT" 2>/dev/null; then
  echo "FAIL: expected rc_firewall.sh to fail when iptables -j NFLOG probe fails" >&2
  exit 1
fi
python3 - "$STATE_FILE" <<'PYEOF'
import json, sys
s = json.loads(open(sys.argv[1]).read())
assert not any(k.startswith("nflog_probe_") for k in s["chains"]), f"probe chain leaked: {list(s['chains'])}"
assert s["meta"]["flushed_live"] == [], f"live chains flushed: {s['meta']['flushed_live']}"
assert len(s["chains"]["logdrop"]) == 2, f"logdrop mutated on failed probe: {s['chains']['logdrop']}"
PYEOF

# --- Test 3: Install + idempotent re-run preserve custom rules and terminal verdicts ---
init_state
IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
  SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT"
# Re-run to verify idempotency
IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
  SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT"

python3 - "$STATE_FILE" <<'PYEOF'
import json, sys
s = json.loads(open(sys.argv[1]).read())
c = s["chains"]
assert s["meta"]["flushed_live"] == [], f"live chains must never be flushed: {s['meta']['flushed_live']}"

# Custom rule stays first, NFLOG inserted before terminal verdict, no duplicates
assert c["logaccept"][0]["spec"] == ["-s", "192.168.1.250", "-j", "RETURN"]
assert c["logaccept"][-1]["target"] == "ACCEPT"
assert sum(1 for r in c["logaccept"] if r["target"] == "NFLOG") == 1

assert c["logdrop"][0]["spec"] == ["-s", "192.168.1.50", "-j", "ACCEPT"]
assert c["logdrop"][-1]["target"] == "DROP"
assert sum(1 for r in c["logdrop"] if r["target"] == "NFLOG") == 2

assert c["portscan"][0]["spec"] == ["-s", "192.168.1.99", "-j", "RETURN"]
assert c["portscan"][-1]["target"] == "logdrop"
assert sum(1 for r in c["portscan"] if r["target"] == "NFLOG") == 1

assert c["logbrute"][0]["target"] == "NFLOG"
assert c["logbrute"][-1]["target"] == "DROP"
PYEOF

# --- Test 4: Rollback removes only NFLOG rules and preserves custom rules & verdicts ---
IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
  SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT" rollback

python3 - "$STATE_FILE" <<'PYEOF'
import json, sys
s = json.loads(open(sys.argv[1]).read())
c = s["chains"]
for name, rules in c.items():
    assert not any(r["target"] == "NFLOG" for r in rules), f"NFLOG left behind in {name}: {rules}"
assert c["logaccept"][0]["spec"] == ["-s", "192.168.1.250", "-j", "RETURN"]
assert c["logaccept"][-1]["target"] == "ACCEPT"
assert c["logdrop"][0]["spec"] == ["-s", "192.168.1.50", "-j", "ACCEPT"]
assert c["logdrop"][-1]["target"] == "DROP"
assert c["portscan"][0]["spec"] == ["-s", "192.168.1.99", "-j", "RETURN"]
assert c["portscan"][-1]["target"] == "logdrop"
assert c["logbrute"][0]["target"] == "LOG"
assert c["logbrute"][-1]["target"] == "DROP"
PYEOF

# --- Test 5: Mid-run interruption preserves custom rules and ALL terminal verdicts ---
init_state
if IPTABLES_BIN="$MOCK_IPT" MOCK_IPT_STATE="$STATE_FILE" NF_LOG_PROC="$PROC_OK" \
   MOCK_IPT_FAIL_AFTER=3 SLEEP_SEC=0 SKIP_DAEMON=1 sh "$FW_SCRIPT" 2>/dev/null; then
  echo "FAIL: expected simulated mid-run interruption to exit non-zero" >&2
  exit 1
fi

python3 - "$STATE_FILE" <<'PYEOF'
import json, sys
s = json.loads(open(sys.argv[1]).read())
c = s["chains"]
assert s["meta"]["flushed_live"] == [], f"live chains flushed before interruption: {s['meta']['flushed_live']}"
assert c["logaccept"][0]["spec"] == ["-s", "192.168.1.250", "-j", "RETURN"]
assert c["logaccept"][-1]["target"] == "ACCEPT"
assert c["logdrop"][0]["spec"] == ["-s", "192.168.1.50", "-j", "ACCEPT"]
assert c["logdrop"][-1]["target"] == "DROP"
assert c["logreject"][-1]["target"] == "REJECT"
assert c["logreject_tcp"][-1]["target"] == "REJECT"
assert c["portscan"][0]["spec"] == ["-s", "192.168.1.99", "-j", "RETURN"]
assert c["portscan"][-1]["target"] == "logdrop"
assert c["logbrute"][-1]["target"] == "DROP"
PYEOF

echo "PASS: rc_firewall.sh verified (NFLOG precheck, no flush, custom rule preservation, interruption safety, rollback)"
