"""Parser & traffic classifier for DD-WRT iptables + NFLOG firewall logs."""

from __future__ import annotations

import gzip
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

# Matches both legacy kernel syslog lines and nflogd lines:
# Nov 21 23:44:27.030 router kern.warn kernel: [593152.396081] DROP IN=wan ...
# Nov 22 00:23:55.869 router kern.info kernel: [1795335835.869980] ACCEPT IN=br0 OUT=wan ...
SYSLOG_FW_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+"
    r"\S+\s+\S+\s+kernel:\s+\[(?P<ktime>[\d.]+)\]\s+"
    r"(?P<prefix>ACCEPT|DROP|REJECT|portscan:|\[DROP BRUTEFORCE\]\s*:)\s+(?P<body>.+)$"
)
KV_RE = re.compile(r"\b([A-Z]+)=([^\s]*)")
ARCHIVE_YEAR_RE = re.compile(r"(?:syslog|fw-drop|fw-accept)-(\d{4})(\d{2})\d{2}-")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

TCP_FLAGS = ("SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR")

PROTO_NAMES = {
    "1": "ICMP",
    "2": "IGMP",
    "4": "IP-in-IP",
    "6": "TCP",
    "17": "UDP",
    "41": "IPv6-encap",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6",
    "89": "OSPF",
    "132": "SCTP",
}

WELL_KNOWN_PORTS = {
    7: "Echo",
    17: "QOTD",
    19: "Chargen",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "SMB/NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    500: "IKE/IPsec",
    514: "Syslog",
    554: "RTSP",
    623: "IPMI",
    853: "DoT",
    1194: "OpenVPN",
    1433: "MSSQL",
    1701: "L2TP",
    1723: "PPTP",
    1883: "MQTT",
    1900: "SSDP/UPnP",
    2222: "SSH-Alt",
    2323: "Telnet-Alt",
    3283: "Apple-RD",
    3306: "MySQL",
    3389: "RDP",
    3478: "STUN",
    3671: "KNX",
    3702: "WS-Discovery",
    4500: "IPsec-NAT-T",
    5060: "SIP",
    5223: "APNs",
    5228: "Google-Push",
    5351: "NAT-PMP",
    5353: "mDNS",
    5432: "PostgreSQL",
    5683: "CoAP",
    5900: "VNC",
    6379: "Redis",
    7547: "TR-069",
    8080: "HTTP-Alt",
    8291: "Winbox",
    8443: "HTTPS-Alt",
    9100: "JetDirect",
    11211: "Memcached",
    27017: "MongoDB",
    51820: "WireGuard",
}

ICMP_TYPES = {
    "0": "Echo Reply",
    "3": "Dest Unreach",
    "5": "Redirect",
    "8": "Echo Req (Ping)",
    "11": "Time Exceeded",
}


@dataclass
class FirewallEvent:
    ts: int
    ts_iso: str
    ktime: str
    action: str  # ACCEPT | DROP | REJECT | PORTSCAN | BRUTEFORCE
    verdict: str  # blocked | allowed
    category: str  # probe | ping | stale | other | outbound | local
    in_iface: str
    out_iface: str
    src_ip: str
    src_name: str
    dst_ip: str
    dst_name: str
    proto: str
    proto_raw: str
    spt: int | None
    dpt: int | None
    service: str
    length: int | None
    ttl: int | None
    flags: list[str]
    icmp_type: str
    dedup_key: str

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "ts_iso": self.ts_iso,
            "action": self.action,
            "verdict": self.verdict,
            "category": self.category,
            "in_iface": self.in_iface,
            "out_iface": self.out_iface,
            "src_ip": self.src_ip,
            "src_name": self.src_name,
            "dst_ip": self.dst_ip,
            "dst_name": self.dst_name,
            "proto": self.proto,
            "spt": self.spt,
            "dpt": self.dpt,
            "service": self.service,
            "length": self.length,
            "ttl": self.ttl,
            "flags": self.flags,
            "icmp_type": self.icmp_type,
        }


def parse_device_map(dnsmasq_conf: str = "", leases_text: str = "") -> dict[str, str]:
    devices: dict[str, str] = {
        "192.168.1.1": "router",
        "127.0.0.1": "router",
    }
    for raw in leases_text.splitlines():
        parts = raw.strip().split()
        if len(parts) >= 4 and parts[3] != "*":
            devices[parts[2]] = parts[3]

    for raw in dnsmasq_conf.splitlines():
        line = raw.strip()
        if not line.startswith("dhcp-host="):
            continue
        body = line.split("=", 1)[1].split("#", 1)[0].strip()
        tokens = [t.strip() for t in body.split(",") if t.strip()]
        found_ip = None
        found_name = None
        for tok in tokens:
            if tok.startswith("id:") or ":" in tok:
                continue
            try:
                ipaddress.ip_address(tok)
                found_ip = tok
            except ValueError:
                if not tok.endswith(("m", "h", "d")) or not tok[:-1].isdigit():
                    found_name = tok
        if found_ip and found_name:
            devices[found_ip] = found_name

    return devices


def _infer_timestamp(
    month_str: str,
    day: int,
    time_str: str,
    ktime: str,
    ref_year: int,
    ref_month: int,
) -> tuple[int, str]:
    # nflogd embeds exact Unix epoch in [ktime] (e.g. 1795335835.869980)
    try:
        kt_val = float(ktime)
        if kt_val >= 1_500_000_000:
            ts_int = int(kt_val)
            return ts_int, datetime.fromtimestamp(ts_int).isoformat()
    except ValueError:
        pass

    month = MONTHS[month_str]
    year = ref_year
    if month > ref_month + 1:
        year -= 1
    hh, mm, ss = (int(x) for x in time_str.split(":"))
    dt = datetime(year, month, day, hh, mm, ss)
    return int(dt.timestamp()), dt.isoformat()


def _normalize_action(prefix: str) -> str:
    p = prefix.strip()
    if p == "ACCEPT":
        return "ACCEPT"
    if p.startswith("portscan"):
        return "PORTSCAN"
    if "BRUTEFORCE" in p:
        return "BRUTEFORCE"
    if p == "REJECT":
        return "REJECT"
    return "DROP"


def _classify_event(
    action: str,
    proto: str,
    spt: int | None,
    dpt: int | None,
    flags: list[str],
    out_iface: str,
    wan_iface: str = "wan",
) -> tuple[str, str, str]:
    """Return (verdict, category, service_label)."""
    if action == "ACCEPT":
        svc = WELL_KNOWN_PORTS.get(dpt, f"{proto.lower()}/{dpt}") if dpt is not None else proto
        cat = "outbound" if (wan_iface and out_iface == wan_iface) else "local"
        return "allowed", cat, svc

    if action in ("PORTSCAN", "BRUTEFORCE"):
        svc = WELL_KNOWN_PORTS.get(dpt, f"port {dpt}") if dpt is not None else proto
        return "blocked", "probe", svc

    if proto == "ICMP":
        return "blocked", "ping", "ICMP"

    if proto not in ("TCP", "UDP"):
        return "blocked", "probe", proto

    if proto == "UDP" and spt in (443, 80, 53) and dpt is not None and dpt >= 1024:
        return "blocked", "stale", f"Late {WELL_KNOWN_PORTS.get(spt, spt)} return"

    if proto == "TCP" and dpt is not None and dpt >= 1024:
        if ("RST" in flags or "FIN" in flags or "ACK" in flags) and "SYN" not in flags:
            svc = (
                f"Late {WELL_KNOWN_PORTS.get(spt, 'TCP')} teardown"
                if spt in (80, 443)
                else "TCP teardown"
            )
            return "blocked", "stale", svc

    if dpt is not None:
        if dpt in WELL_KNOWN_PORTS:
            return "blocked", "probe", WELL_KNOWN_PORTS[dpt]
        if dpt < 1024:
            return "blocked", "probe", f"priv/{dpt}"
        if proto == "TCP" and "SYN" in flags:
            return "blocked", "probe", f"tcp/{dpt}"
        return "blocked", "other", f"{proto.lower()}/{dpt}"

    return "blocked", "other", proto


def parse_lines(
    lines: Iterable[str],
    devices: dict[str, str] | None = None,
    ref_year: int | None = None,
    ref_month: int | None = None,
    wan_iface: str = "wan",
) -> list[FirewallEvent]:
    now = datetime.now()
    ry = ref_year if ref_year is not None else now.year
    rm = ref_month if ref_month is not None else now.month
    dev_map = devices or {}

    events: list[FirewallEvent] = []

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        m = SYSLOG_FW_RE.match(line)
        if not m:
            continue

        ktime = m.group("ktime")
        ts, ts_iso = _infer_timestamp(
            m.group("month"), int(m.group("day")), m.group("time"), ktime, ry, rm
        )
        action = _normalize_action(m.group("prefix"))
        body = m.group("body")

        kv: dict[str, str] = {}
        first_len: int | None = None
        for k, v in KV_RE.findall(body):
            if k == "LEN" and first_len is None and v.isdigit():
                first_len = int(v)
            if k not in kv:
                kv[k] = v

        proto_raw = kv.get("PROTO", "UNKNOWN")
        proto = PROTO_NAMES.get(proto_raw, proto_raw)
        if proto_raw.isdigit() and proto == proto_raw:
            proto = f"PROTO-{proto_raw}"

        spt = int(kv["SPT"]) if kv.get("SPT", "").isdigit() else None
        dpt = int(kv["DPT"]) if kv.get("DPT", "").isdigit() else None
        ttl = int(kv["TTL"]) if kv.get("TTL", "").isdigit() else None
        icmp_type_num = kv.get("TYPE", "")
        icmp_label = ICMP_TYPES.get(icmp_type_num, f"Type {icmp_type_num}") if icmp_type_num else ""

        tokens = set(body.split())
        flags = [f for f in TCP_FLAGS if f in tokens] if proto == "TCP" else []

        in_iface = kv.get("IN", "")
        out_iface = kv.get("OUT", "")
        verdict, category, service = _classify_event(
            action, proto, spt, dpt, flags, out_iface, wan_iface=wan_iface
        )
        if proto == "ICMP" and icmp_label:
            service = icmp_label

        src_ip = kv.get("SRC", "")
        dst_ip = kv.get("DST", "")
        dedup_key = f"{action}|{ktime}|{src_ip}|{dst_ip}|{proto_raw}|{spt}|{dpt}|{kv.get('ID', '')}"

        events.append(
            FirewallEvent(
                ts=ts,
                ts_iso=ts_iso,
                ktime=ktime,
                action=action,
                verdict=verdict,
                category=category,
                in_iface=in_iface,
                out_iface=out_iface,
                src_ip=src_ip,
                src_name=dev_map.get(src_ip, ""),
                dst_ip=dst_ip,
                dst_name=dev_map.get(dst_ip, ""),
                proto=proto,
                proto_raw=proto_raw,
                spt=spt,
                dpt=dpt,
                service=service,
                length=first_len,
                ttl=ttl,
                flags=flags,
                icmp_type=icmp_label,
                dedup_key=dedup_key,
            )
        )

    return events


def parse_iptables_counters(iptables_text: str, wan_iface: str = "wan") -> dict[str, dict]:
    counters: dict[str, dict] = {
        "wan_ssh_22": {"label": "WAN SSH :22", "pkts": None, "bytes": None, "available": False},
        "wan_ssh_2222": {"label": "WAN SSH :2222", "pkts": None, "bytes": None, "available": False},
        "wan_psd": {"label": "Port-Scan (psd)", "pkts": None, "bytes": None, "available": False},
        "wan_icmp": {"label": "WAN ICMP Drop", "pkts": None, "bytes": None, "available": False},
        "invalid_drop": {"label": "Invalid State", "pkts": None, "bytes": None, "available": False},
        "tarpit_tcp": {"label": "Silent TCP Drop", "pkts": None, "bytes": None, "available": False},
    }

    chain = ""
    for raw in iptables_text.splitlines():
        line = raw.strip()
        if line.startswith("Chain "):
            chain = line.split()[1]
            continue
        parts = line.split()
        if len(parts) < 8 or parts[0] == "pkts":
            continue
        pkts_str, bytes_str, target, proto, _opt, in_if = (
            parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        )
        rest = " ".join(parts[8:])

        def parse_pkts(s: str) -> int:
            s = s.upper()
            if s.endswith("K"):
                return int(float(s[:-1]) * 1000)
            if s.endswith("M"):
                return int(float(s[:-1]) * 1_000_000)
            if s.endswith("G"):
                return int(float(s[:-1]) * 1_000_000_000)
            return int(s) if s.isdigit() else 0

        pkts = parse_pkts(pkts_str)
        is_wan_in = bool(wan_iface) and in_if == wan_iface

        if chain == "INPUT" and is_wan_in and target == "DROP" and "dpt:22 " in (rest + " "):
            counters["wan_ssh_22"] = {
                "label": "WAN SSH :22", "pkts": pkts, "bytes": bytes_str, "available": True
            }
        elif chain == "INPUT" and is_wan_in and target == "DROP" and "dpt:2222" in rest:
            counters["wan_ssh_2222"] = {
                "label": "WAN SSH :2222", "pkts": pkts, "bytes": bytes_str, "available": True
            }
        elif chain == "INPUT" and is_wan_in and "-m psd" in rest:
            counters["wan_psd"] = {
                "label": "Port-Scan (psd)", "pkts": pkts, "bytes": bytes_str, "available": True
            }
        elif chain == "INPUT" and is_wan_in and proto == "icmp" and target == "logdrop":
            counters["wan_icmp"] = {
                "label": "WAN ICMP Drop", "pkts": pkts, "bytes": bytes_str, "available": True
            }
        elif chain == "INPUT" and target == "logdrop" and "state INVALID" in rest:
            counters["invalid_drop"] = {
                "label": "Invalid State", "pkts": pkts, "bytes": bytes_str, "available": True
            }
        elif chain == "tarpit" and proto == "tcp" and target == "DROP":
            counters["tarpit_tcp"] = {
                "label": "Silent TCP Drop", "pkts": pkts, "bytes": bytes_str, "available": True
            }

    return counters


def parse_log_file(
    path: Path,
    devices: dict[str, str],
    wan_iface: str = "wan",
) -> list[FirewallEvent]:
    ref_year: int | None = None
    ref_month: int | None = None
    am = ARCHIVE_YEAR_RE.search(path.name)
    if am:
        ref_year = int(am.group(1))
        ref_month = int(am.group(2))

    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return parse_lines(fh, devices, ref_year, ref_month, wan_iface=wan_iface)
    with path.open("rt", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh, devices, ref_year, ref_month, wan_iface=wan_iface)


def load_all_logs(
    data_dir: Path,
    wan_iface: str = "wan",
) -> tuple[list[FirewallEvent], dict[str, dict], list[str]]:
    conf_path = data_dir / "dnsmasq.conf"
    leases_path = data_dir / "dnsmasq.leases"
    devices = parse_device_map(
        conf_path.read_text(encoding="utf-8", errors="replace") if conf_path.exists() else "",
        leases_path.read_text(encoding="utf-8", errors="replace") if leases_path.exists() else "",
    )

    archives_dir = data_dir / "archives"
    files: list[Path] = []
    if archives_dir.exists():
        files.extend(sorted(archives_dir.glob("syslog-*.log.gz")))
        files.extend(sorted(archives_dir.glob("fw-drop-*.log.gz")))
        files.extend(sorted(archives_dir.glob("fw-accept-*.log.gz")))
    for live_name in (
        "messages.0",
        "messages",
        "fw-drop.log.prev",
        "fw-drop.log",
        "fw-accept.log.prev",
        "fw-accept.log",
    ):
        p = data_dir / live_name
        if p.exists() and p.stat().st_size > 0:
            files.append(p)

    seen: set[str] = set()
    events: list[FirewallEvent] = []
    sources: list[str] = []

    for f in files:
        sources.append(f.name)
        for ev in parse_log_file(f, devices, wan_iface=wan_iface):
            if ev.dedup_key not in seen:
                seen.add(ev.dedup_key)
                events.append(ev)

    events.sort(key=lambda e: (e.ts, float(e.ktime)))

    ipt_path = data_dir / "iptables.txt"
    counters = (
        parse_iptables_counters(
            ipt_path.read_text(encoding="utf-8", errors="replace"),
            wan_iface=wan_iface,
        )
        if ipt_path.exists()
        else parse_iptables_counters("", wan_iface=wan_iface)
    )
    return events, counters, sources
