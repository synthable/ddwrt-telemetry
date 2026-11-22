"""Parser for DD-WRT dnsmasq query logs and LAN device maps."""

from __future__ import annotations

import gzip
import ipaddress
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

# Example: Nov 21 23:43:12 dnsmasq[3630]: query[A] cloudflare.com from 192.168.1.1
LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"dnsmasq\[\d+\]:\s+(?P<msg>.+)$"
)
QUERY_RE = re.compile(r"^query\[(?P<qtype>[^\]]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client>\S+)$")
FORWARDED_RE = re.compile(r"^forwarded\s+(?P<domain>\S+)\s+to\s+(?P<upstream>\S+)$")
RESULT_RE = re.compile(
    r"^(?P<kind>reply|cached|config|/etc/hosts)\s+(?P<domain>\S+)\s+is\s+(?P<value>.+)$"
)
ARCHIVE_YEAR_RE = re.compile(r"dns-(\d{4})(\d{2})\d{2}-")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

BLOCKED_VALUES = {"0.0.0.0", "::", "0::0"}


@dataclass
class DnsQuery:
    ts: int
    ts_iso: str
    client_ip: str
    client_name: str
    qtype: str
    domain: str
    status: str = "allowed"  # blocked | cached | nxdomain | allowed
    cached: bool = False
    upstream: str = ""
    answers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "ts_iso": self.ts_iso,
            "client_ip": self.client_ip,
            "client_name": self.client_name,
            "qtype": self.qtype,
            "domain": self.domain,
            "status": self.status,
            "cached": self.cached,
            "upstream": self.upstream,
            "answers": self.answers[:6],
        }


def parse_device_map(dnsmasq_conf: str = "", leases_text: str = "") -> dict[str, str]:
    """Build IP -> hostname map from dnsmasq.conf dhcp-host entries and leases."""
    devices: dict[str, str] = {
        "192.168.1.1": "router",
        "127.0.0.1": "router",
    }

    # Dynamic leases first (static reservations override if both exist)
    for raw in leases_text.splitlines():
        parts = raw.strip().split()
        if len(parts) >= 4:
            ip, host = parts[2], parts[3]
            if host and host != "*":
                devices[ip] = host

    # Static dhcp-host=id:*,<mac>[,<mac>...],<ip>,<hostname>
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


def ptr_domain_to_ip(domain: str) -> str | None:
    """Convert in-addr.arpa or ip6.arpa reverse domain to canonical IP string."""
    lower = domain.rstrip(".").lower()
    if lower.endswith(".in-addr.arpa"):
        labels = lower[: -len(".in-addr.arpa")].split(".")
        if len(labels) == 4:
            try:
                return str(ipaddress.IPv4Address(".".join(reversed(labels))))
            except ValueError:
                return None
    elif lower.endswith(".ip6.arpa"):
        nibbles = lower[: -len(".ip6.arpa")].split(".")
        if len(nibbles) == 32:
            hex_str = "".join(reversed(nibbles))
            try:
                groups = [hex_str[i : i + 4] for i in range(0, 32, 4)]
                return str(ipaddress.IPv6Address(":".join(groups)))
            except ValueError:
                return None
    return None


def _is_ipv4(val: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(val), ipaddress.IPv4Address)
    except ValueError:
        return False


def _is_ipv6(val: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(val), ipaddress.IPv6Address)
    except ValueError:
        return False


def _infer_timestamp(
    month_str: str,
    day: int,
    time_str: str,
    ref_year: int,
    ref_month: int,
) -> tuple[int, str]:
    month = MONTHS[month_str]
    year = ref_year
    # Handle Dec logs parsed in Jan of the following year
    if month > ref_month + 1:
        year -= 1
    hh, mm, ss = (int(x) for x in time_str.split(":"))
    dt = datetime(year, month, day, hh, mm, ss)
    return int(dt.timestamp()), dt.isoformat()


def _match_pending(
    pending: dict[str, deque[DnsQuery]],
    key: str,
    ts: int,
    value: str | None = None,
) -> DnsQuery | None:
    bucket = pending.get(key)
    if not bucket:
        return None
    # Drop stale pending entries (> 8 seconds old)
    while bucket and ts - bucket[0].ts > 8:
        bucket.popleft()
    if not bucket:
        return None

    # Prefer matching A / AAAA / HTTPS / SVCB when multiple queries for same domain are in-flight
    if value is not None:
        if _is_ipv4(value) or value == "NODATA-IPv4":
            for q in reversed(bucket):
                if q.qtype == "A":
                    return q
        elif _is_ipv6(value) or value == "NODATA-IPv6":
            for q in reversed(bucket):
                if q.qtype == "AAAA":
                    return q
        elif value == "<HTTPS>":
            for q in reversed(bucket):
                if q.qtype == "HTTPS":
                    return q
        elif value == "<SVCB>":
            for q in reversed(bucket):
                if q.qtype == "SVCB":
                    return q

    return bucket[-1]


def parse_lines(
    lines: Iterable[str],
    devices: dict[str, str],
    ref_year: int | None = None,
    ref_month: int | None = None,
) -> list[DnsQuery]:
    """Parse dnsmasq log lines into structured DnsQuery records."""
    now = datetime.now()
    ry = ref_year if ref_year is not None else now.year
    rm = ref_month if ref_month is not None else now.month

    queries: list[DnsQuery] = []
    pending: dict[str, deque[DnsQuery]] = {}

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        m = LINE_RE.match(line)
        if not m:
            continue

        ts, ts_iso = _infer_timestamp(
            m.group("month"), int(m.group("day")), m.group("time"), ry, rm
        )
        msg = m.group("msg")

        qm = QUERY_RE.match(msg)
        if qm:
            qtype = qm.group("qtype")
            domain = qm.group("domain").rstrip(".")
            client_ip = qm.group("client")
            record = DnsQuery(
                ts=ts,
                ts_iso=ts_iso,
                client_ip=client_ip,
                client_name=devices.get(client_ip, client_ip),
                qtype=qtype,
                domain=domain,
            )
            queries.append(record)
            key = domain.lower()
            bucket = pending.setdefault(key, deque(maxlen=12))
            bucket.append(record)

            if qtype == "PTR":
                ptr_ip = ptr_domain_to_ip(domain)
                if ptr_ip:
                    pending.setdefault(ptr_ip.lower(), deque(maxlen=12)).append(record)
            continue

        fm = FORWARDED_RE.match(msg)
        if fm:
            key = fm.group("domain").rstrip(".").lower()
            target = _match_pending(pending, key, ts)
            if target:
                target.upstream = fm.group("upstream")
            continue

        rm_match = RESULT_RE.match(msg)
        if rm_match:
            kind = rm_match.group("kind")
            key = rm_match.group("domain").rstrip(".").lower()
            val = rm_match.group("value").strip()
            target = _match_pending(pending, key, ts, val)
            if not target:
                continue

            if val and val not in target.answers and len(target.answers) < 8:
                target.answers.append(val)

            if kind == "cached":
                target.cached = True
                if not target.upstream:
                    target.upstream = "cache"
            elif kind in ("config", "/etc/hosts") and not target.upstream:
                target.upstream = kind

            if val in BLOCKED_VALUES:
                target.status = "blocked"
            elif kind == "config" and val == "NXDOMAIN":
                target.status = "blocked"
            elif val == "NXDOMAIN":
                if target.status != "blocked":
                    target.status = "nxdomain"
            else:
                if target.status != "blocked":
                    target.status = "cached" if target.cached else "allowed"

    return queries


def parse_log_file(path: Path, devices: dict[str, str]) -> list[DnsQuery]:
    """Parse a plain or .gz dnsmasq log file."""
    ref_year: int | None = None
    ref_month: int | None = None
    am = ARCHIVE_YEAR_RE.search(path.name)
    if am:
        ref_year = int(am.group(1))
        ref_month = int(am.group(2))

    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return parse_lines(fh, devices, ref_year, ref_month)
    with path.open("rt", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh, devices, ref_year, ref_month)


def load_all_logs(data_dir: Path) -> tuple[list[DnsQuery], dict[str, str], list[str]]:
    """Load device map and all cached archives + live log from data_dir."""
    conf_path = data_dir / "dnsmasq.conf"
    leases_path = data_dir / "dnsmasq.leases"
    devices = parse_device_map(
        conf_path.read_text(encoding="utf-8", errors="replace") if conf_path.exists() else "",
        leases_path.read_text(encoding="utf-8", errors="replace") if leases_path.exists() else "",
    )

    archives_dir = data_dir / "archives"
    files: list[Path] = []
    if archives_dir.exists():
        files.extend(sorted(archives_dir.glob("dns-*.log.gz")))
    live_prev = data_dir / "dns.log.prev"
    if live_prev.exists():
        files.append(live_prev)
    live_path = data_dir / "dns.log"
    if live_path.exists():
        files.append(live_path)

    all_queries: list[DnsQuery] = []
    source_names: list[str] = []
    for f in files:
        all_queries.extend(parse_log_file(f, devices))
        source_names.append(f.name)

    all_queries.sort(key=lambda q: q.ts)
    return all_queries, devices, source_names
