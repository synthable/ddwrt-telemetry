#!/usr/bin/env python3
"""Local HTTP server with real-time router HTTP/SSE ingestion for Firewall Dashboard."""

from __future__ import annotations

import argparse
import csv
import io
import json
import mimetypes
import os
import random
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from parser import FirewallEvent, load_all_logs, parse_device_map, parse_lines

ROOT_DIR = Path(__file__).resolve().parent
STATIC_DIR = ROOT_DIR / "static"
DATA_DIR = ROOT_DIR / "data"
ARCHIVES_DIR = DATA_DIR / "archives"

DEFAULT_ROUTER_API = os.environ.get("ROUTER_API", "http://192.168.1.1:8789")
DEFAULT_ROUTER_NAME = os.environ.get("ROUTER_NAME", "DD-WRT Router")
DEFAULT_TOKEN_FILE = os.environ.get(
    "ROUTER_TOKEN_FILE", str(Path.home() / ".ddwrt" / "nflogd.token")
)


def _env_non_negative_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
        return max(val, 0)
    except ValueError:
        return default


DEFAULT_RETAIN_DAYS = _env_non_negative_int("RETAIN_DAYS", 30)
DEFAULT_MAX_ARCHIVES = _env_non_negative_int("MAX_ARCHIVES", 0)

MANAGED_ARCHIVE_RE = re.compile(r"^(fw-drop|fw-accept|syslog)-(\d{8})-(\d{6})\.log\.gz$")


def parse_archive_entry(name: str) -> tuple[str, int] | None:
    """Return (prefix, unix_ts) for a managed firewall/syslog archive filename, or None."""
    m = MANAGED_ARCHIVE_RE.match(name)
    if not m:
        return None
    try:
        dt = datetime.strptime(f"{m.group(2)}-{m.group(3)}", "%Y%m%d-%H%M%S")
    except ValueError:
        return None
    return m.group(1), int(dt.timestamp())


def select_archives_to_download(
    remote_names: list,
    archives_dir: Path,
    retain_days: int = DEFAULT_RETAIN_DAYS,
    max_archives: int = DEFAULT_MAX_ARCHIVES,
    now_ts: int | None = None,
) -> list[str]:
    """Select missing remote archives that satisfy retain_days and max_archives limits."""
    now = int(time.time()) if now_ts is None else int(now_ts)
    cutoff = now - retain_days * 86400 if retain_days > 0 else None

    remote_set: set[str] = set()
    by_prefix: dict[str, dict[str, int]] = {}

    if archives_dir.is_dir():
        for entry in archives_dir.iterdir():
            if not entry.is_file():
                continue
            parsed = parse_archive_entry(entry.name)
            if parsed is None:
                continue
            prefix, ts = parsed
            if cutoff is not None and ts < cutoff:
                continue
            by_prefix.setdefault(prefix, {})[entry.name] = ts

    for name in remote_names or []:
        if not isinstance(name, str):
            continue
        base_name = Path(name).name
        parsed = parse_archive_entry(base_name)
        if parsed is None:
            continue
        prefix, ts = parsed
        if cutoff is not None and ts < cutoff:
            continue
        remote_set.add(base_name)
        by_prefix.setdefault(prefix, {})[base_name] = ts

    to_download: list[str] = []
    for items in by_prefix.values():
        ordered = sorted(items.items(), key=lambda pair: (pair[1], pair[0]))
        if max_archives > 0 and len(ordered) > max_archives:
            ordered = ordered[-max_archives:]
        for base_name, _ in ordered:
            if base_name in remote_set and not (archives_dir / base_name).exists():
                to_download.append(base_name)

    return sorted(to_download)


def prune_local_archives(
    archives_dir: Path,
    retain_days: int = DEFAULT_RETAIN_DAYS,
    max_archives: int = DEFAULT_MAX_ARCHIVES,
    now_ts: int | None = None,
) -> list[str]:
    """Prune expired or excess managed firewall archives while preserving unrelated files."""
    if not archives_dir.is_dir():
        return []
    now = int(time.time()) if now_ts is None else int(now_ts)
    cutoff = now - retain_days * 86400 if retain_days > 0 else None

    deleted: list[str] = []
    survivors: dict[str, list[tuple[int, Path]]] = {}
    for entry in archives_dir.iterdir():
        if not entry.is_file():
            continue
        parsed = parse_archive_entry(entry.name)
        if parsed is None:
            continue
        prefix, ts = parsed
        if cutoff is not None and ts < cutoff:
            entry.unlink(missing_ok=True)
            deleted.append(entry.name)
        else:
            survivors.setdefault(prefix, []).append((ts, entry))

    if max_archives > 0:
        for items in survivors.values():
            items.sort(key=lambda pair: (pair[0], pair[1].name))
            if len(items) > max_archives:
                for _, entry in items[:-max_archives]:
                    entry.unlink(missing_ok=True)
                    deleted.append(entry.name)

    return sorted(deleted)


def generate_demo_firewall_data(
    now_ts: int | None = None,
) -> tuple[list[FirewallEvent], dict[str, str], dict[str, dict]]:
    """Generate ~320 realistic synthetic firewall events & kernel counters spanning ~6 hours."""
    rng = random.Random(42)
    end_ts = int(time.time()) if now_ts is None else now_ts
    span_sec = 6 * 3600
    start_ts = end_ts - span_sec

    wan_ip = "203.0.113.10"
    devices = {
        "192.168.1.1": "router",
        "192.168.1.10": "workstation",
        "192.168.1.22": "phone",
        "192.168.1.35": "smart-tv",
        "192.168.1.48": "smart-speaker",
        "192.168.1.64": "tablet",
    }

    # RFC 5737 documentation IPs for synthetic external scanners & peers
    multi_scanners = ["198.51.100.14", "192.0.2.44", "198.51.100.77"]
    wan_peers = [
        "198.51.100.23",
        "198.51.100.51",
        "198.51.100.99",
        "192.0.2.18",
        "192.0.2.72",
        "192.0.2.105",
        "192.0.2.194",
        "203.0.113.45",
        "203.0.113.82",
        "203.0.113.120",
    ]
    cdn_peers = [
        "104.16.133.229",
        "140.82.114.6",
        "142.250.191.238",
        "17.248.192.44",
        "52.217.139.8",
        "162.159.200.1",
        "198.51.100.200",
        "94.140.14.14",
    ]

    probe_templates = [
        ("UDP", "17", 161, "SNMP", [], 68),
        ("UDP", "17", 5060, "SIP", [], 420),
        ("UDP", "17", 11211, "Memcached", [], 42),
        ("UDP", "17", 623, "IPMI", [], 56),
        ("TCP", "6", 3389, "RDP", ["SYN"], 60),
        ("TCP", "6", 22, "SSH", ["SYN"], 60),
        ("TCP", "6", 23, "Telnet", ["SYN"], 44),
        ("TCP", "6", 445, "SMB", ["SYN"], 52),
        ("TCP", "6", 8080, "HTTP-Alt", ["SYN"], 60),
        ("GRE", "47", None, "GRE", [], 564),
        ("IP-in-IP", "4", None, "IP-in-IP", [], 68),
    ]

    outbound_templates = [
        ("TCP", "6", 443, "HTTPS", ["SYN"], 60),
        ("UDP", "17", 443, "HTTPS", [], 1228),
        ("TCP", "6", 853, "DoT", ["SYN"], 60),
        ("UDP", "17", 53, "DNS", [], 74),
        ("UDP", "17", 123, "NTP", [], 76),
        ("TCP", "6", 5223, "APNs", ["SYN"], 60),
        ("UDP", "17", 51820, "WireGuard", [], 176),
        ("TCP", "6", 80, "HTTP", ["SYN"], 60),
    ]

    local_templates = [
        ("UDP", "17", 53, "DNS", [], 68),
        ("UDP", "17", 5353, "mDNS", [], 112),
        ("UDP", "17", 67, "DHCP", [], 328),
        ("TCP", "6", 22, "SSH", ["SYN"], 60),
    ]

    lan_ips = [ip for ip in devices if ip != "192.168.1.1"]
    events: list[FirewallEvent] = []
    seq = 0

    def pick_ts() -> tuple[int, str, str]:
        nonlocal seq
        seq += 1
        if rng.random() < 0.42:
            ts = end_ts - rng.randint(0, 7200)
        else:
            ts = rng.randint(start_ts, end_ts)
        ktime = f"{ts}.{rng.randint(100000, 999999)}"
        return ts, datetime.fromtimestamp(ts).isoformat(), ktime

    # 200 Blocked WAN events
    for _ in range(200):
        ts, ts_iso, ktime = pick_ts()
        roll = rng.random()
        if roll < 0.56:
            # Inbound probes (ports + GRE/47 + IP-in-IP/4)
            proto, proto_raw, dpt, svc, flags, length = rng.choice(probe_templates)
            src_ip = rng.choice(multi_scanners) if rng.random() < 0.45 else rng.choice(wan_peers)
            spt = rng.randint(10000, 62000) if proto in ("TCP", "UDP") else None
            action = "PORTSCAN" if (src_ip in multi_scanners and rng.random() < 0.18) else "DROP"
            events.append(
                FirewallEvent(
                    ts=ts,
                    ts_iso=ts_iso,
                    ktime=ktime,
                    action=action,
                    verdict="blocked",
                    category="probe",
                    in_iface="wan",
                    out_iface="",
                    src_ip=src_ip,
                    src_name="",
                    dst_ip=wan_ip,
                    dst_name="",
                    proto=proto,
                    proto_raw=proto_raw,
                    spt=spt,
                    dpt=dpt,
                    service=svc,
                    length=length,
                    ttl=rng.choice([37, 51, 54, 118, 240, 242]),
                    flags=list(flags),
                    icmp_type="",
                    dedup_key=f"demo|{seq}|{action}|{src_ip}|{dpt}",
                )
            )
        elif roll < 0.72:
            # ICMP Echo Req (Ping)
            src_ip = rng.choice(wan_peers)
            events.append(
                FirewallEvent(
                    ts=ts,
                    ts_iso=ts_iso,
                    ktime=ktime,
                    action="DROP",
                    verdict="blocked",
                    category="ping",
                    in_iface="wan",
                    out_iface="",
                    src_ip=src_ip,
                    src_name="",
                    dst_ip=wan_ip,
                    dst_name="",
                    proto="ICMP",
                    proto_raw="1",
                    spt=None,
                    dpt=None,
                    service="Echo Req (Ping)",
                    length=48,
                    ttl=rng.choice([52, 117, 232]),
                    flags=[],
                    icmp_type="Echo Req (Ping)",
                    dedup_key=f"demo|{seq}|ICMP|{src_ip}",
                )
            )
        elif roll < 0.93:
            # Stale QUIC UDP/443 or TCP RST teardown
            src_ip = rng.choice(cdn_peers)
            if rng.random() < 0.55:
                proto, proto_raw, flags, svc, length = "UDP", "17", [], "Late HTTPS return", 94
            else:
                proto, proto_raw, flags, svc, length = (
                    "TCP",
                    "6",
                    rng.choice([["RST"], ["RST", "ACK"], ["FIN", "ACK"]]),
                    "Late HTTPS teardown",
                    40,
                )
            dpt = rng.randint(32768, 61000)
            events.append(
                FirewallEvent(
                    ts=ts,
                    ts_iso=ts_iso,
                    ktime=ktime,
                    action="DROP",
                    verdict="blocked",
                    category="stale",
                    in_iface="wan",
                    out_iface="",
                    src_ip=src_ip,
                    src_name="",
                    dst_ip=wan_ip,
                    dst_name="",
                    proto=proto,
                    proto_raw=proto_raw,
                    spt=443,
                    dpt=dpt,
                    service=svc,
                    length=length,
                    ttl=rng.choice([52, 56, 240]),
                    flags=flags,
                    icmp_type="",
                    dedup_key=f"demo|{seq}|stale|{src_ip}|{dpt}",
                )
            )
        else:
            # Unsolicited other high-port UDP
            src_ip = rng.choice(wan_peers)
            dpt = rng.randint(15000, 49000)
            events.append(
                FirewallEvent(
                    ts=ts,
                    ts_iso=ts_iso,
                    ktime=ktime,
                    action="DROP",
                    verdict="blocked",
                    category="other",
                    in_iface="wan",
                    out_iface="",
                    src_ip=src_ip,
                    src_name="",
                    dst_ip=wan_ip,
                    dst_name="",
                    proto="UDP",
                    proto_raw="17",
                    spt=rng.randint(10000, 60000),
                    dpt=dpt,
                    service=f"udp/{dpt}",
                    length=rng.randint(52, 180),
                    ttl=rng.choice([49, 114, 236]),
                    flags=[],
                    icmp_type="",
                    dedup_key=f"demo|{seq}|other|{src_ip}|{dpt}",
                )
            )

    # 120 Allowed NFLOG outbound & local flows
    for _ in range(120):
        ts, ts_iso, ktime = pick_ts()
        if rng.random() < 0.78:
            # Outbound br0 -> wan
            src_ip = rng.choice(lan_ips)
            dst_ip = rng.choice(cdn_peers)
            proto, proto_raw, dpt, svc, flags, length = rng.choice(outbound_templates)
            events.append(
                FirewallEvent(
                    ts=ts,
                    ts_iso=ts_iso,
                    ktime=ktime,
                    action="ACCEPT",
                    verdict="allowed",
                    category="outbound",
                    in_iface="br0",
                    out_iface="wan",
                    src_ip=src_ip,
                    src_name=devices[src_ip],
                    dst_ip=dst_ip,
                    dst_name="",
                    proto=proto,
                    proto_raw=proto_raw,
                    spt=rng.randint(40000, 64000),
                    dpt=dpt,
                    service=svc,
                    length=length,
                    ttl=63,
                    flags=list(flags),
                    icmp_type="",
                    dedup_key=f"demo|{seq}|ACCEPT|out|{src_ip}|{dst_ip}|{dpt}",
                )
            )
        else:
            # Local LAN -> router (br0)
            src_ip = rng.choice(lan_ips)
            dst_ip = "192.168.1.1"
            proto, proto_raw, dpt, svc, flags, length = rng.choice(local_templates)
            events.append(
                FirewallEvent(
                    ts=ts,
                    ts_iso=ts_iso,
                    ktime=ktime,
                    action="ACCEPT",
                    verdict="allowed",
                    category="local",
                    in_iface="br0",
                    out_iface="",
                    src_ip=src_ip,
                    src_name=devices[src_ip],
                    dst_ip=dst_ip,
                    dst_name=devices[dst_ip],
                    proto=proto,
                    proto_raw=proto_raw,
                    spt=rng.randint(35000, 62000),
                    dpt=dpt,
                    service=svc,
                    length=length,
                    ttl=64,
                    flags=list(flags),
                    icmp_type="",
                    dedup_key=f"demo|{seq}|ACCEPT|loc|{src_ip}|{dst_ip}|{dpt}",
                )
            )

    events.sort(key=lambda e: (e.ts, float(e.ktime)))

    counters = {
        "wan_ssh_22": {"label": "WAN SSH :22", "pkts": 1842, "bytes": "98K"},
        "wan_ssh_2222": {"label": "WAN SSH :2222", "pkts": 276, "bytes": "14K"},
        "wan_psd": {"label": "Port-Scan (psd)", "pkts": 3190, "bytes": "168K"},
        "wan_icmp": {"label": "WAN ICMP Drop", "pkts": 1412, "bytes": "62K"},
        "invalid_drop": {"label": "Invalid State", "pkts": 4380, "bytes": "204K"},
        "tarpit_tcp": {"label": "Silent TCP Drop", "pkts": 94200, "bytes": "4820K"},
    }
    return events, devices, counters


class FirewallStore:
    def __init__(
        self,
        api_url: str = DEFAULT_ROUTER_API,
        token_file: str = DEFAULT_TOKEN_FILE,
        router_name: str = DEFAULT_ROUTER_NAME,
        demo: bool = False,
        retain_days: int = DEFAULT_RETAIN_DAYS,
        max_archives: int = DEFAULT_MAX_ARCHIVES,
        data_dir: Path | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.token_file = Path(token_file)
        self.router_name = router_name
        self.demo = demo
        self.retain_days = max(int(retain_days), 0)
        self.max_archives = max(int(max_archives), 0)
        self.data_dir = Path(data_dir) if data_dir is not None else DATA_DIR
        self.archives_dir = self.data_dir / "archives"
        self._lock = threading.RLock()
        self.events: list[FirewallEvent] = []
        self._seen: set[str] = set()
        self.devices: dict[str, str] = {}
        self.counters: dict[str, dict] = {}
        self.sources: list[str] = []
        self.last_sync_ts: int | None = None
        self.last_sync_error: str | None = None
        self.syncing: bool = False
        self.stream_connected: bool = False
        self._tail_state: dict[str, tuple[int, int]] = {}
        self._stop_event = threading.Event()
        if self.demo:
            self._load_demo_data()
        else:
            self.reload_local()

    def _load_demo_data(self) -> None:
        now_ts = int(time.time())
        events, devices, counters = generate_demo_firewall_data(now_ts)
        with self._lock:
            self.events = events
            self._seen = {e.dedup_key for e in events}
            self.devices = devices
            self.counters = counters
            self.sources = ["demo-synthetic"]
            self.last_sync_ts = now_ts
            self.last_sync_error = None
            self.stream_connected = False

    def _token(self) -> str:
        if not self.token_file.exists():
            raise RuntimeError(f"Token file not found: {self.token_file}")
        return self.token_file.read_text(encoding="utf-8").strip()

    def _http_get(self, path: str, timeout: int = 15) -> tuple[bytes, dict[str, str]]:
        req = urllib.request.Request(
            f"{self.api_url}{path}",
            headers={"Authorization": f"Bearer {self._token()}"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.read(), headers

    def reload_local(self) -> None:
        if self.demo:
            return
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.archives_dir.mkdir(parents=True, exist_ok=True)
        conf_path = self.data_dir / "dnsmasq.conf"
        leases_path = self.data_dir / "dnsmasq.leases"
        devices = parse_device_map(
            conf_path.read_text(encoding="utf-8", errors="replace") if conf_path.exists() else "",
            leases_path.read_text(encoding="utf-8", errors="replace") if leases_path.exists() else "",
        )
        events, counters, sources = load_all_logs(self.data_dir)
        with self._lock:
            self.devices = devices
            self.events = events
            self._seen = {e.dedup_key for e in events}
            self.counters = counters
            self.sources = sources

    def _pull_tail_file(self, remote_key: str, local_name: str, max_bytes: int = 1_500_000) -> int:
        off, ino = self._tail_state.get(remote_key, (0, 0))
        q = urllib.parse.urlencode(
            {"file": remote_key, "offset": off, "inode": ino, "max_bytes": max_bytes}
        )
        body, hdrs = self._http_get(f"/api/tail?{q}", timeout=20)
        next_off = int(hdrs.get("x-next-offset", "0") or 0)
        new_ino = int(hdrs.get("x-file-inode", "0") or 0)
        rotated = hdrs.get("x-rotated") == "1"

        local_path = self.data_dir / local_name
        if off == 0 or rotated or not local_path.exists():
            local_path.write_bytes(body)
        elif body:
            with local_path.open("ab") as fh:
                fh.write(body)

        self._tail_state[remote_key] = (next_off, new_ino)
        return len(body)

    def sync_from_router(self) -> dict:
        if self.demo:
            with self._lock:
                self.last_sync_ts = int(time.time())
                self.last_sync_error = None
            return {"status": "ok", "transport": "demo"}

        with self._lock:
            if self.syncing:
                return {"status": "busy"}
            self.syncing = True

        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.archives_dir.mkdir(parents=True, exist_ok=True)

            meta_bytes, _ = self._http_get("/api/meta", timeout=15)
            meta = json.loads(meta_bytes.decode("utf-8", errors="replace"))

            if meta.get("iptables"):
                (self.data_dir / "iptables.txt").write_text(meta["iptables"], encoding="utf-8")
            if meta.get("dnsmasq_conf"):
                (self.data_dir / "dnsmasq.conf").write_text(meta["dnsmasq_conf"], encoding="utf-8")
            if meta.get("leases"):
                (self.data_dir / "dnsmasq.leases").write_text(meta["leases"], encoding="utf-8")

            now_ts = int(time.time())
            new_archives = 0
            for base_name in select_archives_to_download(
                meta.get("archives") or [],
                self.archives_dir,
                retain_days=self.retain_days,
                max_archives=self.max_archives,
                now_ts=now_ts,
            ):
                dst = self.archives_dir / base_name
                q = urllib.parse.urlencode({"name": base_name})
                gz_bytes, _ = self._http_get(f"/api/archive?{q}", timeout=25)
                dst.write_bytes(gz_bytes)
                new_archives += 1

            pruned = prune_local_archives(
                self.archives_dir,
                retain_days=self.retain_days,
                max_archives=self.max_archives,
                now_ts=now_ts,
            )

            self._pull_tail_file("drop", "fw-drop.log")
            self._pull_tail_file("accept", "fw-accept.log", max_bytes=1_000_000)

            self.reload_local()
            with self._lock:
                self.last_sync_ts = int(time.time())
                self.last_sync_error = None
                return {
                    "status": "ok",
                    "transport": "http+sse",
                    "last_sync_ts": self.last_sync_ts,
                    "total_events": len(self.events),
                    "new_archives": new_archives,
                    "pruned_archives": len(pruned),
                    "sources": self.sources,
                }
        except Exception as exc:
            with self._lock:
                self.last_sync_error = str(exc)
            return {"status": "error", "error": str(exc)}
        finally:
            with self._lock:
                self.syncing = False

    def start_background_stream(self) -> None:
        if self.demo:
            return
        t = threading.Thread(target=self._sse_loop, daemon=True)
        t.start()

    def _sse_loop(self) -> None:
        first = True
        while not self._stop_event.is_set():
            if not first:
                self.sync_from_router()
            first = False

            try:
                req = urllib.request.Request(
                    f"{self.api_url}/api/stream?types=drop,accept",
                    headers={"Authorization": f"Bearer {self._token()}"},
                )
                with urllib.request.urlopen(req, timeout=35) as resp:
                    with self._lock:
                        self.stream_connected = True
                        self.last_sync_error = None
                    cur_event = ""
                    for raw_line in resp:
                        if self._stop_event.is_set():
                            break
                        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                        if line.startswith("event: "):
                            cur_event = line[7:].strip()
                        elif line.startswith("data: "):
                            payload = line[6:]
                            local_name = "fw-accept.log" if cur_event == "accept" else "fw-drop.log"
                            key = "accept" if cur_event == "accept" else "drop"
                            with (self.data_dir / local_name).open("a", encoding="utf-8") as fh:
                                fh.write(payload + "\n")
                            off, ino = self._tail_state.get(key, (0, 0))
                            self._tail_state[key] = (off + len((payload + "\n").encode("utf-8")), ino)

                            with self._lock:
                                parsed = parse_lines([payload], self.devices)
                                for ev in parsed:
                                    if ev.dedup_key not in self._seen:
                                        self._seen.add(ev.dedup_key)
                                        self.events.append(ev)
                                if len(self.events) > 25000:
                                    # Keep memory bounded on long runs
                                    self.events = self.events[-20000:]
                                    self._seen = {e.dedup_key for e in self.events}
                                self.last_sync_ts = int(time.time())
            except Exception as exc:
                with self._lock:
                    self.stream_connected = False
                    self.last_sync_error = f"SSE reconnecting: {exc}"
                self._stop_event.wait(3.0)

    def stop(self) -> None:
        self._stop_event.set()

    def query_view(self, params: dict[str, list[str]]) -> dict:
        verdict_filter = params.get("verdict", ["blocked"])[0].strip().lower()
        range_key = params.get("range", ["all"])[0]
        src_filter = params.get("src", [""])[0].strip()
        cat_filter = params.get("category", ["all"])[0].strip().lower()
        proto_filter = params.get("proto", ["all"])[0].strip().upper()
        port_filter = params.get("port", [""])[0].strip()
        search_text = params.get("q", [""])[0].strip().lower()
        hide_stale = params.get("hide_stale", ["0"])[0] in ("1", "true", "yes")
        limit = min(max(int(params.get("limit", ["120"])[0]), 10), 1000)
        offset = max(int(params.get("offset", ["0"])[0]), 0)

        with self._lock:
            all_ev = list(self.events)
            counters = dict(self.counters)
            last_sync_ts = self.last_sync_ts
            last_sync_error = self.last_sync_error
            sources = list(self.sources)
            stream_connected = self.stream_connected

        verdict_totals = Counter(e.verdict for e in all_ev)
        now_ts = int(time.time())
        max_ts = all_ev[-1].ts if all_ev else now_ts
        anchor_ts = max(now_ts, max_ts)

        range_seconds = {
            "15m": 900,
            "1h": 3600,
            "6h": 6 * 3600,
            "24h": 24 * 3600,
            "7d": 7 * 24 * 3600,
            "all": None,
        }.get(range_key, None)

        filtered: list[FirewallEvent] = []
        for ev in all_ev:
            if verdict_filter in ("blocked", "allowed") and ev.verdict != verdict_filter:
                continue
            if range_seconds is not None and ev.ts < anchor_ts - range_seconds:
                continue
            if hide_stale and ev.category == "stale":
                continue
            if src_filter and ev.src_ip != src_filter and ev.src_name != src_filter:
                continue
            if cat_filter not in ("", "all") and ev.category != cat_filter:
                continue
            if proto_filter not in ("", "ALL") and ev.proto.upper() != proto_filter:
                continue
            if port_filter:
                if port_filter.isdigit():
                    if ev.dpt != int(port_filter):
                        continue
                else:
                    if ev.service.lower() != port_filter.lower() and ev.proto.lower() != port_filter.lower():
                        continue
            if search_text:
                hay = (
                    f"{ev.src_ip} {ev.src_name} {ev.dst_ip} {ev.dst_name} {ev.proto} "
                    f"{ev.dpt or ''} {ev.spt or ''} {ev.service} {ev.action} {ev.category} "
                    f"{' '.join(ev.flags)} {ev.in_iface} {ev.out_iface}"
                ).lower()
                if search_text not in hay:
                    continue
            filtered.append(ev)

        total = len(filtered)
        cat_counts = Counter(ev.category for ev in filtered)
        proto_counts = Counter(ev.proto for ev in filtered)

        src_map: dict[str, dict] = {}
        for ev in filtered:
            if not ev.src_ip:
                continue
            rec = src_map.get(ev.src_ip)
            if rec is None:
                rec = {
                    "ip": ev.src_ip, "name": ev.src_name, "count": 0,
                    "probes": 0, "stale": 0, "ports": set(), "protos": set(), "last_seen": ev.ts,
                }
                src_map[ev.src_ip] = rec
            rec["count"] += 1
            if ev.category == "probe":
                rec["probes"] += 1
            if ev.category == "stale":
                rec["stale"] += 1
            if ev.dpt is not None:
                rec["ports"].add(ev.dpt)
            rec["protos"].add(ev.proto)
            if ev.ts > rec["last_seen"]:
                rec["last_seen"] = ev.ts

        top_sources = [
            {
                "ip": r["ip"], "name": r["name"], "count": r["count"],
                "probes": r["probes"], "stale": r["stale"],
                "unique_ports": len(r["ports"]), "protos": sorted(r["protos"]),
                "last_seen": r["last_seen"],
            }
            for r in sorted(src_map.values(), key=lambda x: (-x["count"], x["ip"]))[:15]
        ]

        port_counts: Counter[tuple[str, str, str]] = Counter()
        for ev in filtered:
            key = (str(ev.dpt), ev.service, ev.proto) if ev.dpt is not None else (ev.proto, ev.service, ev.proto)
            port_counts[key] += 1

        top_ports = [
            {"port": p, "service": svc, "proto": pr, "count": c}
            for (p, svc, pr), c in port_counts.most_common(15)
        ]

        span_min = max((filtered[-1].ts - filtered[0].ts) / 60.0, 1.0) if len(filtered) >= 2 else 1.0
        timeline = self._build_timeline(filtered)
        rev = list(reversed(filtered))
        page_rows = [e.to_dict() for e in rev[offset : offset + limit]]

        transport = "Demo Mode" if self.demo else ("SSE Live" if stream_connected else "HTTP")

        return {
            "meta": {
                "router_name": self.router_name,
                "router_host": "demo" if self.demo else self.api_url.replace("http://", ""),
                "transport": transport,
                "stream_connected": stream_connected,
                "last_sync_ts": last_sync_ts,
                "last_sync_error": last_sync_error,
                "sources": sources,
                "total_stored": len(all_ev),
                "blocked_stored": verdict_totals.get("blocked", 0),
                "allowed_stored": verdict_totals.get("allowed", 0),
                "earliest_ts": filtered[0].ts if filtered else None,
                "latest_ts": filtered[-1].ts if filtered else None,
            },
            "kernel_counters": list(counters.values()),
            "summary": {
                "total": total,
                "probe": cat_counts.get("probe", 0),
                "ping": cat_counts.get("ping", 0),
                "stale": cat_counts.get("stale", 0),
                "other": cat_counts.get("other", 0),
                "outbound": cat_counts.get("outbound", 0),
                "local": cat_counts.get("local", 0),
                "unique_sources": len(src_map),
                "unique_targets": len(port_counts),
                "epm": round(total / span_min, 2) if total else 0.0,
            },
            "top_sources": top_sources,
            "top_ports": top_ports,
            "protos": [{"proto": k, "count": v} for k, v in proto_counts.most_common(10)],
            "timeline": timeline,
            "events": {
                "total": total,
                "offset": offset,
                "limit": limit,
                "rows": page_rows,
            },
        }

    @staticmethod
    def _build_timeline(filtered: list[FirewallEvent]) -> list[dict]:
        if not filtered:
            return []
        t_min, t_max = filtered[0].ts, filtered[-1].ts
        span = max(t_max - t_min, 60)
        step = 60 if span <= 1800 else (300 if span <= 6 * 3600 else (1800 if span <= 36 * 3600 else 3600))
        start, end = (t_min // step) * step, (t_max // step) * step
        buckets: dict[int, dict] = {}
        cur = start
        while cur <= end and len(buckets) < 96:
            buckets[cur] = {
                "ts": cur,
                "label": datetime.fromtimestamp(cur).strftime("%m/%d %H:%M" if span > 86400 else "%H:%M"),
                "probe": 0, "ping": 0, "other": 0, "stale": 0, "outbound": 0, "local": 0,
            }
            cur += step
        for ev in filtered:
            b = (ev.ts // step) * step
            if b not in buckets:
                buckets[b] = {
                    "ts": b,
                    "label": datetime.fromtimestamp(b).strftime("%m/%d %H:%M" if span > 86400 else "%H:%M"),
                    "probe": 0, "ping": 0, "other": 0, "stale": 0, "outbound": 0, "local": 0,
                }
            buckets[b][ev.category] = buckets[b].get(ev.category, 0) + 1
        return [buckets[k] for k in sorted(buckets)]

    def export_csv(self, params: dict[str, list[str]]) -> str:
        p = dict(params)
        p["limit"] = ["1000"]
        p["offset"] = ["0"]
        data = self.query_view(p)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "timestamp", "verdict", "action", "category", "in_iface", "out_iface", "proto",
            "src_ip", "src_name", "spt", "dst_ip", "dpt", "service", "flags", "length", "ttl",
        ])
        for r in data["events"]["rows"]:
            writer.writerow([
                r["ts_iso"], r["verdict"], r["action"], r["category"], r["in_iface"], r["out_iface"],
                r["proto"], r["src_ip"], r["src_name"], r["spt"] or "", r["dst_ip"], r["dpt"] or "",
                r["service"], " ".join(r["flags"]), r["length"] or "", r["ttl"] or "",
            ])
        return buf.getvalue()


def make_handler(store: FirewallStore) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:  # noqa: A002
            return

        def _send_json(self, obj: dict, status: int = HTTPStatus.OK) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            params = parse_qs(parsed.query)

            if path == "/api/data":
                self._send_json(store.query_view(params))
                return

            if path == "/api/export.csv":
                csv_bytes = store.export_csv(params).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="router-firewall-logs.csv"')
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return

            rel = "index.html" if path in ("/", "") else path.lstrip("/")
            target = (STATIC_DIR / rel).resolve()
            if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
                self.send_error(HTTPStatus.NOT_FOUND)
                return

            ctype, _ = mimetypes.guess_type(str(target))
            data = target.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", f"{ctype or 'application/octet-stream'}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            if urlparse(self.path).path == "/api/sync":
                res = store.sync_from_router()
                code = HTTPStatus.OK if res.get("status") != "error" else HTTPStatus.BAD_GATEWAY
                self._send_json(res, status=code)
                return
            self.send_error(HTTPStatus.NOT_FOUND)

    return Handler


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def main() -> None:
    ap = argparse.ArgumentParser(description="DD-WRT Router Firewall Log Dashboard (HTTP/SSE)")
    ap.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8788, help="HTTP port (default: 8788)")
    ap.add_argument("--api", default=DEFAULT_ROUTER_API, help="Router nflogd HTTP API URL")
    ap.add_argument("--token-file", default=DEFAULT_TOKEN_FILE, help="Bearer token file path")
    ap.add_argument(
        "--router-name",
        default=DEFAULT_ROUTER_NAME,
        help="Router display name (default: ROUTER_NAME env var or 'DD-WRT Router')",
    )
    ap.add_argument(
        "--retain-days",
        type=_non_negative_int,
        default=DEFAULT_RETAIN_DAYS,
        help="Prune managed local archives older than N days (0 disables; env: RETAIN_DAYS, default: 30)",
    )
    ap.add_argument(
        "--max-archives",
        type=_non_negative_int,
        default=DEFAULT_MAX_ARCHIVES,
        help="Keep at most N newest managed local archives per prefix (0 disables; env: MAX_ARCHIVES, default: 0)",
    )
    ap.add_argument("--no-initial-sync", action="store_true", help="Skip initial sync on startup")
    ap.add_argument("--demo", action="store_true", help="Run with synthetic demo data (no router required)")
    args = ap.parse_args()

    store = FirewallStore(
        args.api,
        args.token_file,
        router_name=args.router_name,
        demo=args.demo,
        retain_days=args.retain_days,
        max_archives=args.max_archives,
    )
    if args.demo:
        print(f"[demo] Loaded {len(store.events)} synthetic firewall events in memory", flush=True)
    else:
        if not args.no_initial_sync:
            print(f"[sync] Pulling firewall logs via HTTP from {args.api} ...", flush=True)
            res = store.sync_from_router()
            if res.get("status") == "ok":
                print(
                    f"[sync] Loaded {res['total_events']} firewall event(s) from {len(res['sources'])} source(s)",
                    flush=True,
                )
            else:
                print(f"[sync] Initial sync warning: {res.get('error')}", flush=True)
        store.start_background_stream()

    server = ThreadingHTTPServer((args.bind, args.port), make_handler(store))
    mode_label = "demo mode" if args.demo else "live SSE active"
    print(
        f"[ready] Firewall Dashboard running at http://{args.bind}:{args.port} ({mode_label})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[stop] Shutting down.", flush=True)
        store.stop()
        server.server_close()


if __name__ == "__main__":
    main()
