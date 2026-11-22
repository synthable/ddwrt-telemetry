#!/usr/bin/env python3
"""Local HTTP server with real-time router HTTP/SSE ingestion for DNS Dashboard."""

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

from parser import DnsQuery, load_all_logs

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

MANAGED_ARCHIVE_RE = re.compile(r"^(dns)-(\d{8})-(\d{6})\.log\.gz$")


def parse_archive_entry(name: str) -> tuple[str, int] | None:
    """Return (prefix, unix_ts) for a managed DNS archive filename, or None."""
    m = MANAGED_ARCHIVE_RE.match(name)
    if not m:
        return None
    try:
        dt = datetime.strptime(f"{m.group(2)}-{m.group(3)}", "%Y%m%d-%H%M%S")
    except ValueError:
        return None
    return m.group(1), int(dt.timestamp())


def prune_local_archives(
    archives_dir: Path,
    retain_days: int = DEFAULT_RETAIN_DAYS,
    max_archives: int = DEFAULT_MAX_ARCHIVES,
    now_ts: int | None = None,
) -> list[str]:
    """Prune expired or excess managed DNS archives while preserving unrelated files."""
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


def generate_demo_dns_data(now_ts: int | None = None) -> tuple[list[DnsQuery], dict[str, str]]:
    """Generate ~450 realistic synthetic DNS queries spanning the last ~6 hours."""
    rng = random.Random(42)
    end_ts = int(time.time()) if now_ts is None else now_ts
    span_sec = 6 * 3600
    start_ts = end_ts - span_sec

    devices = {
        "192.168.1.1": "router",
        "192.168.1.10": "workstation",
        "192.168.1.22": "phone",
        "192.168.1.35": "smart-tv",
        "192.168.1.48": "smart-speaker",
        "192.168.1.64": "tablet",
    }
    device_weights = [
        ("192.168.1.10", 0.30),
        ("192.168.1.22", 0.24),
        ("192.168.1.35", 0.18),
        ("192.168.1.64", 0.12),
        ("192.168.1.48", 0.10),
        ("192.168.1.1", 0.06),
    ]
    dev_ips = [d[0] for d in device_weights]
    dev_probs = [d[1] for d in device_weights]

    allowed_domains = [
        ("api.github.com", "140.82.114.6", "2606:50c0:8000::154"),
        ("cloudflare.com", "104.16.133.229", "2606:4700::6810:85e5"),
        ("cdn.jsdelivr.net", "104.16.85.20", "2606:4700::6810:5514"),
        ("www.wikipedia.org", "198.35.26.96", "2620:0:863:ed1a::1"),
        ("play.googleapis.com", "142.250.191.238", "2607:f8b0:4005:812::200e"),
        ("gateway.icloud.com", "17.248.192.44", "2620:149:a44:200::8"),
        ("s3.amazonaws.com", "52.217.139.8", "2600:1fa0:4000::12"),
        ("stream.media.example.net", "198.51.100.42", "2001:db8:10::42"),
        ("time.cloudflare.com", "162.159.200.1", "2606:4700:f1::1"),
        ("updates.cdn.example.org", "203.0.113.88", "2001:db8:20::88"),
        ("news.ycombinator.com", "209.216.230.207", "2001:db8:30::207"),
        ("registry.npmjs.org", "104.16.25.34", "2606:4700::6810:1922"),
        ("connectivitycheck.gstatic.com", "142.250.189.227", "2607:f8b0:4005:80b::2003"),
        ("push.services.mozilla.com", "34.149.100.209", "2001:db8:40::209"),
    ]

    blocked_domains = [
        "ads.doubleclick.net",
        "pagead2.googlesyndication.com",
        "app-measurement.com",
        "metrics.smart-tv.example",
        "telemetry.vendor.example",
        "pixel.adnetwork.example",
        "analytics.smetrics.example",
        "events.data.tracker.example",
        "adservice.google.com",
        "beacon.tracking.example",
    ]

    nxdomain_domains = [
        "wpad.lan",
        "printer-legacy.local",
        "old-nas.home.arpa",
        "10.113.0.203.in-addr.arpa",
        "42.100.51.198.in-addr.arpa",
        "229.133.16.104.in-addr.arpa",
    ]

    ptr_domains = [
        ("1.1.168.192.in-addr.arpa", "router.lan"),
        ("10.1.168.192.in-addr.arpa", "workstation.lan"),
        ("22.1.168.192.in-addr.arpa", "phone.lan"),
        ("1.1.1.1.in-addr.arpa", "one.one.one.one"),
    ]

    upstreams = ["94.140.14.14", "94.140.15.15"]
    queries: list[DnsQuery] = []

    for _ in range(450):
        # Slightly busier in the most recent 2 hours
        u = rng.random()
        if u < 0.45:
            ts = end_ts - rng.randint(0, 7200)
        else:
            ts = rng.randint(start_ts, end_ts)
        ts_iso = datetime.fromtimestamp(ts).isoformat()

        client_ip = rng.choices(dev_ips, weights=dev_probs, k=1)[0]
        client_name = devices[client_ip]

        roll = rng.random()
        if roll < 0.23:
            # AdGuard Blocked (0.0.0.0 / ::)
            domain = rng.choice(blocked_domains)
            qtype = rng.choices(["A", "AAAA", "HTTPS"], weights=[0.6, 0.3, 0.1], k=1)[0]
            cached = rng.random() < 0.35
            ans = "::" if qtype == "AAAA" else "0.0.0.0"
            queries.append(
                DnsQuery(
                    ts=ts,
                    ts_iso=ts_iso,
                    client_ip=client_ip,
                    client_name=client_name,
                    qtype=qtype,
                    domain=domain,
                    status="blocked",
                    cached=cached,
                    upstream="cache" if cached else rng.choice(upstreams),
                    answers=[ans],
                )
            )
        elif roll < 0.30:
            # NXDOMAIN (includes PTR misses)
            domain = rng.choice(nxdomain_domains)
            qtype = "PTR" if domain.endswith(".in-addr.arpa") else rng.choice(["A", "AAAA"])
            queries.append(
                DnsQuery(
                    ts=ts,
                    ts_iso=ts_iso,
                    client_ip=client_ip,
                    client_name=client_name,
                    qtype=qtype,
                    domain=domain,
                    status="nxdomain",
                    cached=False,
                    upstream=rng.choice(upstreams),
                    answers=["NXDOMAIN"],
                )
            )
        elif roll < 0.36:
            # Successful PTR lookups
            domain, target = rng.choice(ptr_domains)
            cached = rng.random() < 0.65
            queries.append(
                DnsQuery(
                    ts=ts,
                    ts_iso=ts_iso,
                    client_ip=client_ip,
                    client_name=client_name,
                    qtype="PTR",
                    domain=domain,
                    status="cached" if cached else "allowed",
                    cached=cached,
                    upstream="cache" if cached else rng.choice(upstreams),
                    answers=[target],
                )
            )
        else:
            # Allowed or Cached normal traffic across A, AAAA, HTTPS
            domain, v4, v6 = rng.choice(allowed_domains)
            qtype = rng.choices(["A", "AAAA", "HTTPS"], weights=[0.52, 0.30, 0.18], k=1)[0]
            cached = rng.random() < 0.48
            ans = v4 if qtype == "A" else (v6 if qtype == "AAAA" else "<HTTPS>")
            queries.append(
                DnsQuery(
                    ts=ts,
                    ts_iso=ts_iso,
                    client_ip=client_ip,
                    client_name=client_name,
                    qtype=qtype,
                    domain=domain,
                    status="cached" if cached else "allowed",
                    cached=cached,
                    upstream="cache" if cached else rng.choice(upstreams),
                    answers=[ans],
                )
            )

    queries.sort(key=lambda q: q.ts)
    return queries, devices


class DashboardStore:
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
        self.queries: list[DnsQuery] = []
        self.devices: dict[str, str] = {}
        self.sources: list[str] = []
        self.last_sync_ts: int | None = None
        self.last_sync_error: str | None = None
        self.syncing: bool = False
        self.stream_connected: bool = False
        self._tail_state: dict[str, tuple[int, int]] = {}  # key -> (offset, inode)
        self._stop_event = threading.Event()
        self._dirty = False
        if self.demo:
            self._load_demo_data()
        else:
            self.reload_local()

    def _load_demo_data(self) -> None:
        now_ts = int(time.time())
        queries, devices = generate_demo_dns_data(now_ts)
        with self._lock:
            self.queries = queries
            self.devices = devices
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
        queries, devices, sources = load_all_logs(self.data_dir)
        with self._lock:
            self.queries = queries
            self.devices = devices
            self.sources = sources

    def _pull_tail_file(self, remote_key: str, local_name: str) -> int:
        off, ino = self._tail_state.get(remote_key, (0, 0))
        q = urllib.parse.urlencode({"file": remote_key, "offset": off, "inode": ino})
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

            if meta.get("dnsmasq_conf"):
                (self.data_dir / "dnsmasq.conf").write_text(meta["dnsmasq_conf"], encoding="utf-8")
            if meta.get("leases"):
                (self.data_dir / "dnsmasq.leases").write_text(meta["leases"], encoding="utf-8")

            # Download any new DNS archives within local retention policy
            now_ts = int(time.time())
            cutoff = now_ts - self.retain_days * 86400 if self.retain_days > 0 else None
            new_archives = 0
            for name in meta.get("archives") or []:
                if not isinstance(name, str):
                    continue
                base_name = Path(name).name
                parsed = parse_archive_entry(base_name)
                if parsed is None:
                    continue
                if cutoff is not None and parsed[1] < cutoff:
                    continue
                dst = self.archives_dir / base_name
                if dst.exists():
                    continue
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

            # Incremental tail of live dns.log (and .prev if present)
            self._pull_tail_file("dns", "dns.log")
            prev_bytes, _ = self._http_get("/api/tail?file=dns_prev&offset=0", timeout=15)
            prev_path = self.data_dir / "dns.log.prev"
            if prev_bytes:
                prev_path.write_bytes(prev_bytes)
            elif prev_path.exists():
                prev_path.unlink()

            self.reload_local()
            with self._lock:
                self.last_sync_ts = int(time.time())
                self.last_sync_error = None
                return {
                    "status": "ok",
                    "transport": "http+sse",
                    "last_sync_ts": self.last_sync_ts,
                    "total_queries": len(self.queries),
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
        t_sse = threading.Thread(target=self._sse_loop, daemon=True)
        t_sse.start()
        t_reload = threading.Thread(target=self._reload_debounce_loop, daemon=True)
        t_reload.start()

    def _reload_debounce_loop(self) -> None:
        while not self._stop_event.wait(1.0):
            if self._dirty:
                self._dirty = False
                self.reload_local()
                with self._lock:
                    self.last_sync_ts = int(time.time())

    def _sse_loop(self) -> None:
        first = True
        while not self._stop_event.is_set():
            if not first:
                # Re-sync deltas & archives after reconnect/sleep
                self.sync_from_router()
            first = False

            try:
                req = urllib.request.Request(
                    f"{self.api_url}/api/stream?types=dns",
                    headers={"Authorization": f"Bearer {self._token()}"},
                )
                with urllib.request.urlopen(req, timeout=35) as resp:
                    with self._lock:
                        self.stream_connected = True
                        self.last_sync_error = None
                    live_path = self.data_dir / "dns.log"
                    for raw_line in resp:
                        if self._stop_event.is_set():
                            break
                        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                        if line.startswith("data: "):
                            payload = line[6:] + "\n"
                            with live_path.open("a", encoding="utf-8") as fh:
                                fh.write(payload)
                            off, ino = self._tail_state.get("dns", (0, 0))
                            self._tail_state["dns"] = (off + len(payload.encode("utf-8")), ino)
                            self._dirty = True
            except Exception as exc:
                with self._lock:
                    self.stream_connected = False
                    self.last_sync_error = f"SSE reconnecting: {exc}"
                self._stop_event.wait(3.0)

    def stop(self) -> None:
        self._stop_event.set()

    def query_view(self, params: dict[str, list[str]]) -> dict:
        range_key = params.get("range", ["all"])[0]
        client_filter = params.get("client", [""])[0].strip()
        status_filter = params.get("status", ["all"])[0].strip().lower()
        qtype_filter = params.get("qtype", ["all"])[0].strip().upper()
        search_text = params.get("q", [""])[0].strip().lower()
        hide_ptr = params.get("hide_ptr", ["0"])[0] in ("1", "true", "yes")
        limit = min(max(int(params.get("limit", ["150"])[0]), 10), 1000)
        offset = max(int(params.get("offset", ["0"])[0]), 0)

        with self._lock:
            all_q = list(self.queries)
            devices_map = dict(self.devices)
            last_sync_ts = self.last_sync_ts
            last_sync_error = self.last_sync_error
            sources = list(self.sources)
            stream_connected = self.stream_connected

        now_ts = int(time.time())
        max_ts = all_q[-1].ts if all_q else now_ts
        anchor_ts = max(now_ts, max_ts)

        range_seconds = {
            "15m": 900,
            "1h": 3600,
            "6h": 6 * 3600,
            "24h": 24 * 3600,
            "7d": 7 * 24 * 3600,
            "all": None,
        }.get(range_key, None)

        base_q: list[DnsQuery] = []
        for q in all_q:
            if range_seconds is not None and q.ts < anchor_ts - range_seconds:
                continue
            if hide_ptr and q.qtype == "PTR":
                continue
            base_q.append(q)

        dev_stats: dict[str, dict] = {}
        for q in base_q:
            ds = dev_stats.get(q.client_ip)
            if ds is None:
                ds = {
                    "ip": q.client_ip,
                    "name": q.client_name,
                    "total": 0,
                    "blocked": 0,
                    "cached": 0,
                    "nxdomain": 0,
                    "allowed": 0,
                    "last_seen": q.ts,
                }
                dev_stats[q.client_ip] = ds
            ds["total"] += 1
            ds[q.status] = ds.get(q.status, 0) + 1
            if q.ts > ds["last_seen"]:
                ds["last_seen"] = q.ts

        for ip, name in devices_map.items():
            if ip == "127.0.0.1":
                continue
            if ip not in dev_stats:
                dev_stats[ip] = {
                    "ip": ip,
                    "name": name,
                    "total": 0,
                    "blocked": 0,
                    "cached": 0,
                    "nxdomain": 0,
                    "allowed": 0,
                    "last_seen": 0,
                }

        device_list = sorted(
            dev_stats.values(), key=lambda d: (-d["total"], d["name"].lower())
        )

        filtered: list[DnsQuery] = []
        for q in base_q:
            if client_filter and q.client_ip != client_filter and q.client_name != client_filter:
                continue
            if status_filter not in ("", "all") and q.status != status_filter:
                continue
            if qtype_filter not in ("", "ALL") and q.qtype.upper() != qtype_filter:
                continue
            if search_text:
                hay = f"{q.domain} {q.client_name} {q.client_ip} {' '.join(q.answers)}".lower()
                if search_text not in hay:
                    continue
            filtered.append(q)

        total = len(filtered)
        status_counts = Counter(q.status for q in filtered)
        qtype_counts = Counter(q.qtype for q in filtered)
        top_domains = Counter(q.domain for q in filtered).most_common(15)
        top_blocked = Counter(q.domain for q in filtered if q.status == "blocked").most_common(15)
        top_nxdomain = Counter(q.domain for q in filtered if q.status == "nxdomain").most_common(10)

        timeline = self._build_timeline(filtered)
        span_min = max((filtered[-1].ts - filtered[0].ts) / 60.0, 1.0) if len(filtered) >= 2 else 1.0

        rev = list(reversed(filtered))
        page_rows = [q.to_dict() for q in rev[offset : offset + limit]]

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
                "total_stored": len(all_q),
                "earliest_ts": all_q[0].ts if all_q else None,
                "latest_ts": all_q[-1].ts if all_q else None,
            },
            "summary": {
                "total": total,
                "allowed": status_counts.get("allowed", 0),
                "cached": status_counts.get("cached", 0),
                "blocked": status_counts.get("blocked", 0),
                "nxdomain": status_counts.get("nxdomain", 0),
                "qpm": round(total / span_min, 1) if total else 0.0,
                "active_clients": sum(1 for d in device_list if d["total"] > 0),
            },
            "devices": device_list,
            "qtypes": [{"type": k, "count": v} for k, v in qtype_counts.most_common(12)],
            "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
            "top_blocked": [{"domain": d, "count": c} for d, c in top_blocked],
            "top_nxdomain": [{"domain": d, "count": c} for d, c in top_nxdomain],
            "timeline": timeline,
            "queries": {
                "total": total,
                "offset": offset,
                "limit": limit,
                "rows": page_rows,
            },
        }

    @staticmethod
    def _build_timeline(filtered: list[DnsQuery]) -> list[dict]:
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
                "allowed": 0, "cached": 0, "blocked": 0, "nxdomain": 0,
            }
            cur += step
        for q in filtered:
            b = (q.ts // step) * step
            if b not in buckets:
                buckets[b] = {
                    "ts": b,
                    "label": datetime.fromtimestamp(b).strftime("%m/%d %H:%M" if span > 86400 else "%H:%M"),
                    "allowed": 0, "cached": 0, "blocked": 0, "nxdomain": 0,
                }
            buckets[b][q.status] = buckets[b].get(q.status, 0) + 1
        return [buckets[k] for k in sorted(buckets)]

    def export_csv(self, params: dict[str, list[str]]) -> str:
        p = dict(params)
        p["limit"] = ["1000"]
        p["offset"] = ["0"]
        data = self.query_view(p)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["timestamp", "device", "client_ip", "type", "domain", "status", "upstream", "answers"])
        for row in data["queries"]["rows"]:
            writer.writerow([
                row["ts_iso"], row["client_name"], row["client_ip"], row["qtype"],
                row["domain"], row["status"], row["upstream"], "; ".join(row["answers"]),
            ])
        return buf.getvalue()


def make_handler(store: DashboardStore) -> type[BaseHTTPRequestHandler]:
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
                self.send_header("Content-Disposition", 'attachment; filename="router-dns-queries.csv"')
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
                result = store.sync_from_router()
                code = HTTPStatus.OK if result.get("status") != "error" else HTTPStatus.BAD_GATEWAY
                self._send_json(result, status=code)
                return
            self.send_error(HTTPStatus.NOT_FOUND)

    return Handler


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def main() -> None:
    ap = argparse.ArgumentParser(description="DD-WRT Router DNS Dashboard (HTTP/SSE)")
    ap.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8787, help="HTTP port (default: 8787)")
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

    store = DashboardStore(
        args.api,
        args.token_file,
        router_name=args.router_name,
        demo=args.demo,
        retain_days=args.retain_days,
        max_archives=args.max_archives,
    )
    if args.demo:
        print(f"[demo] Loaded {len(store.queries)} synthetic DNS queries in memory", flush=True)
    else:
        if not args.no_initial_sync:
            print(f"[sync] Pulling logs via HTTP from {args.api} ...", flush=True)
            res = store.sync_from_router()
            if res.get("status") == "ok":
                print(
                    f"[sync] Loaded {res['total_queries']} queries from {len(res['sources'])} source(s)",
                    flush=True,
                )
            else:
                print(f"[sync] Initial sync warning: {res.get('error')}", flush=True)
        store.start_background_stream()

    server = ThreadingHTTPServer((args.bind, args.port), make_handler(store))
    mode_label = "demo mode" if args.demo else "live SSE active"
    print(f"[ready] DNS Dashboard running at http://{args.bind}:{args.port} ({mode_label})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[stop] Shutting down.", flush=True)
        store.stop()
        server.server_close()


if __name__ == "__main__":
    main()
