#!/usr/bin/env python3
"""Unit tests for Firewall dashboard sync and local archive retention."""

import gzip
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import server


class FirewallServerSyncAndRetentionTests(unittest.TestCase):
    def _make_store(
        self,
        tmp_dir: Path,
        retain_days: int = 30,
        max_archives: int = 0,
    ) -> server.FirewallStore:
        token = tmp_dir / "nflogd.token"
        token.write_text("test-token\n", encoding="utf-8")
        return server.FirewallStore(
            api_url="http://127.0.0.1:8789",
            token_file=str(token),
            router_name="TestRouter",
            demo=False,
            retain_days=retain_days,
            max_archives=max_archives,
            data_dir=tmp_dir / "data",
        )

    def test_first_sync_tolerates_null_and_empty_archives(self) -> None:
        drop_log = (
            "Nov 22 03:00:01 router kern.info kernel: [10.000000] DROP "
            "IN=wan OUT= SRC=198.51.100.20 DST=203.0.113.10 LEN=60 TTL=54 "
            "ID=1001 PROTO=TCP SPT=51234 DPT=3389 SYN\n"
        ).encode("utf-8")
        accept_log = (
            "Nov 22 03:00:02 router kern.info kernel: [11.000000] ACCEPT "
            "IN=br0 OUT=wan SRC=192.168.1.10 DST=140.82.114.6 LEN=60 TTL=63 "
            "ID=1002 PROTO=TCP SPT=52000 DPT=443 SYN\n"
        ).encode("utf-8")

        for archives_value in (None, []):
            with self.subTest(archives=archives_value):
                with tempfile.TemporaryDirectory() as td:
                    store = self._make_store(Path(td))
                    meta_payload = json.dumps(
                        {
                            "iptables": "",
                            "dnsmasq_conf": "dhcp-host=aa:bb:cc:dd:ee:ff,workstation,192.168.1.10\n",
                            "leases": "",
                            "archives": archives_value,
                        }
                    ).encode("utf-8")

                    def fake_http_get(path: str, timeout: int = 15):
                        if path == "/api/meta":
                            return meta_payload, {}
                        if path.startswith("/api/tail?file=drop&"):
                            return drop_log, {
                                "x-next-offset": str(len(drop_log)),
                                "x-file-inode": "201",
                            }
                        if path.startswith("/api/tail?file=accept&"):
                            return accept_log, {
                                "x-next-offset": str(len(accept_log)),
                                "x-file-inode": "202",
                            }
                        raise AssertionError(f"Unexpected HTTP path: {path}")

                    with mock.patch.object(store, "_http_get", side_effect=fake_http_get):
                        res = store.sync_from_router()

                    self.assertEqual(res["status"], "ok")
                    self.assertEqual(res["new_archives"], 0)
                    self.assertEqual(res["total_events"], 2)
                    verdicts = {e.verdict for e in store.events}
                    self.assertEqual(verdicts, {"blocked", "allowed"})

    def test_prune_local_archives_per_prefix_and_preserves_unrelated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            archives_dir = Path(td) / "archives"
            archives_dir.mkdir(parents=True)

            now = datetime(2026, 11, 22, 12, 0, 0)
            expired_drop = f"fw-drop-{(now - timedelta(days=40)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            mid_drop = f"fw-drop-{(now - timedelta(days=5)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            new_drop = f"fw-drop-{(now - timedelta(days=1)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            new_accept = f"fw-accept-{(now - timedelta(days=2)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            new_syslog = f"syslog-{(now - timedelta(days=2)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            dns_archive = f"dns-{(now - timedelta(days=90)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            unrelated = "custom-export.csv"

            for fname in (
                expired_drop,
                mid_drop,
                new_drop,
                new_accept,
                new_syslog,
                dns_archive,
                unrelated,
            ):
                (archives_dir / fname).write_bytes(b"data")

            deleted = server.prune_local_archives(
                archives_dir,
                retain_days=30,
                max_archives=1,
                now_ts=int(now.timestamp()),
            )

            self.assertEqual(deleted, sorted([expired_drop, mid_drop]))
            self.assertFalse((archives_dir / expired_drop).exists())
            self.assertFalse((archives_dir / mid_drop).exists())
            self.assertTrue((archives_dir / new_drop).exists())
            self.assertTrue((archives_dir / new_accept).exists())
            self.assertTrue((archives_dir / new_syslog).exists())
            self.assertTrue((archives_dir / dns_archive).exists())
            self.assertTrue((archives_dir / unrelated).exists())

    def test_sync_skips_expired_router_archives_and_prunes_local(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = self._make_store(Path(td), retain_days=7, max_archives=0)
            store.archives_dir.mkdir(parents=True, exist_ok=True)

            now = datetime.now()
            expired_local = f"fw-drop-{(now - timedelta(days=20)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            expired_remote = f"fw-drop-{(now - timedelta(days=15)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            recent_remote = f"fw-drop-{(now - timedelta(days=1)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            keep_unrelated = store.archives_dir / "keep-me.txt"

            (store.archives_dir / expired_local).write_bytes(gzip.compress(b""))
            keep_unrelated.write_text("do not delete", encoding="utf-8")

            archive_payload = gzip.compress(
                b"Nov 21 03:00:01 router kern.info kernel: [1.0] DROP "
                b"IN=wan OUT= SRC=198.51.100.30 DST=203.0.113.10 LEN=40 TTL=55 "
                b"ID=101 PROTO=TCP SPT=40000 DPT=22 SYN\n"
            )
            meta_payload = json.dumps(
                {
                    "iptables": "",
                    "dnsmasq_conf": "",
                    "leases": "",
                    "archives": [expired_remote, recent_remote],
                }
            ).encode("utf-8")

            requested_paths: list[str] = []

            def fake_http_get(path: str, timeout: int = 15):
                requested_paths.append(path)
                if path == "/api/meta":
                    return meta_payload, {}
                if path == f"/api/archive?name={recent_remote}":
                    return archive_payload, {}
                if path.startswith("/api/tail?"):
                    return b"", {"x-next-offset": "0", "x-file-inode": "1"}
                raise AssertionError(f"Unexpected HTTP path: {path}")

            with mock.patch.object(store, "_http_get", side_effect=fake_http_get):
                res = store.sync_from_router()

            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["new_archives"], 1)
            self.assertEqual(res["pruned_archives"], 1)
            self.assertNotIn(f"/api/archive?name={expired_remote}", requested_paths)
            self.assertFalse((store.archives_dir / expired_local).exists())
            self.assertTrue((store.archives_dir / recent_remote).exists())
            self.assertTrue(keep_unrelated.exists())


if __name__ == "__main__":
    unittest.main()
