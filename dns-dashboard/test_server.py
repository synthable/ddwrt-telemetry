#!/usr/bin/env python3
"""Unit tests for DNS dashboard sync and local archive retention."""

import gzip
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import server


class DnsServerSyncAndRetentionTests(unittest.TestCase):
    def _make_store(
        self,
        tmp_dir: Path,
        retain_days: int = 30,
        max_archives: int = 0,
    ) -> server.DashboardStore:
        token = tmp_dir / "nflogd.token"
        token.write_text("test-token\n", encoding="utf-8")
        return server.DashboardStore(
            api_url="http://127.0.0.1:8789",
            token_file=str(token),
            router_name="TestRouter",
            demo=False,
            retain_days=retain_days,
            max_archives=max_archives,
            data_dir=tmp_dir / "data",
        )

    def test_first_sync_tolerates_null_and_empty_archives(self) -> None:
        live_log = (
            "Nov 22 03:00:01 dnsmasq[1234]: query[A] api.github.com from 192.168.1.10\n"
            "Nov 22 03:00:01 dnsmasq[1234]: forwarded api.github.com to 94.140.14.14\n"
            "Nov 22 03:00:01 dnsmasq[1234]: reply api.github.com is 140.82.114.6\n"
        ).encode("utf-8")

        for archives_value in (None, []):
            with self.subTest(archives=archives_value):
                with tempfile.TemporaryDirectory() as td:
                    store = self._make_store(Path(td))
                    meta_payload = json.dumps(
                        {
                            "dnsmasq_conf": "dhcp-host=aa:bb:cc:dd:ee:ff,workstation,192.168.1.10\n",
                            "leases": "",
                            "archives": archives_value,
                        }
                    ).encode("utf-8")

                    def fake_http_get(path: str, timeout: int = 15):
                        if path == "/api/meta":
                            return meta_payload, {}
                        if path.startswith("/api/tail?file=dns&"):
                            return live_log, {
                                "x-next-offset": str(len(live_log)),
                                "x-file-inode": "101",
                            }
                        if path.startswith("/api/tail?file=dns_prev"):
                            return b"", {"x-next-offset": "0", "x-file-inode": "0"}
                        raise AssertionError(f"Unexpected HTTP path: {path}")

                    with mock.patch.object(store, "_http_get", side_effect=fake_http_get):
                        res = store.sync_from_router()

                    self.assertEqual(res["status"], "ok")
                    self.assertEqual(res["new_archives"], 0)
                    self.assertEqual(res["total_queries"], 1)
                    self.assertEqual(store.queries[0].domain, "api.github.com")
                    self.assertEqual(store.queries[0].client_name, "workstation")

    def test_prune_local_archives_removes_expired_and_preserves_recent_and_unrelated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            archives_dir = Path(td) / "archives"
            archives_dir.mkdir(parents=True)

            now = datetime(2026, 11, 22, 12, 0, 0)
            old_name = f"dns-{(now - timedelta(days=45)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            mid_name = f"dns-{(now - timedelta(days=10)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            new_name = f"dns-{(now - timedelta(days=1)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            unrelated_txt = "notes.txt"
            unrelated_gz = "manual-backup.log.gz"
            other_prefix = f"fw-drop-{(now - timedelta(days=60)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            subdir = archives_dir / "dns-20200101-000000.log.gz"
            subdir.mkdir()

            for fname in (old_name, mid_name, new_name, unrelated_txt, unrelated_gz, other_prefix):
                (archives_dir / fname).write_bytes(b"data")

            deleted = server.prune_local_archives(
                archives_dir,
                retain_days=30,
                max_archives=1,
                now_ts=int(now.timestamp()),
            )

            self.assertEqual(deleted, sorted([old_name, mid_name]))
            self.assertFalse((archives_dir / old_name).exists())
            self.assertFalse((archives_dir / mid_name).exists())
            self.assertTrue((archives_dir / new_name).exists())
            self.assertTrue((archives_dir / unrelated_txt).exists())
            self.assertTrue((archives_dir / unrelated_gz).exists())
            self.assertTrue((archives_dir / other_prefix).exists())
            self.assertTrue(subdir.is_dir())

    def test_sync_skips_expired_router_archives_and_prunes_local(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = self._make_store(Path(td), retain_days=7, max_archives=0)
            store.archives_dir.mkdir(parents=True, exist_ok=True)

            now = datetime.now()
            expired_local = f"dns-{(now - timedelta(days=20)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            expired_remote = f"dns-{(now - timedelta(days=15)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            recent_remote = f"dns-{(now - timedelta(days=1)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            keep_unrelated = store.archives_dir / "keep-me.txt"

            (store.archives_dir / expired_local).write_bytes(gzip.compress(b""))
            keep_unrelated.write_text("do not delete", encoding="utf-8")

            archive_payload = gzip.compress(
                b"Nov 21 03:00:01 dnsmasq[1234]: query[A] archived.example.com from 192.168.1.10\n"
                b"Nov 21 03:00:01 dnsmasq[1234]: reply archived.example.com is 198.51.100.1\n"
            )
            meta_payload = json.dumps(
                {
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

    def test_sync_applies_max_archives_before_downloading(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = self._make_store(Path(td), retain_days=30, max_archives=1)
            now = datetime.now()
            older_remote = f"dns-{(now - timedelta(days=2)).strftime('%Y%m%d-%H%M%S')}.log.gz"
            newer_remote = f"dns-{(now - timedelta(days=1)).strftime('%Y%m%d-%H%M%S')}.log.gz"

            archive_payload = gzip.compress(
                b"Nov 21 03:00:01 dnsmasq[1234]: query[A] latest.example.com from 192.168.1.10\n"
                b"Nov 21 03:00:01 dnsmasq[1234]: reply latest.example.com is 198.51.100.2\n"
            )
            meta_payload = json.dumps(
                {
                    "dnsmasq_conf": "",
                    "leases": "",
                    "archives": [older_remote, newer_remote],
                }
            ).encode("utf-8")

            requested_archives: list[str] = []

            def fake_http_get(path: str, timeout: int = 15):
                if path == "/api/meta":
                    return meta_payload, {}
                if path.startswith("/api/archive?"):
                    requested_archives.append(path)
                    return archive_payload, {}
                if path.startswith("/api/tail?"):
                    return b"", {"x-next-offset": "0", "x-file-inode": "1"}
                raise AssertionError(f"Unexpected HTTP path: {path}")

            with mock.patch.object(store, "_http_get", side_effect=fake_http_get):
                res1 = store.sync_from_router()
                res2 = store.sync_from_router()

            self.assertEqual(res1["status"], "ok")
            self.assertEqual(res1["new_archives"], 1)
            self.assertEqual(res2["status"], "ok")
            self.assertEqual(res2["new_archives"], 0)
            self.assertEqual(requested_archives, [f"/api/archive?name={newer_remote}"])
            self.assertFalse((store.archives_dir / older_remote).exists())
            self.assertTrue((store.archives_dir / newer_remote).exists())


if __name__ == "__main__":
    unittest.main()
