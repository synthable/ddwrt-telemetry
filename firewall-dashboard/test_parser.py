"""Unit tests for DD-WRT firewall log parser & classifier."""

import unittest
from parser import parse_iptables_counters, parse_lines

SAMPLE_LINES = """
Nov 21 23:44:27.030 router kern.warn kernel: [593152.396081] DROP IN=wan OUT= MAC=aa:bb SRC=198.51.100.94 DST=203.0.113.10 LEN=68 TOS=0x00 PREC=0x40 TTL=242 ID=54321 PROTO=4 MARK=0x100000
Nov 21 23:46:23.889 router kern.warn kernel: [593269.243374] DROP IN=wan OUT= MAC=aa:bb SRC=198.51.100.4 DST=203.0.113.10 LEN=94 TOS=0x00 PREC=0x40 TTL=52 ID=0 DF PROTO=UDP SPT=443 DPT=37409 LEN=74 MARK=0x100000
Nov 21 23:47:13.400 router kern.warn kernel: [593318.774480] DROP IN=wan OUT= MAC=aa:bb SRC=192.0.2.59 DST=203.0.113.10 LEN=42 TOS=0x00 PREC=0x40 TTL=51 ID=52312 DF PROTO=UDP SPT=31395 DPT=11211 LEN=22 MARK=0x100000
Nov 21 23:57:36.750 router kern.warn kernel: [593942.116116] DROP IN=wan OUT= MAC=aa:bb SRC=192.0.2.89 DST=203.0.113.10 LEN=564 TOS=0x00 PREC=0x20 TTL=37 ID=30199 DF PROTO=47 MARK=0x100000
Nov 21 23:59:17.700 router kern.warn kernel: [594043.070817] DROP IN=wan OUT= MAC=aa:bb SRC=198.51.100.127 DST=203.0.113.10 LEN=40 TOS=0x00 PREC=0x20 TTL=240 ID=0 DF PROTO=TCP SPT=443 DPT=44690 SEQ=986344344 ACK=0 WINDOW=0 RES=0x00 RST URGP=0
Nov 21 23:10:08.310 router kern.warn kernel: [591093.678070] DROP IN=wan OUT= MAC=aa:bb SRC=192.0.2.194 DST=192.168.1.1 LEN=48 TOS=0x00 PREC=0x40 TTL=232 ID=54321 PROTO=ICMP TYPE=8 CODE=0 ID=20983 SEQ=99 MARK=0x100000
Nov 22 00:23:57.987 router kern.info kernel: [1795335837.987176] ACCEPT IN=br0 OUT=wan SRC=192.168.1.60 DST=203.0.113.44 LEN=1228 TTL=63 ID=0 PROTO=UDP SPT=53088 DPT=443 LEN=1208
Nov 21 23:16:34.627 router authpriv.notice dropbear[3391]: Pubkey auth succeeded for 'root'
""".strip().splitlines()

SAMPLE_IPTABLES = """
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
  309 14352 DROP       tcp  --  wan    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:2222
 1949  103K DROP       tcp  --  wan    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
 3625  193K logdrop    all  --  wan    *       0.0.0.0/0            0.0.0.0/0            -m psd --psd-weight-threshold 15
 5118  239K logdrop    all  --  *      *       0.0.0.0/0            0.0.0.0/0            state INVALID
 1980 85164 logdrop    icmp --  wan    *       0.0.0.0/0            0.0.0.0/0
Chain tarpit (5 references)
 129K 6519K DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0
""".strip()


class TestFirewallParser(unittest.TestCase):
    def test_parse_and_classify(self) -> None:
        evs = parse_lines(SAMPLE_LINES, {"192.168.1.60": "laptop"}, ref_year=2026, ref_month=11)
        self.assertEqual(len(evs), 7)

        # PROTO=4 IP-in-IP probe
        self.assertEqual(evs[0].proto, "IP-in-IP")
        self.assertEqual(evs[0].category, "probe")

        # Late QUIC UDP SPT=443 -> stale
        self.assertEqual(evs[1].proto, "UDP")
        self.assertEqual(evs[1].category, "stale")

        # Memcached port 11211 -> probe
        self.assertEqual(evs[2].dpt, 11211)
        self.assertEqual(evs[2].service, "Memcached")
        self.assertEqual(evs[2].category, "probe")

        # PROTO=47 GRE -> probe
        self.assertEqual(evs[3].proto, "GRE")
        self.assertEqual(evs[3].category, "probe")

        # TCP RST teardown from SPT=443 -> stale
        self.assertEqual(evs[4].category, "stale")
        self.assertIn("RST", evs[4].flags)

        # ICMP Type 8 -> ping
        self.assertEqual(evs[5].category, "ping")
        self.assertEqual(evs[5].service, "Echo Req (Ping)")

        # NFLOG ACCEPT outbound -> allowed + device name
        self.assertEqual(evs[6].verdict, "allowed")
        self.assertEqual(evs[6].category, "outbound")
        self.assertEqual(evs[6].src_name, "laptop")
        self.assertEqual(evs[6].ts, 1795335837)

    def test_iptables_counters(self) -> None:
        c = parse_iptables_counters(SAMPLE_IPTABLES)
        self.assertEqual(c["wan_ssh_22"]["pkts"], 1949)
        self.assertTrue(c["wan_ssh_22"]["available"])
        self.assertEqual(c["wan_ssh_2222"]["pkts"], 309)
        self.assertEqual(c["wan_psd"]["pkts"], 3625)
        self.assertEqual(c["wan_icmp"]["pkts"], 1980)
        self.assertEqual(c["invalid_drop"]["pkts"], 5118)
        self.assertEqual(c["tarpit_tcp"]["pkts"], 129000)

    def test_non_wan_interface_classification_and_counters(self) -> None:
        for iface in ("eth0", "vlan2", "ppp0"):
            with self.subTest(wan_iface=iface):
                lines = [
                    f"Nov 22 00:23:57.987 router kern.info kernel: [1795335837.987176] ACCEPT IN=br0 OUT={iface} SRC=192.168.1.60 DST=203.0.113.44 LEN=60 TTL=63 ID=1 PROTO=TCP SPT=53088 DPT=443 SYN",
                    "Nov 22 00:23:58.987 router kern.info kernel: [1795335838.987176] ACCEPT IN=br0 OUT= SRC=192.168.1.60 DST=192.168.1.1 LEN=60 TTL=64 ID=2 PROTO=TCP SPT=53089 DPT=2222 SYN",
                ]
                evs = parse_lines(lines, {"192.168.1.60": "laptop"}, wan_iface=iface)
                self.assertEqual(len(evs), 2)
                self.assertEqual(evs[0].category, "outbound")
                self.assertEqual(evs[1].category, "local")

        non_wan_iptables = """
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 DROP       tcp  --  ppp0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
  420 21840 logdrop    icmp --  ppp0   *       0.0.0.0/0            0.0.0.0/0
""".strip()
        counters = parse_iptables_counters(non_wan_iptables, wan_iface="ppp0")
        # Measured 0 is available=True with pkts=0
        self.assertTrue(counters["wan_ssh_22"]["available"])
        self.assertEqual(counters["wan_ssh_22"]["pkts"], 0)
        # Matched non-zero counter on ppp0
        self.assertTrue(counters["wan_icmp"]["available"])
        self.assertEqual(counters["wan_icmp"]["pkts"], 420)
        # Unmatched counters are clearly unavailable (not 0)
        self.assertFalse(counters["wan_ssh_2222"]["available"])
        self.assertIsNone(counters["wan_ssh_2222"]["pkts"])
        self.assertFalse(counters["tarpit_tcp"]["available"])
        self.assertIsNone(counters["tarpit_tcp"]["pkts"])

        # Empty snapshot marks all counters unavailable
        empty = parse_iptables_counters("", wan_iface="eth0")
        self.assertTrue(all(not item["available"] and item["pkts"] is None for item in empty.values()))


if __name__ == "__main__":
    unittest.main()
