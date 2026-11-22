"""Unit tests for DD-WRT dnsmasq log parser."""

import unittest
from parser import parse_device_map, parse_lines, ptr_domain_to_ip


SAMPLE_CONF = """
dhcp-host=id:*,02:00:00:00:00:52,192.168.1.52,smart-tv
dhcp-host=id:*,02:00:00:00:00:60,02:00:00:00:00:61,02:00:00:00:00:62,192.168.1.60,laptop
"""

SAMPLE_LEASES = """
1795409793 02:00:00:00:00:19 192.168.1.119 phone 01:02:00:00:00:00:19 11
"""

SAMPLE_LOGS = """
Nov 21 23:43:12 dnsmasq[3630]: query[A] cloudflare.com from 192.168.1.1
Nov 21 23:43:12 dnsmasq[3630]: forwarded cloudflare.com to 94.140.14.14
Nov 21 23:43:12 dnsmasq[3630]: query[AAAA] cloudflare.com from 192.168.1.1
Nov 21 23:43:12 dnsmasq[3630]: forwarded cloudflare.com to 94.140.14.14
Nov 21 23:43:12 dnsmasq[3630]: reply cloudflare.com is 104.16.133.229
Nov 21 23:43:12 dnsmasq[3630]: reply cloudflare.com is 2606:4700::6810:84e5
Nov 21 23:43:12 dnsmasq[3630]: query[PTR] 229.133.16.104.in-addr.arpa from 192.168.1.1
Nov 21 23:43:12 dnsmasq[3630]: forwarded 229.133.16.104.in-addr.arpa to 94.140.14.14
Nov 21 23:43:12 dnsmasq[3630]: reply 104.16.133.229 is NXDOMAIN
Nov 21 23:43:16 dnsmasq[3630]: query[A] play.googleapis.com from 192.168.1.60
Nov 21 23:43:16 dnsmasq[3630]: cached play.googleapis.com is 172.217.118.4
Nov 21 23:43:20 dnsmasq[3630]: query[A] ads.doubleclick.net from 192.168.1.52
Nov 21 23:43:20 dnsmasq[3630]: forwarded ads.doubleclick.net to 94.140.14.14
Nov 21 23:43:20 dnsmasq[3630]: reply ads.doubleclick.net is 0.0.0.0
Nov 21 23:43:25 dnsmasq[3630]: query[AAAA] metrics.example.com from 192.168.1.119
Nov 21 23:43:25 dnsmasq[3630]: cached metrics.example.com is ::
Nov 21 23:43:26 dnsmasq[3630]: query[HTTPS] api.example.org from 192.168.1.60
Nov 21 23:43:26 dnsmasq[3630]: query[A] api.example.org from 192.168.1.60
Nov 21 23:43:26 dnsmasq[3630]: cached api.example.org is 203.0.113.47
Nov 21 23:43:26 dnsmasq[3630]: cached api.example.org is <HTTPS>
""".strip().splitlines()


class TestParser(unittest.TestCase):
    def test_device_map(self) -> None:
        devs = parse_device_map(SAMPLE_CONF, SAMPLE_LEASES)
        self.assertEqual(devs["192.168.1.60"], "laptop")
        self.assertEqual(devs["192.168.1.52"], "smart-tv")
        self.assertEqual(devs["192.168.1.119"], "phone")
        self.assertEqual(devs["192.168.1.1"], "router")

    def test_ptr_conversion(self) -> None:
        self.assertEqual(ptr_domain_to_ip("229.133.16.104.in-addr.arpa"), "104.16.133.229")
        self.assertEqual(
            ptr_domain_to_ip("5.e.4.8.0.1.8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.6.0.6.2.ip6.arpa"),
            "2606:4700::6810:84e5",
        )

    def test_parse_queries_and_statuses(self) -> None:
        devs = parse_device_map(SAMPLE_CONF, SAMPLE_LEASES)
        qs = parse_lines(SAMPLE_LOGS, devs, ref_year=2026, ref_month=11)
        self.assertEqual(len(qs), 8)

        # A vs AAAA matched separately
        self.assertEqual(qs[0].qtype, "A")
        self.assertEqual(qs[0].answers, ["104.16.133.229"])
        self.assertEqual(qs[0].status, "allowed")

        self.assertEqual(qs[1].qtype, "AAAA")
        self.assertEqual(qs[1].answers, ["2606:4700::6810:84e5"])
        self.assertEqual(qs[1].status, "allowed")

        # PTR reverse reply correlated to NXDOMAIN
        self.assertEqual(qs[2].qtype, "PTR")
        self.assertEqual(qs[2].status, "nxdomain")

        # Cached query
        self.assertEqual(qs[3].client_name, "laptop")
        self.assertEqual(qs[3].status, "cached")
        self.assertTrue(qs[3].cached)

        # AdGuard 0.0.0.0 block
        self.assertEqual(qs[4].client_name, "smart-tv")
        self.assertEqual(qs[4].status, "blocked")

        # AdGuard :: cached block
        self.assertEqual(qs[5].client_name, "phone")
        self.assertEqual(qs[5].status, "blocked")
        self.assertTrue(qs[5].cached)

        # HTTPS vs A matched cleanly
        self.assertEqual(qs[6].qtype, "HTTPS")
        self.assertEqual(qs[6].answers, ["<HTTPS>"])
        self.assertEqual(qs[7].qtype, "A")
        self.assertEqual(qs[7].answers, ["203.0.113.47"])


if __name__ == "__main__":
    unittest.main()
