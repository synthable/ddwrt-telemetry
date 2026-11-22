package main

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func buildIPv4TCPPacket(src, dst string, spt, dpt uint16, flags byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // IPv4, IHL=5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	binary.BigEndian.PutUint16(pkt[4:6], 12345)
	pkt[8] = 63
	pkt[9] = 6 // TCP
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())

	binary.BigEndian.PutUint16(pkt[20:22], spt)
	binary.BigEndian.PutUint16(pkt[22:24], dpt)
	pkt[33] = flags
	return pkt
}

func TestParseAndFormatTCP(t *testing.T) {
	payload := buildIPv4TCPPacket("192.168.1.60", "140.82.113.5", 51234, 443, 0x02) // SYN

	msg := make([]byte, 20)
	binary.LittleEndian.PutUint16(msg[4:6], (nfnlSubsysUlog<<8)|nfulnlMsgPacket)
	binary.BigEndian.PutUint16(msg[18:20], 1)

	msg = appendNlattr(msg, nfulaPrefix, []byte("ACCEPT \x00"))
	inIdx := make([]byte, 4)
	binary.BigEndian.PutUint32(inIdx, 11)
	msg = appendNlattr(msg, nfulaIfInDev, inIdx)
	outIdx := make([]byte, 4)
	binary.BigEndian.PutUint32(outIdx, 9)
	msg = appendNlattr(msg, nfulaIfOutDev, outIdx)

	tsBuf := make([]byte, 16)
	ts := time.Date(2026, 11, 22, 0, 20, 1, 123456000, time.UTC)
	binary.BigEndian.PutUint64(tsBuf[0:8], uint64(ts.Unix()))
	binary.BigEndian.PutUint64(tsBuf[8:16], 123456)
	msg = appendNlattr(msg, nfulaTimestamp, tsBuf)
	msg = appendNlattr(msg, nfulaPayload, payload)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))

	pkt, ok := parseNflogMessage(msg)
	if !ok {
		t.Fatalf("expected parseNflogMessage to succeed")
	}
	if pkt.group != 1 || pkt.inDev != 11 || pkt.outDev != 9 {
		t.Fatalf("unexpected header fields: %+v", pkt)
	}

	line := formatLogLine("router", pkt, "br0", "wan", time.UTC)
	for _, want := range []string{
		"router kern.info kernel:",
		"] ACCEPT IN=br0 OUT=wan SRC=192.168.1.60 DST=140.82.113.5 LEN=40 TTL=63 ID=12345 PROTO=TCP SPT=51234 DPT=443 SYN",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("line %q missing %q", line, want)
		}
	}
}

func TestParseDefaultRouteIface(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "standard eth0",
			out:  "default via 203.0.113.1 dev eth0 proto static\n",
			want: "eth0",
		},
		{
			name: "pppoe ppp0",
			out:  "default dev ppp0 scope link\n",
			want: "ppp0",
		},
		{
			name: "vlan2 with metric",
			out:  "default via 198.51.100.1 dev vlan2 metric 100\ndefault via 192.0.2.1 dev eth1 metric 200\n",
			want: "vlan2",
		},
		{
			name: "empty output",
			out:  "",
			want: "",
		},
		{
			name: "non-default route ignored",
			out:  "192.168.1.0/24 dev br0 proto kernel scope link src 192.168.1.1\n",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDefaultRouteIface(tc.out); got != tc.want {
				t.Fatalf("parseDefaultRouteIface(%q) = %q; want %q", tc.out, got, tc.want)
			}
		})
	}
}
