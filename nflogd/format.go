package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	nfnlSubsysUlog  = 4
	nfulnlMsgPacket = 0
	nfulnlMsgConfig = 1

	nfulaPacketHdr = 1
	nfulaMark      = 2
	nfulaTimestamp = 3
	nfulaIfInDev   = 4
	nfulaIfOutDev  = 5
	nfulaPayload   = 9
	nfulaPrefix    = 10

	nfulaCfgCmd  = 1
	nfulaCfgMode = 2

	nfulnlCfgCmdBind   = 1
	nfulnlCfgCmdUnbind = 2
	nfulnlCopyPacket   = 2
)

type parsedPacket struct {
	group   uint16
	prefix  string
	inDev   uint32
	outDev  uint32
	mark    uint32
	ts      time.Time
	payload []byte
	hwProto uint16
}

func align4(n int) int {
	return (n + 3) &^ 3
}

func appendNlattr(buf []byte, attrType uint16, payload []byte) []byte {
	attrLen := 4 + len(payload)
	padded := align4(attrLen)
	start := len(buf)
	buf = append(buf, make([]byte, padded)...)
	binary.LittleEndian.PutUint16(buf[start:start+2], uint16(attrLen))
	binary.LittleEndian.PutUint16(buf[start+2:start+4], attrType)
	copy(buf[start+4:start+4+len(payload)], payload)
	return buf
}

func parseNflogMessage(msg []byte) (parsedPacket, bool) {
	var p parsedPacket
	if len(msg) < 20 {
		return p, false
	}
	msgType := binary.LittleEndian.Uint16(msg[4:6])
	if msgType != (nfnlSubsysUlog<<8)|nfulnlMsgPacket {
		return p, false
	}
	p.group = binary.BigEndian.Uint16(msg[18:20])

	off := 20
	for off+4 <= len(msg) {
		aLen := int(binary.LittleEndian.Uint16(msg[off : off+2]))
		aType := binary.LittleEndian.Uint16(msg[off+2:off+4]) & 0x3fff
		if aLen < 4 || off+aLen > len(msg) {
			break
		}
		val := msg[off+4 : off+aLen]
		switch aType {
		case nfulaPacketHdr:
			if len(val) >= 2 {
				p.hwProto = binary.BigEndian.Uint16(val[0:2])
			}
		case nfulaMark:
			if len(val) >= 4 {
				p.mark = binary.BigEndian.Uint32(val[0:4])
			}
		case nfulaTimestamp:
			if len(val) >= 16 {
				sec := int64(binary.BigEndian.Uint64(val[0:8]))
				usec := int64(binary.BigEndian.Uint64(val[8:16]))
				p.ts = time.Unix(sec, usec*1000)
			}
		case nfulaIfInDev:
			if len(val) >= 4 {
				p.inDev = binary.BigEndian.Uint32(val[0:4])
			}
		case nfulaIfOutDev:
			if len(val) >= 4 {
				p.outDev = binary.BigEndian.Uint32(val[0:4])
			}
		case nfulaPayload:
			p.payload = val
		case nfulaPrefix:
			p.prefix = strings.TrimRight(string(val), "\x00")
		}
		off += align4(aLen)
	}
	if p.ts.IsZero() {
		p.ts = time.Now()
	}
	return p, true
}

func formatLogLine(hostname string, p parsedPacket, inName, outName string, loc *time.Location) string {
	prefix := strings.TrimSpace(p.prefix)
	if prefix == "" {
		if p.group == 1 {
			prefix = "ACCEPT"
		} else {
			prefix = "DROP"
		}
	}

	var b strings.Builder
	b.Grow(220)
	tsLocal := p.ts
	if loc != nil {
		tsLocal = p.ts.In(loc)
	} else {
		tsLocal = p.ts.Local()
	}
	b.WriteString(tsLocal.Format("Jan _2 15:04:05.000"))
	b.WriteByte(' ')
	b.WriteString(hostname)
	b.WriteString(" kern.info kernel: [")
	fmt.Fprintf(&b, "%d.%06d", p.ts.Unix(), p.ts.Nanosecond()/1000)
	b.WriteString("] ")
	b.WriteString(prefix)
	b.WriteString(" IN=")
	b.WriteString(inName)
	b.WriteString(" OUT=")
	b.WriteString(outName)

	if len(p.payload) >= 20 && (p.payload[0]>>4) == 4 {
		ihl := int(p.payload[0]&0x0f) * 4
		totalLen := binary.BigEndian.Uint16(p.payload[2:4])
		ipID := binary.BigEndian.Uint16(p.payload[4:6])
		ttl := p.payload[8]
		protoNum := p.payload[9]
		src := net.IP(p.payload[12:16]).String()
		dst := net.IP(p.payload[16:20]).String()

		b.WriteString(" SRC=")
		b.WriteString(src)
		b.WriteString(" DST=")
		b.WriteString(dst)
		fmt.Fprintf(&b, " LEN=%d TTL=%d ID=%d ", totalLen, ttl, ipID)

		l4 := []byte(nil)
		if ihl >= 20 && ihl <= len(p.payload) {
			l4 = p.payload[ihl:]
		}

		switch protoNum {
		case 6: // TCP
			b.WriteString("PROTO=TCP")
			if len(l4) >= 14 {
				spt := binary.BigEndian.Uint16(l4[0:2])
				dpt := binary.BigEndian.Uint16(l4[2:4])
				flags := l4[13]
				fmt.Fprintf(&b, " SPT=%d DPT=%d", spt, dpt)
				if flags&0x02 != 0 {
					b.WriteString(" SYN")
				}
				if flags&0x10 != 0 {
					b.WriteString(" ACK")
				}
				if flags&0x01 != 0 {
					b.WriteString(" FIN")
				}
				if flags&0x04 != 0 {
					b.WriteString(" RST")
				}
				if flags&0x08 != 0 {
					b.WriteString(" PSH")
				}
				if flags&0x20 != 0 {
					b.WriteString(" URG")
				}
			}
		case 17: // UDP
			b.WriteString("PROTO=UDP")
			if len(l4) >= 6 {
				spt := binary.BigEndian.Uint16(l4[0:2])
				dpt := binary.BigEndian.Uint16(l4[2:4])
				ulen := binary.BigEndian.Uint16(l4[4:6])
				fmt.Fprintf(&b, " SPT=%d DPT=%d LEN=%d", spt, dpt, ulen)
			}
		case 1: // ICMP
			b.WriteString("PROTO=ICMP")
			if len(l4) >= 2 {
				fmt.Fprintf(&b, " TYPE=%d CODE=%d", l4[0], l4[1])
			}
		default:
			fmt.Fprintf(&b, "PROTO=%d", protoNum)
		}
	} else if len(p.payload) >= 40 && (p.payload[0]>>4) == 6 {
		plen := binary.BigEndian.Uint16(p.payload[4:6])
		nh := p.payload[6]
		hlim := p.payload[7]
		src := net.IP(p.payload[8:24]).String()
		dst := net.IP(p.payload[24:40]).String()
		fmt.Fprintf(&b, " SRC=%s DST=%s LEN=%d TTL=%d PROTO=%d", src, dst, int(plen)+40, hlim, nh)
	}

	if p.mark != 0 {
		fmt.Fprintf(&b, " MARK=0x%x", p.mark)
	}
	b.WriteByte('\n')
	return b.String()
}
