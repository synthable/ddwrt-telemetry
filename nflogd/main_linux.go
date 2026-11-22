//go:build linux

// nflogd: lightweight zero-dependency Linux NFLOG daemon for DD-WRT routers.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"
)

const (
	netlinkNetfilter = 12
	solNetlink       = 270
	netlinkNoEnobufs = 5
)

type groupWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	f        *os.File
	bw       *bufio.Writer
	written  int64
}

func newGroupWriter(path string, maxBytes int64) (*groupWriter, error) {
	gw := &groupWriter{path: path, maxBytes: maxBytes}
	if err := gw.openLocked(); err != nil {
		return nil, err
	}
	return gw, nil
}

func (gw *groupWriter) openLocked() error {
	f, err := os.OpenFile(gw.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	if info, err := f.Stat(); err == nil {
		gw.written = info.Size()
	} else {
		gw.written = 0
	}
	gw.f = f
	gw.bw = bufio.NewWriterSize(f, 8192)
	return nil
}

func (gw *groupWriter) WriteLine(line string) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.bw == nil {
		if err := gw.openLocked(); err != nil {
			return
		}
	}
	n, _ := gw.bw.WriteString(line)
	gw.written += int64(n)
	if gw.maxBytes > 0 && gw.written >= gw.maxBytes {
		_ = gw.bw.Flush()
		_ = gw.f.Close()
		gw.f = nil
		gw.bw = nil
		_ = os.Rename(gw.path, gw.path+".prev")
		_ = gw.openLocked()
	}
}

func (gw *groupWriter) Flush() {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.bw != nil {
		_ = gw.bw.Flush()
	}
}

func (gw *groupWriter) Reopen() {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.bw != nil {
		_ = gw.bw.Flush()
	}
	if gw.f != nil {
		_ = gw.f.Close()
		gw.f = nil
		gw.bw = nil
	}
	_ = gw.openLocked()
}

func (gw *groupWriter) Close() {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.bw != nil {
		_ = gw.bw.Flush()
	}
	if gw.f != nil {
		_ = gw.f.Close()
		gw.f = nil
		gw.bw = nil
	}
}

type ifCache struct {
	mu    sync.RWMutex
	names map[uint32]string
	last  time.Time
}

func newIfCache() *ifCache {
	c := &ifCache{names: make(map[uint32]string)}
	c.refresh()
	return c
}

func (c *ifCache) refresh() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	m := make(map[uint32]string, len(ifaces))
	for _, iface := range ifaces {
		m[uint32(iface.Index)] = iface.Name
	}
	c.mu.Lock()
	c.names = m
	c.last = time.Now()
	c.mu.Unlock()
}

func (c *ifCache) Name(idx uint32) string {
	if idx == 0 {
		return ""
	}
	c.mu.RLock()
	name, ok := c.names[idx]
	stale := time.Since(c.last) > 60*time.Second
	c.mu.RUnlock()
	if ok {
		return name
	}
	if stale || !ok {
		c.refresh()
		c.mu.RLock()
		name = c.names[idx]
		c.mu.RUnlock()
	}
	if name == "" {
		return strconv.FormatUint(uint64(idx), 10)
	}
	return name
}

func buildCfgMsg(seq uint32, group uint16, attrType uint16, attrPayload []byte) []byte {
	msg := make([]byte, 20)
	binary.LittleEndian.PutUint16(msg[4:6], (nfnlSubsysUlog<<8)|nfulnlMsgConfig)
	binary.LittleEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.LittleEndian.PutUint32(msg[8:12], seq)
	binary.LittleEndian.PutUint32(msg[12:16], 0)
	msg[16] = syscall.AF_UNSPEC
	msg[17] = 0
	binary.BigEndian.PutUint16(msg[18:20], group)

	msg = appendNlattr(msg, attrType, attrPayload)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

func sendAndCheckAck(fd int, msg []byte) error {
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
		return err
	}
	resp := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, resp, 0)
	if err != nil {
		return err
	}
	if n < 20 {
		return errors.New("short netlink ack")
	}
	msgType := binary.LittleEndian.Uint16(resp[4:6])
	if msgType == syscall.NLMSG_ERROR {
		errCode := int32(binary.LittleEndian.Uint32(resp[16:20]))
		if errCode != 0 {
			return syscall.Errno(-errCode)
		}
	}
	return nil
}

func bindGroup(fd int, seq *uint32, group uint16, copyRange uint32) error {
	*seq++
	bindMsg := buildCfgMsg(*seq, group, nfulaCfgCmd, []byte{nfulnlCfgCmdBind})
	if err := sendAndCheckAck(fd, bindMsg); err != nil {
		return fmt.Errorf("bind group %d: %w", group, err)
	}

	modePayload := make([]byte, 6)
	binary.BigEndian.PutUint32(modePayload[0:4], copyRange)
	modePayload[4] = nfulnlCopyPacket
	modePayload[5] = 0
	*seq++
	modeMsg := buildCfgMsg(*seq, group, nfulaCfgMode, modePayload)
	if err := sendAndCheckAck(fd, modeMsg); err != nil {
		return fmt.Errorf("set copy mode group %d: %w", group, err)
	}
	return nil
}

func main() {
	acceptPath := flag.String("accept-log", "/tmp/fw-accept.log", "Output log path for NFLOG group 1 (ACCEPT)")
	dropPath := flag.String("drop-log", "/tmp/fw-drop.log", "Output log path for NFLOG group 2 (DROP/REJECT)")
	acceptGroup := flag.Int("accept-group", 1, "NFLOG group number for ACCEPT")
	dropGroup := flag.Int("drop-group", 2, "NFLOG group number for DROP")
	acceptMaxMB := flag.Int64("accept-max-mb", 8, "Max RAM size (MB) before rotating accept-log to .prev")
	dropMaxMB := flag.Int64("drop-max-mb", 4, "Max RAM size (MB) before rotating drop-log to .prev")
	pidFile := flag.String("pidfile", "/var/run/nflogd.pid", "PID file path")
	tzName := flag.String("tz", "UTC", "IANA timezone for formatted log timestamps (e.g. America/Los_Angeles)")
	httpListen := flag.String("http-listen", "192.168.1.1:8789", "LAN-only HTTP/SSE bind address (empty to disable)")
	tokenFile := flag.String("token-file", "/jffs/etc/nflogd.token", "Bearer token file path for HTTP API")
	dnsLog := flag.String("dns-log", "/tmp/dns.log", "dnsmasq log path for SSE streaming & /api/tail")
	archiveDir := flag.String("archive-dir", "/jffs/logs", "Archive directory for /api/archive")
	flag.Parse()

	loc, err := time.LoadLocation(*tzName)
	if err != nil {
		loc = time.Local
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "router"
	}

	acceptWriter, err := newGroupWriter(*acceptPath, *acceptMaxMB*1024*1024)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nflogd: open accept log: %v\n", err)
		os.Exit(1)
	}
	defer acceptWriter.Close()

	dropWriter, err := newGroupWriter(*dropPath, *dropMaxMB*1024*1024)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nflogd: open drop log: %v\n", err)
		os.Exit(1)
	}
	defer dropWriter.Close()

	writers := map[uint16]*groupWriter{
		uint16(*acceptGroup): acceptWriter,
		uint16(*dropGroup):   dropWriter,
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, netlinkNetfilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nflogd: netlink socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024*1024)
	_ = syscall.SetsockoptInt(fd, solNetlink, netlinkNoEnobufs, 1)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		fmt.Fprintf(os.Stderr, "nflogd: netlink bind: %v\n", err)
		os.Exit(1)
	}

	var seq uint32
	if err := bindGroup(fd, &seq, uint16(*acceptGroup), 128); err != nil {
		fmt.Fprintf(os.Stderr, "nflogd: %v\n", err)
		os.Exit(1)
	}
	if err := bindGroup(fd, &seq, uint16(*dropGroup), 128); err != nil {
		fmt.Fprintf(os.Stderr, "nflogd: %v\n", err)
		os.Exit(1)
	}

	if *pidFile != "" {
		_ = os.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
		defer os.Remove(*pidFile)
	}

	ifc := newIfCache()
	b := newBroker()

	stopFlush := make(chan struct{})
	if *httpListen != "" {
		token := ""
		if tb, err := os.ReadFile(*tokenFile); err == nil {
			token = strings.TrimSpace(string(tb))
		}
		if token == "" {
			fmt.Fprintf(os.Stderr, "nflogd: warning: token file %s missing/empty; HTTP API disabled\n", *tokenFile)
		} else {
			startFileTailer(*dnsLog, "dns", b, stopFlush)
			startHTTPServer(apiConfig{
				ListenAddr: *httpListen,
				Token:      token,
				AcceptLog:  *acceptPath,
				DropLog:    *dropPath,
				DnsLog:     *dnsLog,
				ArchiveDir: *archiveDir,
				StartedAt:  time.Now(),
				Broker:     b,
			})
		}
	}

	go func() {
		tk := time.NewTicker(1 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				acceptWriter.Flush()
				dropWriter.Flush()
			case <-stopFlush:
				return
			}
		}
	}()

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGUSR1, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGUSR1 {
				acceptWriter.Reopen()
				dropWriter.Reopen()
				ifc.refresh()
			} else {
				close(stopFlush)
				acceptWriter.Close()
				dropWriter.Close()
				if *pidFile != "" {
					_ = os.Remove(*pidFile)
				}
				os.Exit(0)
			}
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ENOBUFS) {
				continue
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		off := 0
		for off+16 <= n {
			nlLen := int(binary.LittleEndian.Uint32(buf[off : off+4]))
			if nlLen < 16 || off+nlLen > n {
				break
			}
			pkt, ok := parseNflogMessage(buf[off : off+nlLen])
			if ok {
				if w, exists := writers[pkt.group]; exists {
					line := formatLogLine(hostname, pkt, ifc.Name(pkt.inDev), ifc.Name(pkt.outDev), loc)
					w.WriteLine(line)
					if pkt.group == uint16(*acceptGroup) {
						b.Publish("accept", line)
					} else {
						b.Publish("drop", line)
					}
				}
			}
			off += align4(nlLen)
		}
	}
}
