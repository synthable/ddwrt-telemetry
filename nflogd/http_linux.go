//go:build linux

package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type streamEvent struct {
	Kind string // "accept", "drop", "dns"
	Line string
}

type broker struct {
	mu   sync.RWMutex
	subs map[chan streamEvent]struct{}
}

func newBroker() *broker {
	return &broker{subs: make(map[chan streamEvent]struct{})}
}

func (b *broker) Subscribe() chan streamEvent {
	ch := make(chan streamEvent, 256)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *broker) Unsubscribe(ch chan streamEvent) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
	close(ch)
}

func (b *broker) Publish(kind, line string) {
	ev := streamEvent{Kind: kind, Line: strings.TrimRight(line, "\r\n")}
	b.mu.RLock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
			// Drop for slow subscriber rather than stalling packet logging
		}
	}
	b.mu.RUnlock()
}

// startFileTailer tails /tmp/dns.log in RAM and publishes new lines to broker.
func startFileTailer(path, kind string, b *broker, stop <-chan struct{}) {
	go func() {
		var (
			f     *os.File
			inode uint64
			off   int64
		)

		openAtEnd := func(seekEnd bool) {
			if f != nil {
				_ = f.Close()
				f = nil
			}
			nf, err := os.Open(path)
			if err != nil {
				return
			}
			fi, err := nf.Stat()
			if err != nil {
				_ = nf.Close()
				return
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if ok {
				inode = st.Ino
			}
			if seekEnd {
				off = fi.Size()
				_, _ = nf.Seek(off, io.SeekStart)
			} else {
				off = 0
			}
			f = nf
		}

		openAtEnd(true)
		tk := time.NewTicker(400 * time.Millisecond)
		defer tk.Stop()
		defer func() {
			if f != nil {
				_ = f.Close()
			}
		}()

		var partial string
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				fi, err := os.Stat(path)
				if err != nil {
					continue
				}
				st, _ := fi.Sys().(*syscall.Stat_t)
				if f == nil || (st != nil && st.Ino != inode) || fi.Size() < off {
					partial = ""
					openAtEnd(false)
					if f == nil {
						continue
					}
				}
				if fi.Size() == off {
					continue
				}
				reader := bufio.NewReader(f)
				for {
					chunk, rerr := reader.ReadString('\n')
					if len(chunk) > 0 {
						off += int64(len(chunk))
						if strings.HasSuffix(chunk, "\n") {
							b.Publish(kind, partial+chunk)
							partial = ""
						} else {
							partial += chunk
						}
					}
					if rerr != nil {
						break
					}
				}
			}
		}
	}()
}

var validArchiveRe = regexp.MustCompile(`^(dns|fw-drop|fw-accept|syslog)-[0-9]{8}-[0-9]{6}\.log\.gz$`)

type apiConfig struct {
	ListenAddr string
	Token      string
	AcceptLog  string
	DropLog    string
	DnsLog     string
	ArchiveDir string
	StartedAt  time.Time
	Broker     *broker
}

func startHTTPServer(cfg apiConfig) *http.Server {
	mux := http.NewServeMux()

	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if cfg.Token != "" {
				got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if subtle.ConstantTimeCompare([]byte(got), []byte(cfg.Token)) != 1 {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next(w, r)
		}
	}

	fileForKey := func(key string) (string, bool) {
		switch key {
		case "dns":
			return cfg.DnsLog, true
		case "dns_prev":
			return cfg.DnsLog + ".prev", true
		case "drop":
			return cfg.DropLog, true
		case "drop_prev":
			return cfg.DropLog + ".prev", true
		case "accept":
			return cfg.AcceptLog, true
		case "accept_prev":
			return cfg.AcceptLog + ".prev", true
		case "messages":
			return "/var/log/messages", true
		case "messages_0":
			return "/var/log/messages.0", true
		default:
			return "", false
		}
	}

	mux.HandleFunc("/api/health", auth(func(w http.ResponseWriter, r *http.Request) {
		fileInfo := func(p string) map[string]any {
			fi, err := os.Stat(p)
			if err != nil {
				return map[string]any{"exists": false, "size": 0}
			}
			var ino uint64
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				ino = st.Ino
			}
			return map[string]any{"exists": true, "size": fi.Size(), "inode": ino}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"pid":        os.Getpid(),
			"uptime_sec": int64(time.Since(cfg.StartedAt).Seconds()),
			"files": map[string]any{
				"dns":    fileInfo(cfg.DnsLog),
				"drop":   fileInfo(cfg.DropLog),
				"accept": fileInfo(cfg.AcceptLog),
			},
		})
	}))

	mux.HandleFunc("/api/meta", auth(func(w http.ResponseWriter, r *http.Request) {
		readStr := func(p string) string {
			b, err := os.ReadFile(p)
			if err != nil {
				return ""
			}
			return string(b)
		}

		iptOut := ""
		if out1, err := exec.Command("iptables", "-L", "INPUT", "-n", "-v").Output(); err == nil {
			iptOut += string(out1)
		}
		if out2, err := exec.Command("iptables", "-L", "tarpit", "-n", "-v").Output(); err == nil {
			iptOut += string(out2)
		}

		var archives []string
		if entries, err := os.ReadDir(cfg.ArchiveDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && validArchiveRe.MatchString(e.Name()) {
					archives = append(archives, e.Name())
				}
			}
			sort.Strings(archives)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dnsmasq_conf": readStr("/tmp/dnsmasq.conf"),
			"leases":       readStr("/jffs/dnsmasq.leases"),
			"iptables":     iptOut,
			"archives":     archives,
		})
	}))

	mux.HandleFunc("/api/tail", auth(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("file")
		path, ok := fileForKey(key)
		if !ok {
			http.Error(w, "unknown file", http.StatusBadRequest)
			return
		}
		reqOff, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		reqIno, _ := strconv.ParseUint(r.URL.Query().Get("inode"), 10, 64)
		maxBytes, _ := strconv.ParseInt(r.URL.Query().Get("max_bytes"), 10, 64)
		if maxBytes <= 0 || maxBytes > 4*1024*1024 {
			maxBytes = 2 * 1024 * 1024
		}

		f, err := os.Open(path)
		if err != nil {
			w.Header().Set("X-Next-Offset", "0")
			w.Header().Set("X-File-Inode", "0")
			w.WriteHeader(http.StatusOK)
			return
		}
		defer f.Close()

		fi, err := f.Stat()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var ino uint64
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			ino = st.Ino
		}

		size := fi.Size()
		rotated := false
		if reqOff < 0 || reqOff > size || (reqIno != 0 && ino != 0 && reqIno != ino) {
			reqOff = 0
			rotated = true
		}

		// If requesting from 0 on a huge file, cap to last maxBytes aligned to newline
		if reqOff == 0 && size > maxBytes {
			reqOff = size - maxBytes
			_, _ = f.Seek(reqOff, io.SeekStart)
			br := bufio.NewReader(f)
			if skip, err := br.ReadBytes('\n'); err == nil {
				reqOff += int64(len(skip))
			}
		}

		_, _ = f.Seek(reqOff, io.SeekStart)
		data, _ := io.ReadAll(io.LimitReader(f, maxBytes))
		nextOff := reqOff + int64(len(data))

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Next-Offset", strconv.FormatInt(nextOff, 10))
		w.Header().Set("X-File-Inode", strconv.FormatUint(ino, 10))
		if rotated {
			w.Header().Set("X-Rotated", "1")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))

	mux.HandleFunc("/api/archive", auth(func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Query().Get("name"))
		if !validArchiveRe.MatchString(name) {
			http.Error(w, "invalid archive name", http.StatusBadRequest)
			return
		}
		full := filepath.Join(cfg.ArchiveDir, name)
		f, err := os.Open(full)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = io.Copy(w, f)
	}))

	mux.HandleFunc("/api/stream", auth(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		want := map[string]bool{"dns": true, "drop": true, "accept": true}
		if t := r.URL.Query().Get("types"); t != "" {
			want = map[string]bool{}
			for _, part := range strings.Split(t, ",") {
				want[strings.TrimSpace(part)] = true
			}
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		_, _ = fmt.Fprint(w, ": connected\n\n")
		flusher.Flush()

		ch := cfg.Broker.Subscribe()
		defer cfg.Broker.Unsubscribe(ch)

		ping := time.NewTicker(15 * time.Second)
		defer ping.Stop()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ping.C:
				_, _ = fmt.Fprint(w, ": ping\n\n")
				flusher.Flush()
			case ev, ok := <-ch:
				if !ok {
					return
				}
				if !want[ev.Kind] {
					continue
				}
				_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind, ev.Line)
				flusher.Flush()
			}
		}
	}))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "nflogd: http server error: %v\n", err)
		}
	}()
	return srv
}
