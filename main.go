// tlstat — live eBPF TLS handshake/connection monitor.
//
// Run as root:  sudo tlstat
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/tlstat/tlstat/internal/loader"
	"github.com/tlstat/tlstat/internal/model"
	"github.com/tlstat/tlstat/internal/tlsparse"
	"github.com/tlstat/tlstat/internal/ui"
)

func tlsVer(c model.Conn) string {
	if v := tlsparse.VersionName(c.Info.NegVersion); v != "" {
		return v
	}
	if c.Preexisting {
		return "pre-ex"
	}
	return "?"
}

func cipherOf(c model.Conn) string {
	if n := tlsparse.CipherName(c.Info.CipherSuite); n != "" {
		return n
	}
	return "-"
}

func peekNote(c model.Conn) string {
	data, arrow := c.HeadOut, "→"
	if len(data) == 0 {
		data, arrow = c.HeadIn, "←"
	}
	if len(data) == 0 {
		return ""
	}
	s := string(data)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 48 {
		s = s[:48]
	}
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '.'
		}
		return r
	}, s)
	return fmt.Sprintf("  peek%s(%dB): %q", arrow, len(data), clean)
}

func main() {
	libssl := flag.String("libssl", "", "path to libssl.so for cleartext uprobes (auto-detected if empty)")
	interval := flag.Duration("interval", 500*time.Millisecond, "map poll interval")
	dump := flag.Duration("dump", 0, "headless mode: print snapshots for this long, then exit (e.g. 10s)")
	history := flag.Int("history", 500, "number of closed connections to retain for inspection")
	peekBytes := flag.Int("peek-bytes", 8192, "rolling plaintext tail size kept per direction, in bytes")
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "tlstat must be run as root (sudo): eBPF requires CAP_BPF/CAP_SYS_ADMIN")
		os.Exit(1)
	}

	path := *libssl
	if path == "" {
		path = findLibssl()
		if path == "" {
			fmt.Fprintln(os.Stderr, "warning: libssl.so not found; cleartext capture disabled (pass --libssl)")
		}
	}

	l, err := loader.New(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load eBPF: %v\n", err)
		os.Exit(1)
	}
	defer l.Close()

	store := model.New(*history, *peekBytes)

	// Event reader: fold ring buffer records into the store.
	go func() {
		for {
			w, d, c, err := l.ReadEvent()
			if err != nil {
				return // ring buffer closed on shutdown
			}
			switch {
			case w != nil:
				store.ApplyWire(w)
			case d != nil:
				store.ApplyData(d)
			case c != nil:
				store.ApplyClose(c)
			}
		}
	}()

	// Map poller: refresh byte counters and plaintext totals.
	go func() {
		t := time.NewTicker(*interval)
		defer t.Stop()
		for range t.C {
			if flows, err := l.Flows(); err == nil {
				store.UpdateFlows(flows)
				for _, f := range flows {
					if f.Closed {
						l.DeleteFlow(f.Sock)
					}
				}
			}
			if stats, err := l.SSLStats(); err == nil {
				store.UpdateSSLStats(stats)
			}
		}
	}()

	if *dump > 0 {
		runDump(store, *dump)
		return
	}

	p := tea.NewProgram(ui.New(store), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "ui error: %v\n", err)
		os.Exit(1)
	}
}

// runDump prints periodic text snapshots — a TTY-free mode for verification.
func runDump(store *model.Store, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		conns := store.Snapshot()
		tls := 0
		for _, c := range conns {
			if c.IsTLS {
				tls++
			}
		}
		closed := store.SnapshotHistory()
		fmt.Printf("\n=== %s | %d conns, %d TLS, %d closed ===\n", time.Now().Format("15:04:05"), len(conns), tls, len(closed))
		for _, c := range conns {
			if !c.IsTLS || !c.HasEndpoint() {
				continue
			}
			id := c.Info.SNI
			if id == "" && c.Info.CertSubject != "" {
				id = "CN=" + c.Info.CertSubject
			}
			if id == "" {
				id = c.Remote.String()
			}
			ver := tlsVer(c)
			cert := ""
			if c.Info.HasCert {
				cert = fmt.Sprintf("  cert[CN=%s SANs=%v sig=%s]", c.Info.CertSubject, c.Info.CertSANs, c.Info.CertSigAlg)
			} else if c.Info.NegVersion == 0x0304 && c.Info.HasServerHello {
				cert = "  cert[encrypted TLS1.3]"
			}
			fmt.Printf("  pid=%-6d %-12s %-28s %-8s %-30s wire=%d/%d plain=%d/%d%s%s\n",
				c.Pid, c.Comm, id, ver,
				cipherOf(c), c.TxBytes, c.RxBytes, c.PtxBytes, c.PrxBytes,
				peekNote(c), cert)
		}
		for _, c := range closed {
			if !c.IsTLS {
				continue
			}
			id := c.Info.SNI
			if id == "" {
				id = c.Remote.String()
			}
			fmt.Printf("  [closed %-8s] pid=%-6d %-12s %-24s %-8s plain=%d/%d%s\n",
				agoShort(c.ClosedAt), c.Pid, c.Comm, id, tlsVer(c),
				c.PtxBytes, c.PrxBytes, tailNote(c))
		}
	}
}

func agoShort(t time.Time) string {
	return time.Since(t).Round(time.Second).String()
}

// tailNote shows the end of the received plaintext for a closed connection.
func tailNote(c model.Conn) string {
	data := c.TailIn
	if len(data) == 0 {
		data = c.TailOut
	}
	if len(data) == 0 {
		return ""
	}
	s := data
	if len(s) > 32 {
		s = s[len(s)-32:]
	}
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '.'
		}
		return r
	}, string(s))
	return fmt.Sprintf("  tail(%dB):…%q", len(data), clean)
}

// findLibssl locates the system libssl shared object.
func findLibssl() string {
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib64/libssl.so.3",
		"/usr/lib/libssl.so.3",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Fall back to ldconfig.
	out, err := exec.Command("ldconfig", "-p").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "libssl.so.3") {
			if i := strings.LastIndex(line, "=> "); i >= 0 {
				return strings.TrimSpace(line[i+3:])
			}
		}
	}
	return ""
}
