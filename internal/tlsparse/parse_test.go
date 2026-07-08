package tlsparse

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// captureClientHello spins up a real tls.Client against a pipe and returns the
// first flight it writes (the ClientHello record).
func captureClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	go func() {
		_ = tls.Client(c1, cfg).Handshake() // will stall after ClientHello
	}()
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := c2.Read(buf)
	if err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}
	c1.Close()
	c2.Close()
	return buf[:n]
}

func TestParseClientHello(t *testing.T) {
	ch := captureClientHello(t, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	var info Info
	Parse(ch, &info)

	if !info.HasClientHello {
		t.Fatal("did not detect ClientHello")
	}
	if info.SNI != "example.com" {
		t.Errorf("SNI = %q, want example.com", info.SNI)
	}
	if len(info.ALPN) == 0 || info.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", info.ALPN)
	}
	if len(info.OfferedSigs) == 0 {
		t.Errorf("expected offered signature algorithms")
	}
	t.Logf("SNI=%s ALPN=%v ver=%s sigs=%d", info.SNI, info.ALPN,
		VersionName(info.ClientVersion), len(info.OfferedSigs))
}

func TestParseTruncated(t *testing.T) {
	// Must not panic on short / garbage buffers.
	for _, b := range [][]byte{nil, {0x16}, {0x16, 0x03, 0x01, 0x00}, {0x17, 0x03, 0x03, 0x00, 0x10, 0x00}} {
		var info Info
		Parse(b, &info)
	}
}
