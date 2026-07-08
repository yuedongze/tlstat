package tlsparse

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// recordConn wraps a net.Conn and copies everything Read from it (the peer's
// writes) into buf — i.e. the bytes arriving at this endpoint.
type recordConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *recordConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.buf.Write(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tlstat.test", Organization: []string{"tlstat"}},
		DNSNames:     []string{"tlstat.test", "www.tlstat.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestParseServerHelloAndCert12(t *testing.T) {
	cert := selfSigned(t)
	cli, srv := net.Pipe()
	// client records what the server sends it (ServerHello + Certificate).
	rc := &recordConn{Conn: cli}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s := tls.Server(srv, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12, // force 1.2 so the cert is cleartext
		})
		_ = s.Handshake()
		s.Close()
	}()

	c := tls.Client(rc, &tls.Config{
		ServerName:         "tlstat.test",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	})
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	c.Close()
	wg.Wait()

	rc.mu.Lock()
	inbound := append([]byte(nil), rc.buf.Bytes()...)
	rc.mu.Unlock()

	var info Info
	Parse(inbound, &info)

	if !info.HasServerHello {
		t.Fatal("did not detect ServerHello")
	}
	if info.NegVersion != 0x0303 {
		t.Errorf("NegVersion = %s, want TLS 1.2", VersionName(info.NegVersion))
	}
	if CipherName(info.CipherSuite) == "" {
		t.Errorf("no cipher suite parsed")
	}
	if !info.HasCert {
		t.Fatal("did not parse Certificate (TLS 1.2)")
	}
	if info.CertSubject != "tlstat.test" {
		t.Errorf("CertSubject = %q, want tlstat.test", info.CertSubject)
	}
	t.Logf("ver=%s cipher=%s group=%s certCN=%s SANs=%v sig=%s",
		VersionName(info.NegVersion), CipherName(info.CipherSuite),
		GroupName(info.Group), info.CertSubject, info.CertSANs, info.CertSigAlg)
}
