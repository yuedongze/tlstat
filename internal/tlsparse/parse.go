// Package tlsparse parses cleartext portions of the TLS handshake captured
// off the wire: ClientHello, ServerHello, and (on TLS 1.2) the Certificate
// message. Everything is best-effort — buffers may be truncated or start
// mid-stream, so partial results are the norm.
package tlsparse

import (
	"crypto/x509"
	"strings"
)

// Info accumulates what we've learned about one connection's handshake.
// It is updated in place as successive wire buffers arrive.
type Info struct {
	HasClientHello bool
	HasServerHello bool
	HasCert        bool

	SNI           string
	ALPN          []string
	ClientVersion uint16 // legacy_version from ClientHello

	NegVersion  uint16 // resolved negotiated version
	CipherSuite uint16
	Group       uint16   // negotiated key-share group
	OfferedSigs []uint16 // signature_algorithms offered by the client

	CertSubject string
	CertIssuer  string
	CertSANs    []string
	CertSigAlg  string
}

// content types
const (
	ctHandshake = 22
)

// handshake message types
const (
	hsClientHello = 1
	hsServerHello = 2
	hsCertificate = 11
)

// Parse consumes one captured wire buffer and folds anything it can decode
// into info. dir is unused today but kept for future asymmetric handling.
func Parse(buf []byte, info *Info) {
	// Reassemble the handshake byte-stream from all leading handshake records.
	stream := collectHandshake(buf)
	if len(stream) == 0 {
		return
	}
	parseHandshakeStream(stream, info)
}

// collectHandshake walks TLS records and concatenates the payloads of
// contiguous handshake (type 22) records into a single stream.
func collectHandshake(buf []byte) []byte {
	var out []byte
	p := 0
	for p+5 <= len(buf) {
		ct := buf[p]
		length := int(buf[p+3])<<8 | int(buf[p+4])
		if ct != ctHandshake {
			break
		}
		start := p + 5
		end := start + length
		if end > len(buf) {
			end = len(buf) // truncated final record — take what we have
		}
		out = append(out, buf[start:end]...)
		if end != start+length {
			break // truncated, stop
		}
		p = end
	}
	return out
}

func parseHandshakeStream(s []byte, info *Info) {
	p := 0
	for p+4 <= len(s) {
		mtype := s[p]
		mlen := int(s[p+1])<<16 | int(s[p+2])<<8 | int(s[p+3])
		body := s[p+4:]
		if mlen > len(body) {
			mlen = len(body) // truncated
		}
		body = body[:mlen]
		switch mtype {
		case hsClientHello:
			parseClientHello(body, info)
		case hsServerHello:
			parseServerHello(body, info)
		case hsCertificate:
			parseCertificate(body, info)
		}
		p += 4 + mlen
	}
}

func parseClientHello(b []byte, info *Info) {
	r := reader{b, 0}
	ver, ok := r.u16()
	if !ok {
		return
	}
	info.HasClientHello = true
	info.ClientVersion = ver
	if info.NegVersion == 0 {
		info.NegVersion = ver
	}
	if !r.skip(32) { // random
		return
	}
	if !r.skipVec8() { // session id
		return
	}
	// cipher suites
	csLen, ok := r.u16()
	if !ok {
		return
	}
	r.skip(int(csLen))
	if !r.skipVec8() { // compression methods
		return
	}
	parseExtensions(&r, info, false)
}

func parseServerHello(b []byte, info *Info) {
	r := reader{b, 0}
	ver, ok := r.u16()
	if !ok {
		return
	}
	info.HasServerHello = true
	info.NegVersion = ver // may be overridden by supported_versions ext (1.3)
	if !r.skip(32) {      // random
		return
	}
	if !r.skipVec8() { // session id
		return
	}
	cs, ok := r.u16()
	if !ok {
		return
	}
	info.CipherSuite = cs
	if _, ok := r.u8(); !ok { // compression method
		return
	}
	parseExtensions(&r, info, true)
	// A TLS 1.3-only cipher suite implies TLS 1.3 even if the supported_versions
	// extension was missed (e.g. a large post-quantum key_share truncated our
	// captured buffer before we reached it).
	if info.NegVersion < 0x0304 && isTLS13Cipher(cs) {
		info.NegVersion = 0x0304
	}
}

func isTLS13Cipher(c uint16) bool { return c >= 0x1301 && c <= 0x1305 }

// parseExtensions walks the extension vector. server distinguishes
// ServerHello semantics for supported_versions / key_share.
func parseExtensions(r *reader, info *Info, server bool) {
	extLen, ok := r.u16()
	if !ok {
		return
	}
	end := r.off + int(extLen)
	for r.off+4 <= end && r.off+4 <= len(r.b) {
		etype, _ := r.u16()
		elen, _ := r.u16()
		data, ok := r.bytes(int(elen))
		if !ok {
			// Truncated capture: extract what we can from the remaining bytes
			// (enough for the small fields we care about), then stop.
			handleExtension(etype, r.b[r.off:], info, server)
			return
		}
		handleExtension(etype, data, info, server)
	}
}

func handleExtension(etype uint16, data []byte, info *Info, server bool) {
	switch etype {
	case 0: // server_name
		if !server {
			if s := parseSNI(data); s != "" {
				info.SNI = s
			}
		}
	case 13: // signature_algorithms (client)
		if !server {
			info.OfferedSigs = parseU16List(data)
		}
	case 16: // ALPN
		info.ALPN = parseALPN(data)
	case 43: // supported_versions
		if server && len(data) >= 2 {
			info.NegVersion = uint16(data[0])<<8 | uint16(data[1])
		}
	case 51: // key_share — negotiated group is the first 2 bytes
		if server && len(data) >= 2 {
			info.Group = uint16(data[0])<<8 | uint16(data[1])
		}
	}
}

func parseSNI(b []byte) string {
	// server_name_list: len(2) then entries type(1)+len(2)+name
	if len(b) < 2 {
		return ""
	}
	r := reader{b, 0}
	listLen, _ := r.u16()
	end := r.off + int(listLen)
	for r.off+3 <= end && r.off+3 <= len(r.b) {
		ntype, _ := r.u8()
		nlen, _ := r.u16()
		name, ok := r.bytes(int(nlen))
		if !ok {
			return ""
		}
		if ntype == 0 {
			return string(name)
		}
	}
	return ""
}

func parseALPN(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	r := reader{b, 0}
	listLen, _ := r.u16()
	end := r.off + int(listLen)
	var out []string
	for r.off+1 <= end && r.off < len(r.b) {
		l, _ := r.u8()
		name, ok := r.bytes(int(l))
		if !ok {
			break
		}
		out = append(out, string(name))
	}
	return out
}

func parseU16List(b []byte) []uint16 {
	if len(b) < 2 {
		return nil
	}
	r := reader{b, 0}
	l, _ := r.u16()
	end := r.off + int(l)
	var out []uint16
	for r.off+2 <= end && r.off+2 <= len(r.b) {
		v, _ := r.u16()
		out = append(out, v)
	}
	return out
}

// parseCertificate handles the TLS 1.2 Certificate message (cleartext).
// Layout: certificates_length(3) then repeated cert_length(3)+cert_der.
// (TLS 1.3 prefixes a 1-byte context and per-cert extensions, and is almost
// always encrypted on the wire anyway, so this targets 1.2.)
func parseCertificate(b []byte, info *Info) {
	if len(b) < 3 {
		return
	}
	r := reader{b, 0}
	total, _ := r.u24()
	end := r.off + int(total)
	if end > len(b) {
		end = len(b)
	}
	if r.off+3 > end {
		return
	}
	clen, _ := r.u24()
	der, ok := r.bytes(int(clen))
	if !ok || len(der) == 0 {
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return
	}
	info.HasCert = true
	info.CertSubject = cert.Subject.CommonName
	if info.CertSubject == "" && len(cert.Subject.Organization) > 0 {
		info.CertSubject = cert.Subject.Organization[0]
	}
	info.CertIssuer = cert.Issuer.CommonName
	info.CertSANs = cert.DNSNames
	info.CertSigAlg = strings.TrimSuffix(cert.SignatureAlgorithm.String(), "-")
}

// reader is a bounds-checked big-endian cursor over a byte slice.
type reader struct {
	b   []byte
	off int
}

func (r *reader) u8() (uint8, bool) {
	if r.off+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.off]
	r.off++
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if r.off+2 > len(r.b) {
		return 0, false
	}
	v := uint16(r.b[r.off])<<8 | uint16(r.b[r.off+1])
	r.off += 2
	return v, true
}

func (r *reader) u24() (uint32, bool) {
	if r.off+3 > len(r.b) {
		return 0, false
	}
	v := uint32(r.b[r.off])<<16 | uint32(r.b[r.off+1])<<8 | uint32(r.b[r.off+2])
	r.off += 3
	return v, true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.off+n > len(r.b) {
		return nil, false
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v, true
}

func (r *reader) skip(n int) bool {
	if n < 0 || r.off+n > len(r.b) {
		r.off = len(r.b)
		return false
	}
	r.off += n
	return true
}

// skipVec8 skips a vector prefixed with a 1-byte length.
func (r *reader) skipVec8() bool {
	l, ok := r.u8()
	if !ok {
		return false
	}
	return r.skip(int(l))
}
