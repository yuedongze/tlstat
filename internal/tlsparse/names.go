package tlsparse

import "fmt"

// VersionName maps a TLS version word to a human label.
func VersionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	case 0:
		return ""
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// cipherSuites covers the suites in common use today. Anything else is shown
// as its hex code point.
var cipherSuites = map[uint16]string{
	// TLS 1.3
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
	// TLS 1.2 ECDHE
	0xc02b: "ECDHE-ECDSA-AES128-GCM-SHA256",
	0xc02c: "ECDHE-ECDSA-AES256-GCM-SHA384",
	0xc02f: "ECDHE-RSA-AES128-GCM-SHA256",
	0xc030: "ECDHE-RSA-AES256-GCM-SHA384",
	0xcca8: "ECDHE-RSA-CHACHA20-POLY1305",
	0xcca9: "ECDHE-ECDSA-CHACHA20-POLY1305",
	0xc023: "ECDHE-ECDSA-AES128-SHA256",
	0xc027: "ECDHE-RSA-AES128-SHA256",
	0xc013: "ECDHE-RSA-AES128-SHA",
	0xc014: "ECDHE-RSA-AES256-SHA",
	0xc009: "ECDHE-ECDSA-AES128-SHA",
	0xc00a: "ECDHE-ECDSA-AES256-SHA",
	// RSA kx (legacy)
	0x009c: "RSA-AES128-GCM-SHA256",
	0x009d: "RSA-AES256-GCM-SHA384",
	0x002f: "RSA-AES128-SHA",
	0x0035: "RSA-AES256-SHA",
	0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
}

// CipherName returns the suite name, or its hex code point if unknown.
func CipherName(c uint16) string {
	if s, ok := cipherSuites[c]; ok {
		return s
	}
	if c == 0 {
		return ""
	}
	return fmt.Sprintf("0x%04x", c)
}

// Symmetric extracts the bulk cipher from a suite name, best-effort.
func Symmetric(c uint16) string {
	switch c {
	case 0x1301, 0x1304, 0x1305:
		return "AES-128-GCM"
	case 0x1302:
		return "AES-256-GCM"
	case 0x1303:
		return "ChaCha20-Poly1305"
	}
	n := CipherName(c)
	for _, k := range []string{"CHACHA20-POLY1305", "AES256-GCM", "AES128-GCM", "AES256", "AES128", "3DES"} {
		if containsFold(n, k) {
			return k
		}
	}
	return ""
}

var namedGroups = map[uint16]string{
	0x0017: "secp256r1 (P-256)",
	0x0018: "secp384r1 (P-384)",
	0x0019: "secp521r1 (P-521)",
	0x001d: "x25519",
	0x001e: "x448",
	0x0100: "ffdhe2048",
	0x0101: "ffdhe3072",
	0x11ec: "X25519MLKEM768",
	0x6399: "X25519Kyber768Draft00",
}

// GroupName maps a supported-group / key-share word to a label.
func GroupName(g uint16) string {
	if s, ok := namedGroups[g]; ok {
		return s
	}
	if g == 0 {
		return ""
	}
	return fmt.Sprintf("0x%04x", g)
}

var sigSchemes = map[uint16]string{
	0x0401: "rsa_pkcs1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x0201: "rsa_pkcs1_sha1",
	0x0203: "ecdsa_sha1",
}

// SigSchemeName maps a signature scheme word to a label.
func SigSchemeName(s uint16) string {
	if n, ok := sigSchemes[s]; ok {
		return n
	}
	return fmt.Sprintf("0x%04x", s)
}

func containsFold(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'a' <= ca && ca <= 'z' {
			ca -= 32
		}
		if 'a' <= cb && cb <= 'z' {
			cb -= 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
