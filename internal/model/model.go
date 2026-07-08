// Package model maintains the live table of connections shown in the UI. It
// merges three eBPF event streams — flow snapshots (bytes/tuple), wire
// handshake captures, and plaintext samples — keyed by kernel socket pointer.
package model

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/tlstat/tlstat/internal/loader"
	"github.com/tlstat/tlstat/internal/tlsparse"
)

// Conn is one tracked connection.
type Conn struct {
	Sock        uint64
	Pid         uint32
	Comm        string
	Local       netip.AddrPort
	Remote      netip.AddrPort
	Direction   uint8 // 1 client, 2 server, 0 unknown
	TxBytes     uint64
	RxBytes     uint64
	PtxBytes    uint64 // plaintext written
	PrxBytes    uint64 // plaintext read
	IsTLS       bool
	Closed      bool
	Preexisting bool
	FirstSeen   time.Time
	LastActive  time.Time
	Info        tlsparse.Info

	PlainOut []byte // most informative decrypted sample written (SSL_write)
	PlainIn  []byte // most informative decrypted sample read (SSL_read)

	// Reassembly buffers: TLS records can be split across syscalls (OpenSSL
	// reads a 5-byte header then the body), so we concatenate captured chunks
	// per direction and parse the reassembled stream.
	wireOut []byte
	wireIn  []byte
}

const maxWireBuf = 16 << 10

// HasEndpoint reports whether the connection has a known remote endpoint yet
// (identity is filled asynchronously, so brand-new entries may not).
func (c Conn) HasEndpoint() bool {
	return c.Remote.IsValid() && c.Remote.Port() != 0
}

// Store is the thread-safe connection table.
type Store struct {
	mu    sync.Mutex
	conns map[uint64]*Conn

	// correlation: (pid,fd) -> sock, resolved lazily via /proc.
	pidfd map[uint64]uint64

	// latest plaintext sample per SSL*, joined to a connection during the
	// ssl_stats poll (decouples event timing from connection discovery).
	plainBySSL map[uint64]sample
}

type sample struct {
	out []byte // longest SSL_write payload seen
	in  []byte // longest SSL_read payload seen
}

// New returns an empty store.
func New() *Store {
	return &Store{
		conns:      map[uint64]*Conn{},
		pidfd:      map[uint64]uint64{},
		plainBySSL: map[uint64]sample{},
	}
}

// UpdateFlows reconciles the store against a fresh snapshot of the flows map.
func (s *Store) UpdateFlows(flows []loader.Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	seen := make(map[uint64]bool, len(flows))
	for _, f := range flows {
		seen[f.Sock] = true
		c := s.conns[f.Sock]
		if c == nil {
			c = &Conn{Sock: f.Sock, FirstSeen: now}
			s.conns[f.Sock] = c
		}
		c.Pid = f.Pid
		c.Comm = f.Comm
		c.Local = netip.AddrPortFrom(ipFrom(f.Saddr, f.IsIPv6), f.Sport)
		c.Remote = netip.AddrPortFrom(ipFrom(f.Daddr, f.IsIPv6), f.Dport)
		if f.Direction != 0 {
			c.Direction = f.Direction
		}
		if f.IsTLS {
			c.IsTLS = true
		}
		if f.Tx != c.TxBytes || f.Rx != c.RxBytes {
			c.LastActive = now
		}
		c.TxBytes = f.Tx
		c.RxBytes = f.Rx
		c.Closed = f.Closed
		// TLS traffic seen but no handshake captured => it predates us.
		c.Preexisting = c.IsTLS && !c.Info.HasClientHello && !c.Info.HasServerHello
	}
	// Drop connections that closed and are gone from the map.
	for sock, c := range s.conns {
		if !seen[sock] && c.Closed {
			delete(s.conns, sock)
		}
	}
}

// ApplyWire folds a captured wire buffer into the matching connection.
func (s *Store) ApplyWire(w *loader.WireEvent) {
	if w == nil || len(w.Data) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.conns[w.Sock]
	if c == nil {
		c = &Conn{Sock: w.Sock, FirstSeen: time.Now()}
		s.conns[w.Sock] = c
	}
	// Append to the per-direction reassembly buffer, then parse the whole
	// stream so handshake messages split across records/syscalls are recovered.
	buf := &c.wireOut
	if w.Dir == 2 {
		buf = &c.wireIn
	}
	if len(*buf) < maxWireBuf {
		*buf = append(*buf, w.Data...)
	}
	tlsparse.Parse(*buf, &c.Info)
	if c.Info.HasClientHello || c.Info.HasServerHello {
		c.IsTLS = true
		c.Preexisting = false // we caught (part of) the handshake
	}
}

// ApplyData stashes a plaintext sample keyed by SSL*. It is joined to a
// connection later, during UpdateSSLStats, so it survives arriving before the
// connection has been discovered by the flow poll.
func (s *Store) ApplyData(d *loader.DataEvent) {
	if d == nil || len(d.Data) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	smp := s.plainBySSL[d.SSL]
	// Keep the longest sample per direction — the request line and response
	// headers are more informative than tiny chunked-encoding trailers.
	if d.Dir == 1 && len(d.Data) > len(smp.out) {
		smp.out = d.Data
	} else if d.Dir == 2 && len(d.Data) > len(smp.in) {
		smp.in = d.Data
	}
	s.plainBySSL[d.SSL] = smp
}

// UpdateSSLStats recomputes plaintext byte totals from the ssl_stats snapshot
// and joins the latest plaintext sample to each connection.
func (s *Store) UpdateSSLStats(stats []loader.SSLStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// zero then re-accumulate authoritative totals
	for _, c := range s.conns {
		c.PtxBytes, c.PrxBytes = 0, 0
	}
	for _, st := range stats {
		c := s.resolve(st.Pid, st.Fd)
		if c == nil {
			continue
		}
		c.PtxBytes += st.Ptx
		c.PrxBytes += st.Prx
		if smp, ok := s.plainBySSL[st.SSL]; ok {
			c.PlainOut = smp.out
			c.PlainIn = smp.in
		}
	}
}

// Snapshot returns a stable copy of the current connections for rendering.
func (s *Store) Snapshot() []Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Conn, 0, len(s.conns))
	for _, c := range s.conns {
		out = append(out, *c)
	}
	return out
}

// resolve maps a (pid, fd) plaintext source to a connection. Must hold s.mu.
// Strategy: exact (pid,fd)->socket via /proc when fd is known and unique;
// otherwise fall back to the sole TLS connection owned by the pid.
func (s *Store) resolve(pid uint32, fd int32) *Conn {
	if fd >= 0 {
		key := uint64(pid)<<32 | uint64(uint32(fd))
		if sock, ok := s.pidfd[key]; ok {
			if c := s.conns[sock]; c != nil {
				return c
			}
			delete(s.pidfd, key)
		}
		if ap, ok := procPeer(pid, fd); ok {
			for _, c := range s.conns {
				if c.Remote == ap {
					s.pidfd[key] = c.Sock
					return c
				}
			}
		}
	}
	// Fallback: attribute to the pid's single TLS connection.
	var match *Conn
	for _, c := range s.conns {
		if c.Pid == pid {
			if match != nil {
				return nil // ambiguous — don't guess
			}
			match = c
		}
	}
	return match
}

func ipFrom(a [4]uint32, v6 bool) netip.Addr {
	if v6 {
		var b [16]byte
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint32(b[i*4:], a[i])
		}
		return netip.AddrFrom16(b)
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], a[0])
	return netip.AddrFrom4(b)
}
