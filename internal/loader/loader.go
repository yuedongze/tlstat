package loader

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Exported, padding-free mirrors of the eBPF structs, so other packages don't
// touch the generated (unexported) bpf2go types.

// Flow is a per-socket snapshot from the `flows` map.
type Flow struct {
	Sock      uint64
	Pid       uint32
	Saddr     [4]uint32
	Daddr     [4]uint32
	Sport     uint16
	Dport     uint16
	IsIPv6    bool
	Direction uint8
	IsTLS     bool
	Closed    bool
	Comm      string
	Tx        uint64
	Rx        uint64
}

// SSLStat is a per-SSL snapshot from the `ssl_stats` map.
type SSLStat struct {
	SSL uint64
	Ptx uint64
	Prx uint64
	Pid uint32
	Fd  int32
}

// WireEvent is a captured run of TLS records off the wire.
type WireEvent struct {
	Dir  uint8
	Sock uint64
	Data []byte
}

// DataEvent is a captured plaintext sample from the TLS library uprobe.
type DataEvent struct {
	Dir  uint8
	Pid  uint32
	Tid  uint32
	Fd   int32
	SSL  uint64
	Data []byte
}

// Loader owns the loaded eBPF objects, attachments, and the ring buffer.
type Loader struct {
	objs   tlstatObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New loads the eBPF objects and attaches every program. libsslPath is the
// shared object to attach the OpenSSL uprobes to; if empty, uprobes are skipped.
func New(libsslPath string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	l := &Loader{}
	if err := loadTlstatObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}

	// Kernel wire probes.
	must := func(lk link.Link, err error) error {
		if err != nil {
			return err
		}
		l.links = append(l.links, lk)
		return nil
	}
	if err := errors.Join(
		must(link.Kprobe("tcp_sendmsg", l.objs.K_tcpSendmsg, nil)),
		must(link.Kprobe("tcp_recvmsg", l.objs.K_tcpRecvmsg, nil)),
		must(link.Kretprobe("tcp_recvmsg", l.objs.KrTcpRecvmsg, nil)),
		must(link.Tracepoint("sock", "inet_sock_set_state", l.objs.TpInetSockSetState, nil)),
	); err != nil {
		l.Close()
		return nil, fmt.Errorf("attach kernel probes: %w", err)
	}

	// OpenSSL uprobes (best-effort; a missing symbol shouldn't be fatal).
	if libsslPath != "" {
		if err := l.attachSSL(libsslPath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: OpenSSL uprobes: %v\n", err)
		}
	}

	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ringbuf: %w", err)
	}
	l.reader = rd
	return l, nil
}

func (l *Loader) attachSSL(path string) error {
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return err
	}
	type up struct {
		sym  string
		prog *ebpf.Program
		ret  bool
	}
	for _, u := range []up{
		{"SSL_set_fd", l.objs.U_sslSetFd, false},
		{"SSL_write", l.objs.U_sslWrite, false},
		{"SSL_read", l.objs.U_sslRead, false},
		{"SSL_read", l.objs.UrSslRead, true},
	} {
		var lk link.Link
		var err error
		if u.ret {
			lk, err = ex.Uretprobe(u.sym, u.prog, nil)
		} else {
			lk, err = ex.Uprobe(u.sym, u.prog, nil)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", u.sym, err)
		}
		l.links = append(l.links, lk)
	}
	return nil
}

// ReadEvent blocks for the next ring buffer record and decodes it. Returns
// (wire, data) where exactly one is non-nil, or an error.
func (l *Loader) ReadEvent() (*WireEvent, *DataEvent, error) {
	rec, err := l.reader.Read()
	if err != nil {
		return nil, nil, err
	}
	b := rec.RawSample
	if len(b) < 1 {
		return nil, nil, nil
	}
	switch b[0] {
	case 1: // EVENT_WIRE
		if len(b) < 12 {
			return nil, nil, nil
		}
		w := &WireEvent{
			Dir:  b[1],
			Sock: le64(b[4:]),
		}
		n := int(le16(b[2:]))
		if 12+n <= len(b) {
			w.Data = append([]byte(nil), b[12:12+n]...)
		}
		return w, nil, nil
	case 2: // EVENT_DATA
		if len(b) < 24 {
			return nil, nil, nil
		}
		d := &DataEvent{
			Dir: b[1],
			Pid: le32(b[4:]),
			Tid: le32(b[8:]),
			Fd:  int32(le32(b[12:])),
			SSL: le64(b[16:]),
		}
		n := int(le16(b[2:]))
		if 24+n <= len(b) {
			d.Data = append([]byte(nil), b[24:24+n]...)
		}
		return nil, d, nil
	}
	return nil, nil, nil
}

// Flows returns a snapshot of every tracked socket.
func (l *Loader) Flows() ([]Flow, error) {
	var out []Flow
	var k uint64
	var v tlstatFlow
	it := l.objs.Flows.Iterate()
	for it.Next(&k, &v) {
		out = append(out, Flow{
			Sock:      k,
			Pid:       v.Pid,
			Saddr:     v.Saddr,
			Daddr:     v.Daddr,
			Sport:     v.Sport,
			Dport:     v.Dport,
			IsIPv6:    v.IsIpv6 != 0,
			Direction: v.Direction,
			IsTLS:     v.IsTls != 0,
			Closed:    v.Closed != 0,
			Comm:      cstr(v.Comm[:]),
			Tx:        v.Tx,
			Rx:        v.Rx,
		})
	}
	return out, it.Err()
}

// SSLStats returns a snapshot of every tracked SSL session.
func (l *Loader) SSLStats() ([]SSLStat, error) {
	var out []SSLStat
	var k uint64
	var v tlstatSslStat
	it := l.objs.SslStats.Iterate()
	for it.Next(&k, &v) {
		out = append(out, SSLStat{SSL: k, Ptx: v.Ptx, Prx: v.Prx, Pid: v.Pid, Fd: v.Fd})
	}
	return out, it.Err()
}

// DeleteFlow removes a closed socket from the map so it stops being reported.
func (l *Loader) DeleteFlow(sock uint64) { _ = l.objs.Flows.Delete(&sock) }

// Close detaches everything and releases resources.
func (l *Loader) Close() {
	if l.reader != nil {
		l.reader.Close()
	}
	for _, lk := range l.links {
		lk.Close()
	}
	l.objs.Close()
}

func cstr(b []int8) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func le64(b []byte) uint64 { return uint64(le32(b)) | uint64(le32(b[4:]))<<32 }
