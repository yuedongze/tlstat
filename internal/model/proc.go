package model

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// procPeer resolves the remote endpoint of a process's socket fd by reading
// /proc/<pid>/fd/<fd> to get the socket inode, then locating that inode in
// /proc/net/tcp{,6}. Best-effort: returns ok=false on any failure.
func procPeer(pid uint32, fd int32) (netip.AddrPort, bool) {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil || !strings.HasPrefix(link, "socket:[") {
		return netip.AddrPort{}, false
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if ap, ok := scanNetTCP(path, inode); ok {
			return ap, true
		}
	}
	return netip.AddrPort{}, false
}

// scanNetTCP finds the line whose inode column matches and returns its remote
// address:port.
func scanNetTCP(path, inode string) (netip.AddrPort, bool) {
	f, err := os.Open(path)
	if err != nil {
		return netip.AddrPort{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		// sl local rem st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
		if len(fields) < 10 || fields[9] != inode {
			continue
		}
		if ap, ok := parseHexAddr(fields[2]); ok {
			return ap, true
		}
	}
	return netip.AddrPort{}, false
}

// parseHexAddr parses a "HEXADDR:HEXPORT" token from /proc/net/tcp{,6}.
func parseHexAddr(tok string) (netip.AddrPort, bool) {
	i := strings.IndexByte(tok, ':')
	if i < 0 {
		return netip.AddrPort{}, false
	}
	addrHex, portHex := tok[:i], tok[i+1:]
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	switch len(addrHex) {
	case 8: // IPv4: one host-order word
		v, err := strconv.ParseUint(addrHex, 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		b := [4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
		return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(port)), true
	case 32: // IPv6: four host-order words, each byte-reversed
		var b [16]byte
		for w := 0; w < 4; w++ {
			v, err := strconv.ParseUint(addrHex[w*8:w*8+8], 16, 32)
			if err != nil {
				return netip.AddrPort{}, false
			}
			b[w*4+0] = byte(v)
			b[w*4+1] = byte(v >> 8)
			b[w*4+2] = byte(v >> 16)
			b[w*4+3] = byte(v >> 24)
		}
		return netip.AddrPortFrom(netip.AddrFrom16(b), uint16(port)), true
	}
	return netip.AddrPort{}, false
}
