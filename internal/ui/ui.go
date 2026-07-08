// Package ui renders the live tlstat terminal UI with bubbletea.
package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/tlstat/tlstat/internal/model"
	"github.com/tlstat/tlstat/internal/tlsparse"
)

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

type sortMode int

const (
	sortActive sortMode = iota
	sortBytes
	sortPid
)

func (s sortMode) String() string {
	switch s {
	case sortBytes:
		return "bytes"
	case sortPid:
		return "pid"
	default:
		return "recent"
	}
}

// Model is the bubbletea model.
type Model struct {
	store  *model.Store
	rows   []model.Conn
	sel    int
	sortBy sortMode
	peek   bool
	w, h   int
}

// New builds the UI model over a store.
func New(store *model.Store) Model {
	return Model{store: store, sortBy: sortActive}
}

func (m Model) Init() tea.Cmd { return tick() }

// Update handles input and the refresh tick.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.sel > 0 {
				m.sel--
			}
		case "down", "j":
			if m.sel < len(m.rows)-1 {
				m.sel++
			}
		case "enter", " ":
			m.peek = !m.peek
		case "s":
			m.sortBy = (m.sortBy + 1) % 3
		case "g":
			m.sel = 0
		case "G":
			m.sel = len(m.rows) - 1
		}
	case tickMsg:
		m.refresh()
		return m, tick()
	}
	return m, nil
}

func (m *Model) refresh() {
	all := m.store.Snapshot()
	m.rows = m.rows[:0]
	for _, c := range all {
		if c.HasEndpoint() {
			m.rows = append(m.rows, c)
		}
	}
	sortConns(m.rows, m.sortBy)
	if m.sel >= len(m.rows) {
		m.sel = len(m.rows) - 1
	}
	if m.sel < 0 {
		m.sel = 0
	}
}

func sortConns(cs []model.Conn, by sortMode) {
	sort.Slice(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		// TLS connections always sort above plain ones.
		if a.IsTLS != b.IsTLS {
			return a.IsTLS
		}
		switch by {
		case sortBytes:
			return (a.TxBytes + a.RxBytes) > (b.TxBytes + b.RxBytes)
		case sortPid:
			if a.Pid != b.Pid {
				return a.Pid < b.Pid
			}
			return a.Sock < b.Sock
		default:
			return a.LastActive.After(b.LastActive)
		}
	})
}

var (
	styHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("87"))
	stySel    = lipgloss.NewStyle().Background(lipgloss.Color("24")).Foreground(lipgloss.Color("231"))
	styTLS    = lipgloss.NewStyle().Foreground(lipgloss.Color("120"))
	styDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	styLabel  = lipgloss.NewStyle().Foreground(lipgloss.Color("111"))
	styTitle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("57"))
	styWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
)

// column widths for the main table
const (
	wPID    = 7
	wComm   = 14
	wRemote = 24
	wVer    = 8
	wCipher = 30
	wIO     = 18
	wState  = 6
)

// View renders the whole screen.
func (m Model) View() string {
	if m.w == 0 {
		return "starting…"
	}
	var b strings.Builder

	tlsCount := 0
	for _, c := range m.rows {
		if c.IsTLS {
			tlsCount++
		}
	}
	title := fmt.Sprintf(" tlstat — %d connections, %d TLS ", len(m.rows), tlsCount)
	b.WriteString(styTitle.Render(title))
	b.WriteString("  " + styDim.Render(fmt.Sprintf("sort:%s", m.sortBy)))
	b.WriteString("\n\n")

	// header
	head := strings.Join([]string{
		trunc("PID", wPID), trunc("COMM", wComm), trunc("REMOTE / SNI", wRemote),
		trunc("VER", wVer), trunc("CIPHER", wCipher),
		trunc("WIRE ↑/↓", wIO), trunc("PLAIN ↑/↓", wIO), trunc("ST", wState),
	}, " ")
	b.WriteString(styHeader.Render(head))
	b.WriteByte('\n')

	// how many rows fit: reserve space for title(2)+header(1)+detail(~12)+footer(1)
	detailH := 12
	if m.peek {
		detailH = 22
	}
	maxRows := m.h - (4 + detailH + 1)
	if maxRows < 3 {
		maxRows = 3
	}

	start := 0
	if m.sel >= maxRows {
		start = m.sel - maxRows + 1
	}
	for i := start; i < len(m.rows) && i < start+maxRows; i++ {
		b.WriteString(m.renderRow(m.rows[i], i == m.sel))
		b.WriteByte('\n')
	}
	for i := len(m.rows); i < start+maxRows; i++ {
		b.WriteByte('\n')
	}

	b.WriteString(m.renderDetail())
	b.WriteString(styDim.Render("↑/↓ select · enter peek plaintext · s sort · q quit"))
	return b.String()
}

func (m Model) renderRow(c model.Conn, selected bool) string {
	remote := orDash(c.Info.SNI)
	if remote == "—" {
		remote = c.Remote.String()
	}
	ver := tlsparse.VersionName(c.Info.NegVersion)
	cipher := tlsparse.CipherName(c.Info.CipherSuite)
	if c.Preexisting && ver == "" {
		ver = "?"
		cipher = "(pre-existing)"
	}
	io := func(up, down uint64) string {
		return fmt.Sprintf("%s/%s", humanBytes(up), humanBytes(down))
	}
	st := "—"
	if c.Closed {
		st = "clos"
	} else if c.IsTLS {
		st = "TLS"
	}
	cols := strings.Join([]string{
		trunc(fmt.Sprintf("%d", c.Pid), wPID),
		trunc(c.Comm, wComm),
		trunc(remote, wRemote),
		trunc(ver, wVer),
		trunc(cipher, wCipher),
		trunc(io(c.TxBytes, c.RxBytes), wIO),
		trunc(io(c.PtxBytes, c.PrxBytes), wIO),
		trunc(st, wState),
	}, " ")

	if selected {
		return stySel.Render(cols)
	}
	if c.IsTLS {
		return styTLS.Render(cols)
	}
	return styDim.Render(cols)
}

func (m Model) renderDetail() string {
	div := styDim.Render(strings.Repeat("─", min(m.w, 100))) + "\n"
	if len(m.rows) == 0 || m.sel >= len(m.rows) {
		return div + styDim.Render("  (no connection selected)") + "\n\n"
	}
	c := m.rows[m.sel]
	lab := func(k, v string) string {
		return "  " + styLabel.Render(trunc(k, 14)) + orDash(v) + "\n"
	}

	var b strings.Builder
	b.WriteString(div)

	dir := map[uint8]string{1: "outbound (client)", 2: "inbound (server)"}[c.Direction]
	b.WriteString(lab("process", fmt.Sprintf("%s  pid=%d", c.Comm, c.Pid)))
	b.WriteString(lab("flow", fmt.Sprintf("%s → %s  %s", c.Local, c.Remote, dir)))

	// server identity
	ident := c.Info.SNI
	if c.Info.CertSubject != "" {
		ident = fmt.Sprintf("%s  (cert CN=%s)", orDash(c.Info.SNI), c.Info.CertSubject)
	}
	b.WriteString(lab("server", ident))
	if len(c.Info.CertSANs) > 0 {
		b.WriteString(lab("cert SANs", strings.Join(c.Info.CertSANs, ", ")))
	} else if c.Info.HasServerHello && c.Info.NegVersion == 0x0304 && !c.Info.HasCert {
		b.WriteString(lab("cert", styWarn.Render("encrypted (TLS 1.3)")))
	}

	// crypto
	b.WriteString(lab("version", tlsparse.VersionName(c.Info.NegVersion)))
	b.WriteString(lab("cipher", fmt.Sprintf("%s", orDash(tlsparse.CipherName(c.Info.CipherSuite)))))
	b.WriteString(lab("symmetric", tlsparse.Symmetric(c.Info.CipherSuite)))
	b.WriteString(lab("key exch", tlsparse.GroupName(c.Info.Group)))
	sig := c.Info.CertSigAlg
	if sig == "" && len(c.Info.OfferedSigs) > 0 {
		names := make([]string, 0, 3)
		for i, s := range c.Info.OfferedSigs {
			if i == 3 {
				break
			}
			names = append(names, tlsparse.SigSchemeName(s))
		}
		sig = "offered: " + strings.Join(names, ", ")
	}
	b.WriteString(lab("signature", sig))
	if len(c.Info.ALPN) > 0 {
		b.WriteString(lab("alpn", strings.Join(c.Info.ALPN, ", ")))
	}

	if c.Preexisting {
		b.WriteString("  " + styWarn.Render("pre-existing connection — handshake not captured") + "\n")
	}

	// plaintext peek
	if m.peek {
		b.WriteString(div)
		if len(c.PlainOut) == 0 && len(c.PlainIn) == 0 {
			b.WriteString(styDim.Render("  no plaintext captured (needs OpenSSL app; press enter to hide)") + "\n")
		} else {
			if len(c.PlainOut) > 0 {
				b.WriteString("  " + styLabel.Render("plaintext ") + styDim.Render("SSL_write → (cleartext sent)") + "\n")
				b.WriteString(indent(hexDump(c.PlainOut, 160)))
			}
			if len(c.PlainIn) > 0 {
				b.WriteString("  " + styLabel.Render("plaintext ") + styDim.Render("SSL_read ← (cleartext received)") + "\n")
				b.WriteString(indent(hexDump(c.PlainIn, 160)))
			}
		}
	}
	return b.String()
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = "  " + lines[i]
	}
	return strings.Join(lines, "\n") + "\n"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
