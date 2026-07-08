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

type viewMode int

const (
	viewActive viewMode = iota
	viewClosed
	viewAll
)

// Model is the bubbletea model.
type Model struct {
	store  *model.Store
	rows   []model.Conn
	sel    int
	sortBy sortMode
	view   viewMode
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
		case "tab":
			m.view = (m.view + 1) % 3
			m.sel = 0
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
	m.rows = m.rows[:0]
	if m.view == viewActive || m.view == viewAll {
		for _, c := range m.store.Snapshot() {
			if c.HasEndpoint() {
				m.rows = append(m.rows, c)
			}
		}
	}
	active := len(m.rows)
	if m.view == viewClosed || m.view == viewAll {
		// SnapshotHistory is already newest-first.
		m.rows = append(m.rows, m.store.SnapshotHistory()...)
	}
	// Sort only the active portion; history keeps its recency order.
	sortConns(m.rows[:active], m.sortBy)
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
	wState  = 9
)

func (v viewMode) String() string {
	switch v {
	case viewClosed:
		return "Closed"
	case viewAll:
		return "All"
	default:
		return "Active"
	}
}

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
	b.WriteString(styTitle.Render(" tlstat "))
	// view tabs — active highlighted
	b.WriteByte(' ')
	for _, v := range []viewMode{viewActive, viewClosed, viewAll} {
		label := " " + v.String() + " "
		if v == m.view {
			b.WriteString(styTitle.Render(label))
		} else {
			b.WriteString(styDim.Render(label))
		}
	}
	b.WriteString("  " + styDim.Render(fmt.Sprintf("%d rows, %d TLS · sort:%s", len(m.rows), tlsCount, m.sortBy)))
	b.WriteString("\n\n")

	// header — last column is state (active) or close age (closed/all)
	lastCol := "ST"
	if m.view != viewActive {
		lastCol = "CLOSED"
	}
	head := strings.Join([]string{
		trunc("PID", wPID), trunc("COMM", wComm), trunc("REMOTE / SNI", wRemote),
		trunc("VER", wVer), trunc("CIPHER", wCipher),
		trunc("WIRE ↑/↓", wIO), trunc("PLAIN ↑/↓", wIO), trunc(lastCol, wState),
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
	b.WriteString(styDim.Render("↑/↓ select · enter peek · tab active/closed/all · s sort · q quit"))
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
	// last column: close age for retired rows, TCP/TLS state otherwise
	last := "—"
	if !c.ClosedAt.IsZero() {
		last = ago(c.ClosedAt)
	} else if c.Closed {
		last = "clos"
	} else if c.IsTLS {
		last = "TLS"
	}
	cols := strings.Join([]string{
		trunc(fmt.Sprintf("%d", c.Pid), wPID),
		trunc(c.Comm, wComm),
		trunc(remote, wRemote),
		trunc(ver, wVer),
		trunc(cipher, wCipher),
		trunc(io(c.TxBytes, c.RxBytes), wIO),
		trunc(io(c.PtxBytes, c.PrxBytes), wIO),
		trunc(last, wState),
	}, " ")

	if selected {
		return stySel.Render(cols)
	}
	if !c.ClosedAt.IsZero() {
		return styDim.Render(cols) // retired rows are dimmed
	}
	if c.IsTLS {
		return styTLS.Render(cols)
	}
	return styDim.Render(cols)
}

// ago renders a compact "Ns ago" / "Nm ago" for a past timestamp.
func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
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
	if !c.ClosedAt.IsZero() {
		lifetime := c.ClosedAt.Sub(c.FirstSeen).Round(time.Millisecond)
		b.WriteString(lab("closed", fmt.Sprintf("%s  (open for %s)", ago(c.ClosedAt), lifetime)))
	}

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

	// plaintext peek — head (first bytes) + rolling tail (last bytes)
	if m.peek {
		b.WriteString(div)
		if len(c.HeadOut) == 0 && len(c.HeadIn) == 0 && len(c.TailOut) == 0 && len(c.TailIn) == 0 {
			b.WriteString(styDim.Render("  no plaintext captured (needs OpenSSL app; press enter to hide)") + "\n")
		} else {
			b.WriteString(renderPlain("SSL_write →", "sent", c.HeadOut, c.TailOut))
			b.WriteString(renderPlain("SSL_read ←", "received", c.HeadIn, c.TailIn))
		}
	}
	return b.String()
}

// renderPlain shows the head and, if distinct, the rolling tail of one
// direction's decrypted plaintext.
func renderPlain(fn, verb string, head, tail []byte) string {
	if len(head) == 0 && len(tail) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("  " + styLabel.Render("plaintext ") + styDim.Render(fmt.Sprintf("%s (cleartext %s)", fn, verb)) + "\n")
	if len(head) > 0 {
		b.WriteString("  " + styDim.Render("head:") + "\n")
		b.WriteString(indent(hexDump(head, 128)))
	}
	// Only show the tail when it carries bytes beyond the head.
	if len(tail) > 0 && !bytesEqualPrefix(head, tail) {
		b.WriteString("  " + styDim.Render(fmt.Sprintf("tail (last %s):", humanBytes(uint64(len(tail))))) + "\n")
		b.WriteString(indent(hexDump(tail, 128)))
	}
	return b.String()
}

// bytesEqualPrefix reports whether tail is fully contained at the start of head
// (i.e. the whole exchange fit in the head, so the tail adds nothing new).
func bytesEqualPrefix(head, tail []byte) bool {
	if len(tail) > len(head) {
		return false
	}
	for i := range tail {
		if head[i] != tail[i] {
			return false
		}
	}
	return true
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
