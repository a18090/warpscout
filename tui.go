package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type (
	stepMsg struct {
		label, summary string
		done, fail     bool
	}
	barBeginMsg struct {
		label string
		total int
	}
	probedMsg struct{}
	foundMsg  struct {
		endpoint string
		epPing   time.Duration
		tunPing  time.Duration
		loss     float32
		measured bool
		exit     string
		colo     string
		torn     bool
	}
	barEndMsg struct{ label, summary string }
	doneMsg   struct{}
)

type emitter func(tea.Msg)

func plainEmit(msg tea.Msg) {
	switch m := msg.(type) {
	case stepMsg:
		switch {
		case m.fail:
			fmt.Fprintln(os.Stderr, m.summary)
		case m.done:
			fmt.Fprintf(os.Stderr, "%s: %s\n", m.label, m.summary)
		default:
			fmt.Fprintln(os.Stderr, m.label+"...")
		}
	case barBeginMsg:
		fmt.Fprintf(os.Stderr, "%s: %d...\n", m.label, m.total)
	case barEndMsg:
		fmt.Fprintf(os.Stderr, "%s: %s\n", m.label, m.summary)
	}
}

const feedMax = 12

type scanModel struct {
	cancel   context.CancelFunc
	ping     bool
	header   string
	quitHint string
	st       conStyles
	spin     spinner.Model
	bar      progress.Model

	lines []string
	step  string
	label string
	total int
	done  int
	feed  []foundMsg

	finished bool
}

func newScanModel(cancel context.CancelFunc, ping bool) scanModel {
	st := newConStyles(lipgloss.NewRenderer(os.Stderr))
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = st.accent
	return scanModel{
		cancel:   cancel,
		ping:     ping,
		quitHint: "q to quit",
		st:       st,
		spin:     sp,
		bar:      progress.New(progress.WithDefaultGradient(), progress.WithWidth(28)),
	}
}

func (m scanModel) Init() tea.Cmd { return m.spin.Tick }

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			if m.cancel != nil {
				m.cancel()
			}
			m.finished = true
			return m, tea.Quit
		}

	case stepMsg:
		switch {
		case msg.fail:
			m.step = ""
			m.lines = append(m.lines, m.st.fail.Render("✗ "+msg.summary))
		case msg.done:
			m.step = ""
			m.lines = append(m.lines, m.st.ok.Render("✔ ")+m.st.title.Render(msg.label)+": "+msg.summary)
		default:
			m.step = msg.label
		}
		return m, nil

	case barBeginMsg:
		m.label, m.total, m.done = msg.label, msg.total, 0
		return m, m.bar.SetPercent(0)

	case probedMsg:
		if m.total > 0 {
			m.done++
			return m, m.bar.SetPercent(float64(m.done) / float64(m.total))
		}
		return m, nil

	case foundMsg:
		m.feed = append(m.feed, msg)
		sort.SliceStable(m.feed, func(i, j int) bool { return lessLatency(m.feed[i], m.feed[j]) })
		return m, nil

	case barEndMsg:
		m.label, m.total, m.done = "", 0, 0
		m.lines = append(m.lines, m.st.ok.Render("✔ ")+m.st.title.Render(msg.label)+": "+msg.summary)
		return m, nil

	case doneMsg:
		m.finished = true
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case progress.FrameMsg:
		pm, cmd := m.bar.Update(msg)
		m.bar = pm.(progress.Model)
		return m, cmd
	}
	return m, nil
}

func lessLatency(a, b foundMsg) bool {
	if a.loss != b.loss {
		return a.loss < b.loss
	}
	pa, pb := a.sortPing(), b.sortPing()
	if (pa <= 0) != (pb <= 0) {
		return pa > 0
	}
	if pa != pb {
		return pa < pb
	}
	return a.endpoint < b.endpoint
}

func (m foundMsg) sortPing() time.Duration {
	if m.measured {
		return m.tunPing
	}
	return m.epPing
}

func (m foundMsg) lossStr() string {
	if !m.measured {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", m.loss*100)
}

func (m scanModel) View() string {
	st := m.st
	var b strings.Builder
	if m.header != "" {
		b.WriteString(st.title.Render(m.header) + "\n\n")
	}

	for _, l := range m.lines {
		b.WriteString(l + "\n")
	}
	if m.step != "" {
		b.WriteString(m.spin.View() + " " + st.title.Render(m.step) + "\n")
	}
	if m.total > 0 {
		b.WriteString(m.spin.View() + " " + st.title.Render(m.label) + "\n")
		b.WriteString("  " + m.bar.View() + fmt.Sprintf("  %d/%d\n", m.done, m.total))
	}

	if len(m.feed) > 0 {
		b.WriteString("\n" + m.renderFeed())
	}
	if !m.finished {
		b.WriteString("\n" + st.dim.Render(m.quitHint) + "\n")
	}
	return b.String()
}

func (m scanModel) renderFeed() string {
	st := m.st
	pad := func(s string, n int) string { return fmt.Sprintf("%-*s", n, s) }
	rows := m.feed
	extra := 0
	if len(rows) > feedMax {
		extra = len(rows) - feedMax
		rows = rows[:feedMax]
	}
	tunHead := ""
	if m.ping {
		tunHead = pad("TUN PING", 9) + " " + pad("LOSS", 6) + " "
	}
	var b strings.Builder
	b.WriteString(st.dim.Render(pad("ENDPOINT", 22)+" "+pad("ENDPOINT PING", 13)+" "+tunHead+pad("SEEN AS", 10)+" NODE") + "\n")
	for _, r := range rows {
		ep := pad(r.endpoint, 22)
		ping := pad(latencyStr(r.epPing), 13)
		tun := ""
		if m.ping {
			tun = pad(latencyStr(r.tunPing), 9) + " " + pad(r.lossStr(), 6) + " "
		}
		if r.torn {
			b.WriteString(st.warn.Render(ep+" "+ping+" "+tun+"torn down") + "\n")
			continue
		}
		exit := r.exit + strings.Repeat(" ", max(0, 10-lipgloss.Width(r.exit)))
		tunSeg := ""
		if m.ping {
			tunSeg = st.accent.Render(tun)
		}
		b.WriteString(st.title.Render(ep) + " " + st.accent.Render(ping) + " " + tunSeg + exit + " " + r.colo + "\n")
	}
	if extra > 0 {
		b.WriteString(st.dim.Render(fmt.Sprintf("… +%d more", extra)) + "\n")
	}
	return b.String()
}
