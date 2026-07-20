package main

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	dimColor    = lipgloss.Color("240")
	okColor     = lipgloss.Color("42")
	failColor   = lipgloss.Color("196")
	warnColor   = lipgloss.Color("214")
	accentColor = lipgloss.Color("39")
)

type conStyles struct {
	title, dim, ok, fail, warn, accent, box, cell lipgloss.Style
}

func newConStyles(r *lipgloss.Renderer) conStyles {
	return conStyles{
		title:  r.NewStyle().Bold(true),
		dim:    r.NewStyle().Foreground(dimColor),
		ok:     r.NewStyle().Foreground(okColor),
		fail:   r.NewStyle().Foreground(failColor),
		warn:   r.NewStyle().Foreground(warnColor),
		accent: r.NewStyle().Foreground(accentColor),
		box:    r.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(dimColor).Padding(0, 1).Bold(true),
		cell:   r.NewStyle().Padding(0, 1),
	}
}

const (
	statusOK = iota
	statusFlaky
	statusNone
)

type endpointResult struct {
	ip       netip.Addr
	endpoint string
	exit     traceResult
	latency  time.Duration
	ok       bool
	durable  bool
}

func (r endpointResult) pingStr() string { return latencyStr(r.latency) }

func latencyStr(d time.Duration) string {
	if d <= 0 {
		return "?"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func (r endpointResult) working() bool { return r.ok && r.durable }
func (r endpointResult) flaky() bool   { return r.ok && !r.durable }

func withFlag(flag, code string) string {
	if flag == "" {
		return code
	}
	return flag + " " + code
}

func exitRegion(t traceResult) string {
	if t.loc == "" {
		return "?"
	}
	return withFlag(flagEmoji(t.loc), t.loc)
}

func exitColo(t traceResult) string {
	if t.colo == "" {
		return "?"
	}
	return withFlag(coloFlag(t.colo), t.colo)
}

func exitColosOf(phases []phaseResult) []string {
	seen := make(map[string]struct{})
	var colos []string
	for _, ph := range phases {
		for _, r := range ph.results {
			c := r.exit.colo
			if c == "" {
				continue
			}
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			colos = append(colos, c)
		}
	}
	return colos
}

func workingSorted(results []endpointResult) []endpointResult {
	return filterSorted(results, endpointResult.working)
}

func flakySorted(results []endpointResult) []endpointResult {
	return filterSorted(results, endpointResult.flaky)
}

func filterSorted(results []endpointResult, keep func(endpointResult) bool) []endpointResult {
	out := make([]endpointResult, 0, len(results))
	for _, r := range results {
		if keep(r) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return lessByPing(out[i], out[j]) })
	return out
}

func lessByPing(a, b endpointResult) bool {
	if a.latency != b.latency {
		return lessDur(a.latency, b.latency)
	}
	return a.endpoint < b.endpoint
}

func lessDur(a, b time.Duration) bool {
	if (a <= 0) != (b <= 0) {
		return a > 0
	}
	return a < b
}

func bestByPing(picks []endpointResult) endpointResult {
	best := picks[0]
	for _, r := range picks[1:] {
		if lessByPing(r, best) {
			best = r
		}
	}
	return best
}

func writeHeader(w io.Writer, working, probed int) {
	fmt.Fprintln(w, "════════════════════════════════════════════════════════")
	fmt.Fprintf(w, "  WARP endpoints: %d working / %d probed\n", working, probed)
	fmt.Fprintln(w, "  EXIT = exit region external services see through the tunnel")
	fmt.Fprintln(w, "  COLO = Cloudflare WARP edge node the tunnel landed on")
	fmt.Fprintln(w, "════════════════════════════════════════════════════════")
}

func writeFullReport(w io.Writer, results []endpointResult) {
	working := workingSorted(results)
	flaky := flakySorted(results)
	writeHeader(w, len(working), len(results))
	if len(flaky) > 0 {
		fmt.Fprintf(w, "  %d flaky (handshake ok, dropped on re-probe)\n", len(flaky))
	}
	if len(working) == 0 && len(flaky) == 0 {
		fmt.Fprintln(w, "\nNo working endpoints found.")
		return
	}

	for _, base := range pools {
		subnet := subnetEndpoints(working, base)
		subnetFlaky := subnetEndpoints(flaky, base)
		if len(subnet) == 0 && len(subnetFlaky) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  ── %s0/24 ──  (sorted by ping)\n", base)
		for _, r := range subnet {
			fmt.Fprintf(w, "    %-22s %-8s %-10s %s\n", r.endpoint, r.pingStr(), exitRegion(r.exit), exitColo(r.exit))
		}
		for _, r := range subnetFlaky {
			fmt.Fprintf(w, "    %-22s %-8s %-10s %-10s %s\n", r.endpoint, r.pingStr(), exitRegion(r.exit), exitColo(r.exit), "flaky")
		}
	}

	if len(working) > 0 {
		writeSubnetPicks(w, working)
	}
}

func subnetEndpoints(working []endpointResult, base string) []endpointResult {
	var picks []endpointResult
	for _, r := range working {
		if strings.HasPrefix(r.ip.String(), base) {
			picks = append(picks, r)
		}
	}
	return picks
}

func writeConsole(w io.Writer, ph phaseResult, r *lipgloss.Renderer) {
	st := newConStyles(r)
	results := ph.results
	working := workingSorted(results)
	flaky := flakySorted(results)
	fmt.Fprintln(w)
	if len(working) == 0 {
		fmt.Fprintln(w, st.fail.Render("No working endpoints found."))
		writeFlakyNote(w, st, len(flaky))
		return
	}

	fmt.Fprintln(w, banner(st))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Proto:    %s\n", st.accent.Render(strings.ToUpper(ph.run.name)))
	fmt.Fprintf(w, "Colo:     %s\n", st.accent.Render(uniqueSorted(working, func(r endpointResult) string { return r.exit.colo }, coloFlag)))
	fmt.Fprintf(w, "Regions:  %s\n", st.accent.Render(uniqueSorted(working, func(r endpointResult) string { return r.exit.loc }, flagEmoji)))
	fmt.Fprintf(w, "Working:  %s\n", st.ok.Render(strconv.Itoa(len(working)))+st.dim.Render(" / ")+strconv.Itoa(len(results))+" probed")
	writeFlakyNote(w, st, len(flaky))
	writePicksTable(w, st, working, flaky)
}

func writeFlakyNote(w io.Writer, st conStyles, n int) {
	if n == 0 {
		return
	}
	fmt.Fprintf(w, "Flaky:    %s\n", st.warn.Render(fmt.Sprintf("%d (handshake ok, dropped on re-probe)", n)))
}

func banner(st conStyles) string {
	return st.box.Render("WARPSCOUT")
}

type pickRow struct {
	cells   []string
	status  int
	latency time.Duration
}

func writePicksTable(w io.Writer, st conStyles, working, flaky []endpointResult) {
	var rows []pickRow
	for _, base := range pools {
		subnet := base + "0/24"
		if picks := subnetEndpoints(working, base); len(picks) > 0 {
			r := bestByPing(picks)
			rows = append(rows, pickRow{[]string{subnet, r.endpoint, r.pingStr(), exitRegion(r.exit), exitColo(r.exit)}, statusOK, r.latency})
			continue
		}
		if picks := subnetEndpoints(flaky, base); len(picks) > 0 {
			r := bestByPing(picks)
			rows = append(rows, pickRow{[]string{subnet, r.endpoint, r.pingStr(), "flaky", ""}, statusFlaky, 0})
			continue
		}
		rows = append(rows, pickRow{[]string{subnet, "no working endpoints", "", "", ""}, statusNone, 0})
	}
	sort.SliceStable(rows, func(i, j int) bool { return lessDur(rows[i].latency, rows[j].latency) })

	fmt.Fprintln(w, "\n"+st.title.Render("Best endpoint per subnet (lowest ping)"))
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(st.dim).
		Headers("SUBNET", "ENDPOINT", "PING", "EXIT", "COLO").
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return st.cell.Bold(true)
			}
			switch rows[row].status {
			case statusFlaky:
				return st.cell.Foreground(warnColor)
			case statusNone:
				if col == 1 {
					return st.cell.Foreground(failColor)
				}
				return st.cell.Foreground(dimColor)
			}
			switch col {
			case 1:
				return st.cell.Bold(true)
			case 2, 3:
				return st.cell.Foreground(accentColor)
			}
			return st.cell
		})
	for _, pr := range rows {
		t.Row(pr.cells...)
	}
	fmt.Fprintln(w, t.Render())
}

type bothRow struct {
	cells                 []string
	wgStat, awgStat, pick int
	latency               time.Duration
}

func writeConsoleBoth(w io.Writer, phases []phaseResult, r *lipgloss.Renderer) {
	st := newConStyles(r)
	var wg, awg []endpointResult
	for _, ph := range phases {
		if ph.run.awg {
			awg = ph.results
		} else {
			wg = ph.results
		}
	}
	wgWork, wgFlaky := workingSorted(wg), flakySorted(wg)
	awgWork, awgFlaky := workingSorted(awg), flakySorted(awg)

	probed := len(wg)
	if probed == 0 {
		probed = len(awg)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, banner(st))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Working:  wg %s%sawg %s of %d probed\n",
		st.ok.Render(strconv.Itoa(len(wgWork))), st.dim.Render(" / "), st.ok.Render(strconv.Itoa(len(awgWork))), probed)
	fmt.Fprintln(w)

	protoStatus := func(work, flaky []endpointResult, base string) (string, int) {
		if len(subnetEndpoints(work, base)) > 0 {
			return "OK", statusOK
		}
		if len(subnetEndpoints(flaky, base)) > 0 {
			return "flaky", statusFlaky
		}
		return "-", statusNone
	}

	var rows []bothRow
	for _, base := range pools {
		wgTxt, wgStat := protoStatus(wgWork, wgFlaky, base)
		awgTxt, awgStat := protoStatus(awgWork, awgFlaky, base)
		endpoint, ping, region, colo, latency, isFlaky := bestPick(base, wgWork, awgWork, wgFlaky, awgFlaky)
		pick := statusOK
		if isFlaky {
			pick = statusFlaky
		}
		if endpoint == "" {
			endpoint, ping, region, colo, pick = "-", "", "", "", statusNone
		}
		rows = append(rows, bothRow{[]string{base + "0/24", wgTxt, awgTxt, endpoint, ping, region, colo}, wgStat, awgStat, pick, latency})
	}
	sort.SliceStable(rows, func(i, j int) bool { return lessDur(rows[i].latency, rows[j].latency) })

	protoStyle := func(s int) lipgloss.Style {
		switch s {
		case statusOK:
			return st.cell.Foreground(okColor)
		case statusFlaky:
			return st.cell.Foreground(warnColor)
		}
		return st.cell.Foreground(dimColor)
	}

	fmt.Fprintln(w, st.title.Render("WireGuard vs AmneziaWG per subnet"))
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(st.dim).
		Headers("SUBNET", "WG", "AWG", "ENDPOINT", "PING", "EXIT", "COLO").
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return st.cell.Bold(true)
			}
			br := rows[row]
			switch col {
			case 1:
				return protoStyle(br.wgStat)
			case 2:
				return protoStyle(br.awgStat)
			}
			switch br.pick {
			case statusFlaky:
				return st.cell.Foreground(warnColor)
			case statusNone:
				return st.cell.Foreground(dimColor)
			}
			switch col {
			case 3:
				return st.cell.Bold(true)
			case 4, 5:
				return st.cell.Foreground(accentColor)
			}
			return st.cell
		})
	for _, br := range rows {
		t.Row(br.cells...)
	}
	fmt.Fprintln(w, t.Render())
}

func bestPick(base string, sets ...[]endpointResult) (endpoint, ping, region, colo string, latency time.Duration, flaky bool) {
	for i, set := range sets {
		if picks := subnetEndpoints(set, base); len(picks) > 0 {
			r := bestByPing(picks)
			return r.endpoint, r.pingStr(), exitRegion(r.exit), exitColo(r.exit), r.latency, i >= 2
		}
	}
	return "", "", "", "", 0, false
}

func uniqueSorted(working []endpointResult, key func(endpointResult) string, flagFor func(string) string) string {
	seen := make(map[string]struct{})
	for _, r := range working {
		if v := key(r); v != "" {
			seen[v] = struct{}{}
		}
	}
	vals := make([]string, 0, len(seen))
	for v := range seen {
		vals = append(vals, v)
	}
	sort.Strings(vals)
	for i, v := range vals {
		vals[i] = withFlag(flagFor(v), v)
	}
	return strings.Join(vals, "  ")
}

func writeSubnetPicks(w io.Writer, working []endpointResult) {
	type line struct {
		text    string
		latency time.Duration
	}
	var lines []line
	for _, base := range pools {
		picks := subnetEndpoints(working, base)
		subnet := base + "0/24"
		if len(picks) == 0 {
			lines = append(lines, line{fmt.Sprintf("  %-18s %s", subnet, "no working endpoints"), 0})
			continue
		}
		r := bestByPing(picks)
		lines = append(lines, line{fmt.Sprintf("  %-18s %-22s %-8s %-10s %s", subnet, r.endpoint, r.pingStr(), exitRegion(r.exit), exitColo(r.exit)), r.latency})
	}
	sort.SliceStable(lines, func(i, j int) bool { return lessDur(lines[i].latency, lines[j].latency) })

	fmt.Fprintln(w, "\n  ── Best working endpoint per subnet (lowest ping) ──")
	for _, l := range lines {
		fmt.Fprintln(w, l.text)
	}
}

type phaseResult struct {
	run     protoRun
	results []endpointResult
}

func writeToFile(path string, phases []phaseResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for i, ph := range phases {
		if len(phases) > 1 {
			if i > 0 {
				fmt.Fprintln(f)
			}
			fmt.Fprintf(f, "########## proto=%s ##########\n", ph.run.name)
		}
		writeFullReport(f, ph.results)
	}
	return nil
}
