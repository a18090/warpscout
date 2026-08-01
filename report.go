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
		box:    r.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(dimColor).Padding(0, 1),
		cell:   r.NewStyle().Padding(0, 1),
	}
}

const projectURL = "https://github.com/vernette/warpscout"

const (
	statusOK = iota
	statusFlaky
	statusNone
)

type endpointResult struct {
	ip       netip.Addr
	endpoint string
	exit     metaResult
	latency  time.Duration // host ICMP ping to the bare IP (off-tunnel)
	rtt      time.Duration // in-tunnel RTT to 1.1.1.1, valid only when measured
	loss     float32       // in-tunnel packet loss 0..1, valid only when measured
	measured bool          // rtt/loss were sampled (-ping)
	ok       bool
	durable  bool
}

func (r endpointResult) ping() time.Duration {
	if r.measured {
		return r.rtt
	}
	return r.latency
}

func (r endpointResult) pingStr() string { return latencyStr(r.ping()) }

func (r endpointResult) lossStr() string {
	if !r.measured {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", r.loss*100)
}

func lossCol(v string, ping bool) string {
	if !ping {
		return ""
	}
	return fmt.Sprintf("%-6s ", v)
}

func lossField(r endpointResult, ping bool) string { return lossCol(r.lossStr(), ping) }

func sortNote(ping bool) string {
	if ping {
		return "sorted by loss, then ping"
	}
	return "sorted by ping"
}

func bestNote(ping bool) string {
	if ping {
		return "lowest loss, then ping"
	}
	return "lowest ping"
}

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

func noFlag(string) string { return "" }

func withFlag(flag, code string) string {
	if flag == "" {
		return code
	}
	return flag + " " + code
}

func exitRegion(t metaResult) string {
	if t.loc == "" {
		return "?"
	}
	return withFlag(flagEmoji(t.loc), t.loc)
}

func exitColo(t metaResult) string {
	if t.colo == "" {
		return "?"
	}
	return t.colo
}

func exitColoLocation(t metaResult) string { return coloLocation(t) }

// An empty row is only worth showing when the scan really covered the whole
// subnet, so subnets a filter emptied are dropped.
func poolsWithHits(ph phaseResult) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(pools))
	for _, p := range pools {
		if len(subnetEndpoints(ph.results, p)) > 0 {
			out = append(out, p)
		}
	}
	return out
}

func filterByColo(ph phaseResult, colos []string) phaseResult {
	keep := upperSet(colos)
	return filterResults(ph, func(r endpointResult) bool {
		_, ok := keep[strings.ToUpper(r.exit.colo)]
		return ok
	})
}

func filterByCountry(ph phaseResult, countries []string) phaseResult {
	keep := upperSet(countries)
	return filterResults(ph, func(r endpointResult) bool {
		if r.exit.coloISO == "" {
			return false
		}
		_, ok := keep[strings.ToUpper(r.exit.coloISO)]
		return ok
	})
}

func upperSet(vals []string) map[string]struct{} {
	set := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		set[strings.ToUpper(v)] = struct{}{}
	}
	return set
}

func filterResults(ph phaseResult, keep func(endpointResult) bool) phaseResult {
	var kept []endpointResult
	for _, r := range ph.results {
		if keep(r) {
			kept = append(kept, r)
		}
	}
	return phaseResult{ph.run, kept}
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
	sort.Slice(out, func(i, j int) bool { return lessByLossRTT(out[i], out[j]) })
	return out
}

// Loss before ping, mirroring CloudflareWarpSpeedTest. Unmeasured endpoints
// carry loss 0, so without -ping this degrades to ping-only ordering.
func lessByLossRTT(a, b endpointResult) bool {
	if a.loss != b.loss {
		return a.loss < b.loss
	}
	if a.ping() != b.ping() {
		return lessDur(a.ping(), b.ping())
	}
	return a.endpoint < b.endpoint
}

func lessLossDur(la float32, da time.Duration, lb float32, db time.Duration) bool {
	if la != lb {
		return la < lb
	}
	return lessDur(da, db)
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
		if lessByLossRTT(r, best) {
			best = r
		}
	}
	return best
}

const (
	reportRowFmt   = "%-22s %-8s %s%-10s %-6s %s\n"
	nodePickRowFmt = "%-6s %-22s %-8s %s%-10s %s\n"
)

func writeHeader(w io.Writer, working, probed int, ping bool) {
	fmt.Fprintf(w, "# WARP endpoints: %d working / %d probed\n", working, probed)
	fmt.Fprintf(w, "# %s\n", sortNote(ping))
	fmt.Fprintln(w, "# SEEN AS = region external services see through the tunnel")
	fmt.Fprintln(w, "# NODE / NODE LOCATION = Cloudflare WARP edge node the tunnel landed on, and where it sits")
	fmt.Fprintln(w, "# One /24 pool can land on several different nodes - NODE is per endpoint, not per subnet")
}

func writeFullReport(w io.Writer, results []endpointResult, ping bool) {
	working := workingSorted(results)
	flaky := flakySorted(results)
	writeHeader(w, len(working), len(results), ping)
	if len(working) == 0 && len(flaky) == 0 {
		fmt.Fprintln(w, "\nNo working endpoints found.")
		return
	}

	if len(working) > 0 {
		fmt.Fprintln(w)
		writeRows(w, working, ping)
	}
	if len(flaky) > 0 {
		fmt.Fprintf(w, "\n# %d flaky (handshake ok, dropped on re-probe)\n", len(flaky))
		writeRows(w, flaky, ping)
	}
	if len(working) > 0 {
		writeNodePicks(w, working, ping)
	}
}

func writeRows(w io.Writer, results []endpointResult, ping bool) {
	fmt.Fprintf(w, reportRowFmt, "ENDPOINT", "PING", lossCol("LOSS", ping), "SEEN AS", "NODE", "NODE LOCATION")
	for _, r := range results {
		fmt.Fprintf(w, reportRowFmt, r.endpoint, r.pingStr(), lossField(r, ping), exitRegion(r.exit), exitColo(r.exit), exitColoLocation(r.exit))
	}
}

func subnetEndpoints(working []endpointResult, p netip.Prefix) []endpointResult {
	var picks []endpointResult
	for _, r := range working {
		if p.Contains(r.ip) {
			picks = append(picks, r)
		}
	}
	return picks
}

func writeConsole(w io.Writer, ph phaseResult, r *lipgloss.Renderer, ping bool) {
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
	writeJunkNote(w, st, ph.run.awg)
	fmt.Fprintf(w, "Nodes:    %s\n", st.accent.Render(uniqueSorted(working, func(r endpointResult) string { return r.exit.colo }, noFlag)))
	fmt.Fprintf(w, "Seen as:  %s\n", st.accent.Render(uniqueSorted(working, func(r endpointResult) string { return r.exit.loc }, flagEmoji)))
	fmt.Fprintf(w, "Working:  %s\n", st.ok.Render(strconv.Itoa(len(working)))+st.dim.Render(" / ")+strconv.Itoa(len(results))+" probed")
	writeFlakyNote(w, st, len(flaky))
	writePicksTable(w, st, working, flaky, ping)
}

func writeJunkNote(w io.Writer, st conStyles, awg bool) {
	if !awg {
		return
	}
	fmt.Fprintf(w, "Junk:     %s %s\n",
		st.accent.Render(fmt.Sprintf("jc=%d jmin=%d jmax=%d", awgJc, awgJmin, awgJmax)),
		st.dim.Render("("+i1Note()+")"))
}

func writeFlakyNote(w io.Writer, st conStyles, n int) {
	if n == 0 {
		return
	}
	fmt.Fprintf(w, "Flaky:    %s\n", st.warn.Render(fmt.Sprintf("%d (handshake ok, dropped on re-probe)", n)))
}

func banner(st conStyles) string {
	heart := "<3"
	if showEmoji {
		// U+2764 with VS16 measures as one cell but renders as two, so the box
		// misaligns - a U+1F49x heart is measured and rendered the same width.
		heart = "💕"
	}
	credit := st.dim.Render("Made with ") + st.fail.Render(heart) + st.dim.Render(" by vernette")
	return st.box.Render(lipgloss.JoinVertical(lipgloss.Center,
		st.title.Render("WARPSCOUT"),
		credit,
		st.dim.Render(projectURL),
	))
}

type pickRow struct {
	cells   []string
	status  int
	loss    float32
	latency time.Duration
}

func lossCell(r endpointResult, ping bool) []string {
	if !ping {
		return nil
	}
	return []string{r.lossStr()}
}

func lossHeader(ping bool) []string {
	if !ping {
		return nil
	}
	return []string{"LOSS"}
}

func metricCols(ping bool, pingCol int) map[int]bool {
	cols := map[int]bool{pingCol: true}
	if ping {
		cols[pingCol+1] = true
	}
	return cols
}

func writePicksTable(w io.Writer, st conStyles, working, flaky []endpointResult, ping bool) {
	var rows []pickRow
	for _, p := range pools {
		subnet := p.String()
		if picks := subnetEndpoints(working, p); len(picks) > 0 {
			r := bestByPing(picks)
			cells := append([]string{subnet, r.endpoint, r.pingStr()}, lossCell(r, ping)...)
			cells = append(cells, exitRegion(r.exit), exitColo(r.exit), exitColoLocation(r.exit))
			rows = append(rows, pickRow{cells, statusOK, r.loss, r.ping()})
			continue
		}
		if picks := subnetEndpoints(flaky, p); len(picks) > 0 {
			r := bestByPing(picks)
			cells := append([]string{subnet, r.endpoint, r.pingStr()}, lossCell(r, ping)...)
			cells = append(cells, "flaky", "", "")
			rows = append(rows, pickRow{cells, statusFlaky, r.loss, r.ping()})
			continue
		}
		cells := []string{subnet, "no working endpoints", ""}
		if ping {
			cells = append(cells, "")
		}
		cells = append(cells, "", "", "")
		rows = append(rows, pickRow{cells, statusNone, 0, 0})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return lessLossDur(rows[i].loss, rows[i].latency, rows[j].loss, rows[j].latency)
	})

	headers := append([]string{"SUBNET", "ENDPOINT", "PING"}, lossHeader(ping)...)
	headers = append(headers, "SEEN AS", "NODE", "NODE LOCATION")
	accentCols := metricCols(ping, 2)

	fmt.Fprintln(w, "\n"+st.title.Render("Best endpoint per subnet ("+bestNote(ping)+")"))
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(st.dim).
		Headers(headers...).
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
			if col == 1 {
				return st.cell.Bold(true)
			}
			if accentCols[col] {
				return st.cell.Foreground(accentColor)
			}
			return st.cell
		})
	for _, pr := range rows {
		t.Row(pr.cells...)
	}
	fmt.Fprintln(w, t.Render())
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

// Grouped by node, not by subnet: a single /24 can hand out several different
// edge nodes, so a per-subnet pick would hide all but one of them.
func writeNodePicks(w io.Writer, working []endpointResult, ping bool) {
	byNode := make(map[string][]endpointResult)
	for _, r := range working {
		node := exitColo(r.exit)
		byNode[node] = append(byNode[node], r)
	}
	picks := make([]endpointResult, 0, len(byNode))
	for _, group := range byNode {
		picks = append(picks, bestByPing(group))
	}
	sort.Slice(picks, func(i, j int) bool { return lessByLossRTT(picks[i], picks[j]) })

	fmt.Fprintf(w, "\n# Best endpoint per node (%s)\n", bestNote(ping))
	fmt.Fprintf(w, nodePickRowFmt, "NODE", "ENDPOINT", "PING", lossCol("LOSS", ping), "SEEN AS", "NODE LOCATION")
	for _, r := range picks {
		fmt.Fprintf(w, nodePickRowFmt, exitColo(r.exit), r.endpoint, r.pingStr(), lossField(r, ping), exitRegion(r.exit), exitColoLocation(r.exit))
	}
}

type phaseResult struct {
	run     protoRun
	results []endpointResult
}

func writeToFile(path string, ph phaseResult, ping bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	writeFullReport(f, ph.results, ping)
	return nil
}
