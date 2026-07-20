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

// Palette colors shared by the console tables and the live TUI, so both read as
// one design.
var (
	dimColor    = lipgloss.Color("240")
	okColor     = lipgloss.Color("42")
	failColor   = lipgloss.Color("196")
	warnColor   = lipgloss.Color("214")
	accentColor = lipgloss.Color("39")
)

// conStyles bundles the styles for one output, built from a renderer bound to a
// specific writer so color degrades automatically on a non-TTY (pipe/NO_COLOR).
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

// Row status used by the table StyleFunc to color a pick.
const (
	statusOK = iota
	statusFlaky
	statusNone
)

// endpointResult is the outcome of the full check for one IP.
type endpointResult struct {
	ip       netip.Addr
	endpoint string        // ip:port that completed the handshake
	exit     traceResult   // phase 2: real exit seen through the tunnel
	latency  time.Duration // direct host ICMP RTT to ip; 0 means unknown
	ok       bool          // handshake + trace through the tunnel succeeded
	durable  bool          // survived the re-probe (meaningful only when ok)
}

// pingStr renders the latency as "47ms" ("0.4ms" below 1ms, common from a
// datacenter next to the edge), or "?" when it is unknown (0).
func (r endpointResult) pingStr() string { return latencyStr(r.latency) }

// latencyStr renders a latency as "47ms" ("0.4ms" below 1ms), or "?" when it is
// unknown (0). Shared by the report tables and the live TUI feed.
func latencyStr(d time.Duration) string {
	if d <= 0 {
		return "?"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// working is a durable endpoint; flaky passed once but died on the re-probe
// (TSPU dropped the peer after a few packets).
func (r endpointResult) working() bool { return r.ok && r.durable }
func (r endpointResult) flaky() bool   { return r.ok && !r.durable }

// withFlag prefixes code with its flag emoji ("🇷🇺 RU"), or returns code alone
// when the flag is unknown.
func withFlag(flag, code string) string {
	if flag == "" {
		return code
	}
	return flag + " " + code
}

// exitRegion renders the exit region as external services see it ("🇷🇺 RU"), or
// "?" when unknown.
func exitRegion(t traceResult) string {
	if t.loc == "" {
		return "?"
	}
	return withFlag(flagEmoji(t.loc), t.loc)
}

// exitColo renders the WARP edge node the tunnel landed on ("🇷🇺 DME"), or "?"
// when unknown.
func exitColo(t traceResult) string {
	if t.colo == "" {
		return "?"
	}
	return withFlag(coloFlag(t.colo), t.colo)
}

// exitColosOf returns the distinct non-empty exit colos across every phase.
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

// workingSorted returns the durable endpoints sorted by exit colo then endpoint.
func workingSorted(results []endpointResult) []endpointResult {
	return filterSorted(results, endpointResult.working)
}

// flakySorted returns the endpoints that passed once but died on the re-probe.
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

// lessByPing orders by latency ascending with unknown (0) pings last, breaking
// ties on the endpoint string for a stable order.
func lessByPing(a, b endpointResult) bool {
	ap, bp := a.latency, b.latency
	if (ap <= 0) != (bp <= 0) {
		return ap > 0 // known ping sorts before unknown
	}
	if ap != bp {
		return ap < bp
	}
	return a.endpoint < b.endpoint
}

// bestByPing returns the lowest-ping endpoint (unknown pings last). picks must
// be non-empty.
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

// writeFullReport prints every working endpoint grouped by its exit region/colo,
// the flaky ones, and one ready-to-use endpoint per subnet. Goes to the report
// file.
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

// subnetEndpoints returns the working endpoints whose IP falls in the base /24.
func subnetEndpoints(working []endpointResult, base string) []endpointResult {
	var picks []endpointResult
	for _, r := range working {
		if strings.HasPrefix(r.ip.String(), base) {
			picks = append(picks, r)
		}
	}
	return picks
}

// writeConsole prints a colored, framed summary to the terminal: a banner with
// the working/probed counts, the unique colos and regions found, and a boxed
// table of one working endpoint per subnet. The full per-endpoint report goes
// to the file (writeFullReport, plain text).
func writeConsole(w io.Writer, ph phaseResult, r *lipgloss.Renderer) {
	st := newConStyles(r)
	results := ph.results
	working := workingSorted(results)
	flaky := flakySorted(results)
	fmt.Fprintln(w) // blank line between the phase-2 progress and the table
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

// writeFlakyNote prints the count of endpoints that handshook but were dropped
// on the re-probe, if any.
func writeFlakyNote(w io.Writer, st conStyles, n int) {
	if n == 0 {
		return
	}
	fmt.Fprintf(w, "Flaky:    %s\n", st.warn.Render(fmt.Sprintf("%d (handshake ok, dropped on re-probe)", n)))
}

// banner renders the WARPSCOUT headline in a rounded box; the counts go on the
// lines below it.
func banner(st conStyles) string {
	return st.box.Render("WARPSCOUT")
}

// pickRow is one table row plus the status used to color it.
type pickRow struct {
	cells  []string
	status int
}

// writePicksTable prints a boxed table of the lowest-ping endpoint per subnet: a
// durable one when available, otherwise a flaky one flagged in yellow.
func writePicksTable(w io.Writer, st conStyles, working, flaky []endpointResult) {
	var rows []pickRow
	for _, base := range pools {
		subnet := base + "0/24"
		if picks := subnetEndpoints(working, base); len(picks) > 0 {
			r := bestByPing(picks)
			rows = append(rows, pickRow{[]string{subnet, r.endpoint, r.pingStr(), exitRegion(r.exit), exitColo(r.exit)}, statusOK})
			continue
		}
		if picks := subnetEndpoints(flaky, base); len(picks) > 0 {
			r := bestByPing(picks)
			rows = append(rows, pickRow{[]string{subnet, r.endpoint, r.pingStr(), "flaky", ""}, statusFlaky})
			continue
		}
		rows = append(rows, pickRow{[]string{subnet, "no working endpoints", "", "", ""}, statusNone})
	}

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

// bothRow is one -proto both row: cells plus the per-cell statuses that color it.
type bothRow struct {
	cells                 []string
	wgStat, awgStat, pick int
}

// writeConsoleBoth renders the -proto both comparison: per subnet, whether wg
// and awg each yield a durable (OK), flaky, or no (-) endpoint, plus one
// concrete endpoint to use (a durable wg one preferred). Directly answers which
// subnets work on plain WireGuard and which need AmneziaWG obfuscation.
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
		endpoint, ping, region, colo, isFlaky := bestPick(base, wgWork, awgWork, wgFlaky, awgFlaky)
		pick := statusOK
		if isFlaky {
			pick = statusFlaky
		}
		if endpoint == "" {
			endpoint, ping, region, colo, pick = "-", "", "", "", statusNone
		}
		rows = append(rows, bothRow{[]string{base + "0/24", wgTxt, awgTxt, endpoint, ping, region, colo}, wgStat, awgStat, pick})
	}

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

// bestPick returns one endpoint to use for a subnet, preferring a durable wg one,
// then durable awg, then flaky wg, then flaky awg; within the chosen set it picks
// the lowest ping, returning its exit region and colo separately. flaky reports
// whether the chosen endpoint is only flaky. Empty endpoint means nothing worked.
func bestPick(base string, sets ...[]endpointResult) (endpoint, ping, region, colo string, flaky bool) {
	for i, set := range sets {
		if picks := subnetEndpoints(set, base); len(picks) > 0 {
			r := bestByPing(picks)
			return r.endpoint, r.pingStr(), exitRegion(r.exit), exitColo(r.exit), i >= 2 // sets[2:] are the flaky lists
		}
	}
	return "", "", "", "", false
}

// uniqueSorted collects the non-empty key(r) values, sorted, each rendered with
// its flag (flagFor(v) may return "" to omit it), and space-joined.
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

// writeSubnetPicks prints the lowest-ping working endpoint per subnet, with its
// ping and real (phase-2) region/colo, so the best one can be grabbed per pool.
func writeSubnetPicks(w io.Writer, working []endpointResult) {
	fmt.Fprintln(w, "\n  ── Best working endpoint per subnet (lowest ping) ──")
	for _, base := range pools {
		picks := subnetEndpoints(working, base)
		subnet := base + "0/24"
		if len(picks) == 0 {
			fmt.Fprintf(w, "  %-18s %s\n", subnet, "no working endpoints")
			continue
		}
		r := bestByPing(picks)
		fmt.Fprintf(w, "  %-18s %-22s %-8s %-10s %s\n", subnet, r.endpoint, r.pingStr(), exitRegion(r.exit), exitColo(r.exit))
	}
}

// phaseResult pairs a protocol run with its per-endpoint results.
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
