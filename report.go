package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// endpointResult is the outcome of the full check for one IP.
type endpointResult struct {
	ip       netip.Addr
	endpoint string      // ip:port that completed the handshake
	exit     traceResult // phase 2: real exit seen through the tunnel
	ok       bool        // handshake + trace through the tunnel succeeded
	durable  bool        // survived the re-probe (meaningful only when ok)
}

// working is a durable endpoint; flaky passed once but died on the re-probe
// (TSPU dropped the peer after a few packets).
func (r endpointResult) working() bool { return r.ok && r.durable }
func (r endpointResult) flaky() bool   { return r.ok && !r.durable }

// regionColo renders "loc/colo" (e.g. RU/DME), with "?" for missing fields.
func regionColo(t traceResult) string {
	loc, colo := t.loc, t.colo
	if loc == "" {
		loc = "?"
	}
	if colo == "" {
		colo = "?"
	}
	return loc + "/" + colo
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].exit.colo != out[j].exit.colo {
			return out[i].exit.colo < out[j].exit.colo
		}
		return out[i].endpoint < out[j].endpoint
	})
	return out
}

func writeHeader(w io.Writer, working, probed int) {
	fmt.Fprintln(w, "════════════════════════════════════════════════════════")
	fmt.Fprintf(w, "  WARP endpoints: %d working / %d probed\n", working, probed)
	fmt.Fprintln(w, "  EXIT = real exit region/colo seen through the tunnel")
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
		fmt.Fprintf(w, "\n  ── %s0/24 ──\n", base)
		for _, colo := range exitColos(subnet) {
			fmt.Fprintf(w, "    %s\n", colo)
			for _, r := range subnet {
				if regionColo(r.exit) != colo {
					continue
				}
				fmt.Fprintf(w, "      %s\n", r.endpoint)
			}
		}
		for _, r := range subnetFlaky {
			fmt.Fprintf(w, "    %-22s %-10s %s\n", r.endpoint, regionColo(r.exit), "flaky")
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

// exitColos returns the distinct phase-2 region/colo values in the group, sorted.
func exitColos(picks []endpointResult) []string {
	seen := make(map[string]struct{})
	var colos []string
	for _, r := range picks {
		colo := regionColo(r.exit)
		if _, ok := seen[colo]; ok {
			continue
		}
		seen[colo] = struct{}{}
		colos = append(colos, colo)
	}
	sort.Strings(colos)
	return colos
}

// writeConsole prints a colored, framed summary to the terminal: a banner with
// the working/probed counts, the unique colos and regions found, and a boxed
// table of one working endpoint per subnet. The full per-endpoint report goes
// to the file (writeFullReport, plain text).
func writeConsole(w io.Writer, ph phaseResult, pal palette) {
	results := ph.results
	working := workingSorted(results)
	flaky := flakySorted(results)
	fmt.Fprintln(w) // blank line between the phase-2 progress and the table
	if len(working) == 0 {
		fmt.Fprintln(w, pal.fail("No working endpoints found."))
		writeFlakyNote(w, pal, len(flaky))
		return
	}

	writeBanner(w, pal, len(working), len(results))
	fmt.Fprintf(w, "  Proto:    %s\n", pal.accent(strings.ToUpper(ph.run.name)))
	fmt.Fprintf(w, "  Colo:     %s\n", pal.accent(uniqueSorted(working, func(r endpointResult) string { return r.exit.colo })))
	fmt.Fprintf(w, "  Regions:  %s\n", pal.accent(uniqueSorted(working, func(r endpointResult) string { return r.exit.loc })))
	writeFlakyNote(w, pal, len(flaky))
	writePicksTable(w, pal, working, flaky)
}

// writeFlakyNote prints the count of endpoints that handshook but were dropped
// on the re-probe, if any.
func writeFlakyNote(w io.Writer, pal palette, n int) {
	if n == 0 {
		return
	}
	fmt.Fprintf(w, "  Flaky:    %s\n", pal.warn(fmt.Sprintf("%d (handshake ok, dropped on re-probe)", n)))
}

const bannerWidth = 52

// writeBanner prints a rounded box with the working/probed headline.
func writeBanner(w io.Writer, pal palette, working, probed int) {
	plain := fmt.Sprintf("  WARPSCOUT   %d working / %d probed", working, probed)
	body := "  " + pal.title("WARPSCOUT") + "   " + pal.ok(strconv.Itoa(working)) + " working" +
		pal.dim(" / ") + strconv.Itoa(probed) + " probed"
	writeBox(w, pal, plain, body)
}

// writeBox draws a rounded box around one headline. plain is the uncolored text
// (used only to size the padding); body is the colored text to print.
func writeBox(w io.Writer, pal palette, plain, body string) {
	pad := bannerWidth - len([]rune(plain))
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintln(w, pal.dim("╭"+strings.Repeat("─", bannerWidth)+"╮"))
	fmt.Fprintf(w, "%s%s%s%s\n", pal.dim("│"), body, strings.Repeat(" ", pad), pal.dim("│"))
	fmt.Fprintln(w, pal.dim("╰"+strings.Repeat("─", bannerWidth)+"╯"))
}

// Column widths for the subnet-picks table (excluding the 1-space cell padding).
const (
	colSubnet   = 16
	colEndpoint = 22
	colExit     = 8
)

// writePicksTable prints a boxed table of one random endpoint per subnet: a
// durable one when available, otherwise a flaky one flagged in yellow.
func writePicksTable(w io.Writer, pal palette, working, flaky []endpointResult) {
	pad := func(s string, n int) string { return fmt.Sprintf("%-*s", n, s) }
	border := func(l, m, r string) string {
		return l + strings.Repeat("─", colSubnet+2) + m + strings.Repeat("─", colEndpoint+2) + m +
			strings.Repeat("─", colExit+2) + r
	}
	row := func(a, b, c string) string {
		bar := pal.dim("│")
		return fmt.Sprintf("  %s %s %s %s %s %s %s", bar, a, bar, b, bar, c, bar)
	}

	fmt.Fprintln(w, "\n  "+pal.title("Working endpoint per subnet"))
	fmt.Fprintln(w, "  "+pal.dim(border("┌", "┬", "┐")))
	fmt.Fprintln(w, row(pal.title(pad("SUBNET", colSubnet)), pal.title(pad("ENDPOINT", colEndpoint)), pal.title(pad("EXIT", colExit))))
	fmt.Fprintln(w, "  "+pal.dim(border("├", "┼", "┤")))
	for _, base := range pools {
		subnet := pad(base+"0/24", colSubnet)
		if picks := subnetEndpoints(working, base); len(picks) > 0 {
			r := picks[rand.Intn(len(picks))]
			fmt.Fprintln(w, row(subnet, pal.addr(pad(r.endpoint, colEndpoint)), pal.accent(pad(regionColo(r.exit), colExit))))
			continue
		}
		if picks := subnetEndpoints(flaky, base); len(picks) > 0 {
			r := picks[rand.Intn(len(picks))]
			fmt.Fprintln(w, row(subnet, pal.warn(pad(r.endpoint, colEndpoint)), pal.warn(pad("flaky", colExit))))
			continue
		}
		fmt.Fprintln(w, row(subnet, pal.fail(pad("no working endpoints", colEndpoint)), pad("", colExit)))
	}
	fmt.Fprintln(w, "  "+pal.dim(border("└", "┴", "┘")))
}

const colProto = 6

// writeConsoleBoth renders the -proto both comparison: per subnet, whether wg
// and awg each yield a durable (OK), flaky, or no (-) endpoint, plus one
// concrete endpoint to use (a durable wg one preferred). Directly answers which
// subnets work on plain WireGuard and which need AmneziaWG obfuscation.
func writeConsoleBoth(w io.Writer, phases []phaseResult, pal palette) {
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
	plain := fmt.Sprintf("  WARPSCOUT   wg %d / awg %d working of %d probed", len(wgWork), len(awgWork), probed)
	body := "  " + pal.title("WARPSCOUT") + "   wg " + pal.ok(strconv.Itoa(len(wgWork))) +
		pal.dim(" / ") + "awg " + pal.ok(strconv.Itoa(len(awgWork))) + " working of " + strconv.Itoa(probed) + " probed"
	writeBox(w, pal, plain, body)
	fmt.Fprintln(w)

	pad := func(s string, n int) string { return fmt.Sprintf("%-*s", n, s) }
	widths := []int{colSubnet, colProto, colProto, colEndpoint, colExit}
	border := func(l, m, r string) string {
		parts := make([]string, len(widths))
		for i, n := range widths {
			parts[i] = strings.Repeat("─", n+2)
		}
		return l + strings.Join(parts, m) + r
	}
	row := func(cells ...string) string {
		bar := pal.dim("│")
		out := "  " + bar
		for _, c := range cells {
			out += " " + c + " " + bar
		}
		return out
	}
	statusCell := func(work, flaky []endpointResult, base string) string {
		if len(subnetEndpoints(work, base)) > 0 {
			return pal.ok(pad("OK", colProto))
		}
		if len(subnetEndpoints(flaky, base)) > 0 {
			return pal.warn(pad("flaky", colProto))
		}
		return pal.dim(pad("-", colProto))
	}

	fmt.Fprintln(w, "  "+pal.title("WireGuard vs AmneziaWG per subnet"))
	fmt.Fprintln(w, "  "+pal.dim(border("┌", "┬", "┐")))
	fmt.Fprintln(w, row(pal.title(pad("SUBNET", colSubnet)), pal.title(pad("WG", colProto)), pal.title(pad("AWG", colProto)),
		pal.title(pad("ENDPOINT", colEndpoint)), pal.title(pad("EXIT", colExit))))
	fmt.Fprintln(w, "  "+pal.dim(border("├", "┼", "┤")))
	for _, base := range pools {
		subnet := pad(base+"0/24", colSubnet)
		wgCell := statusCell(wgWork, wgFlaky, base)
		awgCell := statusCell(awgWork, awgFlaky, base)
		endpoint, exit, flaky := bestPick(base, wgWork, awgWork, wgFlaky, awgFlaky)
		if endpoint == "" {
			fmt.Fprintln(w, row(subnet, wgCell, awgCell, pal.dim(pad("-", colEndpoint)), pad("", colExit)))
			continue
		}
		endpointCell := pal.addr(pad(endpoint, colEndpoint))
		exitCell := pal.accent(pad(exit, colExit))
		if flaky {
			endpointCell = pal.warn(pad(endpoint, colEndpoint))
			exitCell = pal.warn(pad(exit, colExit))
		}
		fmt.Fprintln(w, row(subnet, wgCell, awgCell, endpointCell, exitCell))
	}
	fmt.Fprintln(w, "  "+pal.dim(border("└", "┴", "┘")))
}

// bestPick returns one endpoint to use for a subnet, preferring a durable wg one,
// then durable awg, then flaky wg, then flaky awg. flaky reports whether the
// chosen endpoint is only flaky. Empty endpoint means nothing worked.
func bestPick(base string, sets ...[]endpointResult) (endpoint, exit string, flaky bool) {
	for i, set := range sets {
		if picks := subnetEndpoints(set, base); len(picks) > 0 {
			r := picks[rand.Intn(len(picks))]
			return r.endpoint, regionColo(r.exit), i >= 2 // sets[2:] are the flaky lists
		}
	}
	return "", "", false
}

// uniqueSorted collects the non-empty key(r) values, sorted and space-joined.
func uniqueSorted(working []endpointResult, key func(endpointResult) string) string {
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
	return strings.Join(vals, "  ")
}

// writeSubnetPicks prints one random working endpoint per subnet, with its real
// (phase-2) region/colo, so one can be grabbed quickly per pool.
func writeSubnetPicks(w io.Writer, working []endpointResult) {
	fmt.Fprintln(w, "\n  ── One random working endpoint per subnet ──")
	for _, base := range pools {
		picks := subnetEndpoints(working, base)
		subnet := base + "0/24"
		if len(picks) == 0 {
			fmt.Fprintf(w, "  %-18s %s\n", subnet, "no working endpoints")
			continue
		}
		r := picks[rand.Intn(len(picks))]
		fmt.Fprintf(w, "  %-18s %-22s %s\n", subnet, r.endpoint, regionColo(r.exit))
	}
}
