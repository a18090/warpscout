package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"sort"
	"strings"
)

// endpointResult is the outcome of the full check for one IP.
type endpointResult struct {
	ip       netip.Addr
	edge     traceResult // phase 1: direct edge that answered
	endpoint string      // ip:port that completed the handshake
	exit     traceResult // phase 2: real exit seen through the tunnel
	ok       bool        // handshake + trace through the tunnel succeeded
}

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

func (r endpointResult) phasesMatch() bool {
	return r.edge.colo == r.exit.colo && r.edge.loc == r.exit.loc
}

// workingSorted returns the working endpoints sorted by exit colo then endpoint.
func workingSorted(results []endpointResult) []endpointResult {
	working := make([]endpointResult, 0, len(results))
	for _, r := range results {
		if r.ok {
			working = append(working, r)
		}
	}
	sort.Slice(working, func(i, j int) bool {
		if working[i].exit.colo != working[j].exit.colo {
			return working[i].exit.colo < working[j].exit.colo
		}
		return working[i].endpoint < working[j].endpoint
	})
	return working
}

func writeHeader(w io.Writer, working, probed int) {
	fmt.Fprintln(w, "════════════════════════════════════════════════════════")
	fmt.Fprintf(w, "  WARP endpoints: %d working / %d probed\n", working, probed)
	fmt.Fprintln(w, "  PHASE1 = direct edge (--resolve), PHASE2 = real exit via tunnel")
	fmt.Fprintln(w, "════════════════════════════════════════════════════════")
}

// writeFullReport prints every working endpoint with its phase-1 (direct edge)
// and phase-2 (via tunnel) region/colo, whether they matched, and one
// ready-to-use endpoint per subnet. Goes to the report file.
func writeFullReport(w io.Writer, results []endpointResult) {
	working := workingSorted(results)
	writeHeader(w, len(working), len(results))
	if len(working) == 0 {
		fmt.Fprintln(w, "\nNo working endpoints found.")
		return
	}

	fmt.Fprintf(w, "\n  %-22s %-10s %-10s %s\n", "ENDPOINT", "PHASE1", "PHASE2", "MATCH")
	for _, base := range pools {
		subnet := subnetEndpoints(working, base)
		if len(subnet) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  ── %s0/24 ──\n", base)
		for _, colo := range exitColos(subnet) {
			fmt.Fprintf(w, "    %s\n", colo)
			for _, r := range subnet {
				if regionColo(r.exit) != colo {
					continue
				}
				match := "✓"
				if !r.phasesMatch() {
					match = "✗"
				}
				fmt.Fprintf(w, "    %-22s %-10s %-10s %s\n", r.endpoint, regionColo(r.edge), regionColo(r.exit), match)
			}
		}
	}

	writeSubnetPicks(w, working)
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

// writeConsole prints a compact summary: unique colos and regions found, plus
// one working endpoint per subnet. The full per-endpoint table goes to the file.
func writeConsole(w io.Writer, results []endpointResult) {
	working := workingSorted(results)
	writeHeader(w, len(working), len(results))
	if len(working) == 0 {
		fmt.Fprintln(w, "\nNo working endpoints found.")
		return
	}

	fmt.Fprintf(w, "\n  Colo:    %s\n", uniqueSorted(working, func(r endpointResult) string { return r.exit.colo }))
	fmt.Fprintf(w, "  Regions: %s\n", uniqueSorted(working, func(r endpointResult) string { return r.exit.loc }))

	writeSubnetPicks(w, working)
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
			fmt.Fprintf(w, "  %-18s %s\n", subnet, "(none)")
			continue
		}
		r := picks[rand.Intn(len(picks))]
		fmt.Fprintf(w, "  %-18s %-22s %s\n", subnet, r.endpoint, regionColo(r.exit))
	}
}
