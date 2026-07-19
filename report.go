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

// writeReport prints every working endpoint with its phase-1 (direct edge) and
// phase-2 (via tunnel) region/colo, whether they matched, and one ready-to-use
// endpoint per subnet.
func writeReport(w io.Writer, results []endpointResult) {
	working := make([]endpointResult, 0, len(results))
	for _, r := range results {
		if r.ok {
			working = append(working, r)
		}
	}

	fmt.Fprintln(w, "════════════════════════════════════════════════════════")
	fmt.Fprintf(w, "  WARP endpoints: %d working / %d probed\n", len(working), len(results))
	fmt.Fprintln(w, "  PHASE1 = direct edge (--resolve), PHASE2 = real exit via tunnel")
	fmt.Fprintln(w, "════════════════════════════════════════════════════════")

	if len(working) == 0 {
		fmt.Fprintln(w, "\nNo working endpoints found.")
		return
	}

	sort.Slice(working, func(i, j int) bool {
		if working[i].exit.colo != working[j].exit.colo {
			return working[i].exit.colo < working[j].exit.colo
		}
		return working[i].endpoint < working[j].endpoint
	})

	fmt.Fprintf(w, "\n  %-22s %-10s %-10s %s\n", "ENDPOINT", "PHASE1", "PHASE2", "MATCH")
	for _, r := range working {
		match := "✓"
		if !r.phasesMatch() {
			match = "✗"
		}
		fmt.Fprintf(w, "  %-22s %-10s %-10s %s\n", r.endpoint, regionColo(r.edge), regionColo(r.exit), match)
	}

	writeSubnetPicks(w, working)
}

// writeSubnetPicks prints one random working endpoint per subnet, with its real
// (phase-2) region/colo, so one can be grabbed quickly per pool.
func writeSubnetPicks(w io.Writer, working []endpointResult) {
	fmt.Fprintln(w, "\n  ── One random working endpoint per subnet ──")
	for _, base := range pools {
		var picks []endpointResult
		for _, r := range working {
			if strings.HasPrefix(r.ip.String(), base) {
				picks = append(picks, r)
			}
		}
		subnet := base + "0/24"
		if len(picks) == 0 {
			fmt.Fprintf(w, "  %-18s %s\n", subnet, "(none)")
			continue
		}
		r := picks[rand.Intn(len(picks))]
		fmt.Fprintf(w, "  %-18s %-22s %s\n", subnet, r.endpoint, regionColo(r.exit))
	}
}
