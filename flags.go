package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// options holds every parsed command-line value.
type options struct {
	tunnelParallel int
	timeoutSec     int
	perSubnet      int
	proto          string
	output         string
	proxy          string
	accountPath    string
	pingCheck      bool
	register       bool
	full           bool
	plain          bool
}

// flagSpec describes one flag for the help renderer. The default value is not
// stored here: usage() reads it from the registered flag so it can never drift
// from what parseFlags actually registered.
type flagSpec struct {
	short string
	long  string
	meta  string
	help  string
}

type flagGroup struct {
	title string
	specs []flagSpec
}

var flagGroups = []flagGroup{
	{"Scan tuning", []flagSpec{
		{"jt", "tunnel-jobs", "N", "phase 2 tunnel workers"},
		{"t", "timeout", "SEC", "per-request timeout"},
		{"P", "ping", "", "ping wg tunnels through to catch flaky (TSPU-dropped) endpoints; off by default for speed"},
		{"n", "sample", "N", "addresses to sample per /24 subnet"},
		{"f", "full", "", "scan all 256 addresses per /24 (overrides -sample)"},
	}},
	{"Protocol & registration", []flagSpec{
		{"p", "proto", "wg|awg|both", "tunnel protocol: wg (WireGuard), awg (AmneziaWG), or both"},
		{"x", "proxy", "URL", "http(s)/socks5 proxy for registration"},
		{"r", "register", "", "register a fresh WARP account, save it and exit"},
		{"a", "account", "FILE", "cached WARP account file"},
	}},
	{"Output", []flagSpec{
		{"o", "output", "FILE", "full per-endpoint report file (default warpscout-report-<timestamp>.txt)"},
		{"", "plain", "", "force plain line output (no live TUI)"},
	}},
}

// intFlag/strFlag/boolFlag register one value under both a short and a long
// name. Help text is empty because usage() renders help from flagGroups.
func intFlag(p *int, def int, short, long string) {
	flag.IntVar(p, short, def, "")
	flag.IntVar(p, long, def, "")
}

func strFlag(p *string, def, short, long string) {
	flag.StringVar(p, short, def, "")
	flag.StringVar(p, long, def, "")
}

func boolFlag(p *bool, short, long string) {
	flag.BoolVar(p, short, false, "")
	flag.BoolVar(p, long, false, "")
}

func parseFlags() options {
	var o options
	// ponytail: single shared WARP key => WireGuard keeps one session per key,
	// so parallel tunnels clobber each other server-side. Keep phase-2 low until
	// per-run key registration (wgcf) lands, then raise the default.
	intFlag(&o.tunnelParallel, 4, "jt", "tunnel-jobs")
	// Real WARP handshakes complete in ~100-250ms; the timeout only bounds how
	// long a dead endpoint stalls a worker waiting for a handshake that never
	// comes. 2s keeps a wide margin over real latency while cutting that stall.
	intFlag(&o.timeoutSec, 2, "t", "timeout")
	intFlag(&o.perSubnet, 10, "n", "sample")
	strFlag(&o.proto, "wg", "p", "proto")
	strFlag(&o.output, "", "o", "output")
	strFlag(&o.proxy, "", "x", "proxy")
	strFlag(&o.accountPath, defaultAccount, "a", "account")
	// Off by default: pinging each working tunnel catches TSPU (passes a WG
	// handshake and a few packets, then drops the peer) but finds nothing on
	// unrestricted networks and only slows phase 2. Opt in on censored networks.
	boolFlag(&o.pingCheck, "P", "ping")
	boolFlag(&o.register, "r", "register")
	boolFlag(&o.full, "f", "full")
	// Long-only: no natural short letter, and the plain path is a rare escape hatch.
	flag.BoolVar(&o.plain, "plain", false, "")

	flag.Usage = usage
	flag.Parse()
	return o
}

// usage renders the grouped, colored --help screen to stderr.
func usage() {
	w := flag.CommandLine.Output()
	pal := palette{enabled: colorEnabled(os.Stderr)}

	fmt.Fprintln(w, pal.title("warpscout")+" - find the exit colo and region of Cloudflare WARP endpoints")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Two-phase scan:")
	fmt.Fprintln(w, "  - Phase 1 finds which WARP ports get through this network")
	fmt.Fprintln(w, "  - Phase 2 verifies each endpoint's real exit colo through a WARP tunnel")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Working endpoints are reported grouped per /24 subnet")
	fmt.Fprintln(w)
	fmt.Fprintln(w, pal.title("Usage:"))
	fmt.Fprintf(w, "  %s [options]\n", pal.accent("warpscout"))

	col := flagColumnWidth()
	for _, g := range flagGroups {
		fmt.Fprintf(w, "\n%s\n", pal.title(g.title))
		for _, s := range g.specs {
			names := flagNames(s)
			pad := col - len(names)
			if pad < 0 {
				pad = 0
			}
			fmt.Fprintf(w, "%s%s%s%s\n",
				pal.accent(names), strings.Repeat(" ", pad+2), s.help, defaultNote(pal, s.long))
		}
	}
}

// flagNames renders the "  -s, -long meta" cell, dropping the short pair when a
// flag is long-only (empty short).
func flagNames(s flagSpec) string {
	if s.short == "" {
		return fmt.Sprintf("  -%s %s", s.long, s.meta)
	}
	return fmt.Sprintf("  -%s, -%s %s", s.short, s.long, s.meta)
}

// flagColumnWidth is the width of the widest name cell, so the help text lines
// up in a column.
func flagColumnWidth() int {
	max := 0
	for _, g := range flagGroups {
		for _, s := range g.specs {
			if n := len(flagNames(s)); n > max {
				max = n
			}
		}
	}
	return max
}

// defaultNote reads the registered default for a flag and renders it dim, or ""
// for empty/false defaults where a note would be noise.
func defaultNote(pal palette, long string) string {
	f := flag.CommandLine.Lookup(long)
	if f == nil || f.DefValue == "" || f.DefValue == "false" {
		return ""
	}
	return pal.dim(fmt.Sprintf(" (default %s)", f.DefValue))
}
