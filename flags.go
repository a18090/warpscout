package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// options holds every parsed command-line value.
type options struct {
	parallel       int
	tunnelParallel int
	timeoutSec     int
	durability     int
	perSubnet      int
	proto          string
	output         string
	proxy          string
	accountPath    string
	register       bool
	full           bool
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
		{"j", "jobs", "N", "phase 1 discovery workers"},
		{"jt", "tunnel-jobs", "N", "phase 2 tunnel workers"},
		{"t", "timeout", "SEC", "per-request timeout"},
		{"d", "durability", "N", "durability probe pings per working tunnel (wg only, ignored for awg); 0 disables"},
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
	intFlag(&o.parallel, 50, "j", "jobs")
	// ponytail: single shared WARP key => WireGuard keeps one session per key,
	// so parallel tunnels clobber each other server-side. Keep phase-2 low until
	// per-run key registration (wgcf) lands, then raise the default.
	intFlag(&o.tunnelParallel, 4, "jt", "tunnel-jobs")
	// Real WARP handshakes complete in ~100-250ms; the timeout only bounds how
	// long a dead endpoint (answers HTTPS in phase 1 but no tunnel) stalls a
	// worker. 2s keeps a wide margin over real latency while cutting that stall.
	intFlag(&o.timeoutSec, 2, "t", "timeout")
	// A working tunnel is pinged this many times: TSPU passes a WG handshake and
	// a few packets, then drops the peer, so a single fetch false-positives. Any
	// lost reply marks it flaky.
	intFlag(&o.durability, 10, "d", "durability")
	intFlag(&o.perSubnet, 10, "n", "sample")
	strFlag(&o.proto, "wg", "p", "proto")
	strFlag(&o.output, "", "o", "output")
	strFlag(&o.proxy, "", "x", "proxy")
	strFlag(&o.accountPath, defaultAccount, "a", "account")
	boolFlag(&o.register, "r", "register")
	boolFlag(&o.full, "f", "full")

	flag.Usage = usage
	flag.Parse()
	return o
}

// usage renders the grouped, colored --help screen to stderr.
func usage() {
	w := flag.CommandLine.Output()
	pal := palette{enabled: colorEnabled(os.Stderr)}

	fmt.Fprintln(w, pal.title("warpscout")+" - scan Cloudflare WARP endpoint pools for working endpoints")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Two-phase scan: phase 1 finds responsive Cloudflare edges, phase 2 verifies")
	fmt.Fprintln(w, "the real exit colo through a WARP tunnel. Working endpoints are reported")
	fmt.Fprintln(w, "grouped per /24 subnet.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, pal.title("Usage:"))
	fmt.Fprintf(w, "  %s [options]\n", pal.accent("warpscout"))

	col := flagColumnWidth()
	for _, g := range flagGroups {
		fmt.Fprintf(w, "\n%s\n", pal.title(g.title))
		for _, s := range g.specs {
			names := fmt.Sprintf("  -%s, -%s %s", s.short, s.long, s.meta)
			pad := col - len(names)
			if pad < 0 {
				pad = 0
			}
			fmt.Fprintf(w, "%s%s%s%s\n",
				pal.accent(names), strings.Repeat(" ", pad+2), s.help, defaultNote(pal, s.long))
		}
	}
}

// flagColumnWidth is the width of the widest "-s, --long meta" cell, so the
// help text lines up in a column.
func flagColumnWidth() int {
	max := 0
	for _, g := range flagGroups {
		for _, s := range g.specs {
			n := len(fmt.Sprintf("  -%s, -%s %s", s.short, s.long, s.meta))
			if n > max {
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
