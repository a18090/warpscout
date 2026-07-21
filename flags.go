package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

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
	noEmoji        bool
}

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
	{"AmneziaWG junk parameters", []flagSpec{
		{"", "jc", "N", "junk packet count"},
		{"", "jmin", "N", "min junk packet size"},
		{"", "jmax", "N", "max junk packet size"},
		{"", "i1", "PKT", "custom init packet (default: built-in iCloud probe)"},
	}},
	{"Output", []flagSpec{
		{"o", "output", "FILE", "full per-endpoint report file (default warpscout-report-<timestamp>.txt)"},
		{"", "plain", "", "force plain line output (no live TUI)"},
		{"", "no-emoji", "", "drop country flag emoji (for terminals that can't render them)"},
	}},
}

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
	// One shared WARP key: WireGuard keeps one session per key, so parallel
	// tunnels clobber each other server-side. Keep phase-2 concurrency low.
	intFlag(&o.tunnelParallel, 4, "jt", "tunnel-jobs")
	intFlag(&o.timeoutSec, 2, "t", "timeout")
	intFlag(&o.perSubnet, 10, "n", "sample")
	strFlag(&o.proto, "wg", "p", "proto")
	strFlag(&o.output, "", "o", "output")
	strFlag(&o.proxy, "", "x", "proxy")
	strFlag(&o.accountPath, defaultAccount, "a", "account")
	boolFlag(&o.pingCheck, "P", "ping")
	boolFlag(&o.register, "r", "register")
	boolFlag(&o.full, "f", "full")
	flag.BoolVar(&o.plain, "plain", false, "")
	flag.BoolVar(&o.noEmoji, "no-emoji", false, "")
	flag.IntVar(&awgJc, "jc", awgJc, "")
	flag.IntVar(&awgJmin, "jmin", awgJmin, "")
	flag.IntVar(&awgJmax, "jmax", awgJmax, "")
	flag.StringVar(&awgI1, "i1", awgI1, "")

	flag.Usage = usage
	flag.Parse()

	if awgJmin > awgJmax {
		fmt.Fprintf(os.Stderr, "invalid junk params: -jmin (%d) must be <= -jmax (%d)\n", awgJmin, awgJmax)
		os.Exit(2)
	}
	return o
}

func usage() {
	w := flag.CommandLine.Output()
	st := newConStyles(lipgloss.NewRenderer(w))

	fmt.Fprintln(w, st.title.Render("warpscout")+" - find the exit colo and region of Cloudflare WARP endpoints")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Two-phase scan:")
	fmt.Fprintln(w, "  - Phase 1 finds which WARP ports get through this network")
	fmt.Fprintln(w, "  - Phase 2 verifies each endpoint's real exit colo through a WARP tunnel")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Working endpoints are reported grouped per /24 subnet")
	fmt.Fprintln(w)
	fmt.Fprintln(w, st.title.Render("Usage:"))
	fmt.Fprintf(w, "  %s [options]\n", st.accent.Render("warpscout"))

	col := flagColumnWidth()
	for _, g := range flagGroups {
		fmt.Fprintf(w, "\n%s\n", st.title.Render(g.title))
		for _, s := range g.specs {
			names := flagNames(s)
			pad := col - len(names)
			if pad < 0 {
				pad = 0
			}
			fmt.Fprintf(w, "%s%s%s%s\n",
				st.accent.Render(names), strings.Repeat(" ", pad+2), s.help, defaultNote(st, s.long))
		}
	}
}

func flagNames(s flagSpec) string {
	if s.short == "" {
		return fmt.Sprintf("  -%s %s", s.long, s.meta)
	}
	return fmt.Sprintf("  -%s, -%s %s", s.short, s.long, s.meta)
}

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

func defaultNote(st conStyles, long string) string {
	f := flag.CommandLine.Lookup(long)
	if f == nil || f.DefValue == "" || f.DefValue == "false" {
		return ""
	}
	if len(f.DefValue) > 40 {
		return ""
	}
	return st.dim.Render(fmt.Sprintf(" (default %s)", f.DefValue))
}
