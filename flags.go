package main

import (
	"flag"
	"fmt"
	"net/netip"
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
	iface          string
	accountPath    string
	genI1          string
	i1Host         string
	target         string
	node           string
	targets        []netip.Prefix
	colos          []string
	i1Explicit     bool
	pingCheck      bool
	genJunk        bool
	findJunk       bool
	ipv6           bool
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
		{"P", "ping", "", "measure in-tunnel RTT and packet loss and flag flaky (TSPU-torn-down) endpoints; off by default for speed"},
		{"n", "sample", "N", "addresses to sample per subnet"},
		{"f", "full", "", "scan all 256 addresses per subnet (overrides -sample)"},
		{"6", "ipv6", "", "scan IPv6 endpoint pools instead of IPv4"},
		{"", "target", "ADDR", "scan these addresses instead of the built-in pools: comma-separated IPs or CIDRs"},
		{"I", "interface", "NAME", "scan and register through this interface (bind to device; Linux, may need CAP_NET_RAW)"},
	}},
	{"Protocol & registration", []flagSpec{
		{"p", "proto", "wg|awg|both", "tunnel protocol: wg (WireGuard), awg (AmneziaWG), or both"},
		{"x", "proxy", "URL", "http(s)/socks5 proxy for registration"},
		{"r", "register", "", "register a fresh WARP account, save it and exit"},
		{"a", "account", "FILE", "cached WARP account file"},
	}},
	{"AmneziaWG obfuscation parameters", []flagSpec{
		{"", "gen-junk", "", "randomize junk params per run (overridden by -jc/-jmin/-jmax)"},
		{"", "find-junk", "", "keep rescanning with fresh random junk params (and a fresh I1 when -gen-i1 is set) until a set unblocks every sampled endpoint, then print the command to reuse it (implies -ping, needs -proto awg)"},
		{"", "gen-i1", "PROTO", "generate the init packet per run: quic, dns, sip, stun or random"},
		{"", "i1-sni", "HOST", "host to mimic in the generated I1 (default: a random well-known host)"},
		{"", "jc", "N", "junk packet count"},
		{"", "jmin", "N", "min junk packet size"},
		{"", "jmax", "N", "max junk packet size"},
		{"", "i1", "PKT", "custom init packet, or \"none\" to send none (default: built-in iCloud probe)"},
	}},
	{"Output", []flagSpec{
		{"o", "output", "FILE", "full per-endpoint report file (default warpscout-report-<timestamp>.txt)"},
		{"", "node", "COLO", "keep only endpoints landing on these colos: comma-separated IATA codes"},
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
	intFlag(&o.tunnelParallel, 10, "jt", "tunnel-jobs")
	intFlag(&o.timeoutSec, 2, "t", "timeout")
	intFlag(&o.perSubnet, 10, "n", "sample")
	strFlag(&o.proto, protoWG, "p", "proto")
	strFlag(&o.output, "", "o", "output")
	strFlag(&o.proxy, "", "x", "proxy")
	strFlag(&o.iface, "", "I", "interface")
	strFlag(&o.accountPath, defaultAccount, "a", "account")
	boolFlag(&o.pingCheck, "P", "ping")
	boolFlag(&o.ipv6, "6", "ipv6")
	boolFlag(&o.register, "r", "register")
	boolFlag(&o.full, "f", "full")
	flag.StringVar(&o.target, "target", "", "")
	flag.StringVar(&o.node, "node", "", "")
	flag.BoolVar(&o.plain, "plain", false, "")
	flag.BoolVar(&o.noEmoji, "no-emoji", false, "")
	flag.BoolVar(&o.genJunk, "gen-junk", false, "")
	flag.BoolVar(&o.findJunk, "find-junk", false, "")
	flag.IntVar(&awgJc, "jc", awgJc, "")
	flag.IntVar(&awgJmin, "jmin", awgJmin, "")
	flag.IntVar(&awgJmax, "jmax", awgJmax, "")
	flag.StringVar(&awgI1, "i1", awgI1, "")
	flag.StringVar(&o.genI1, "gen-i1", "", "")
	flag.StringVar(&o.i1Host, "i1-sni", "", "")

	flag.Usage = usage
	flag.Parse()

	if awgI1 == i1Keyword {
		awgI1 = ""
	}
	if o.genJunk {
		if o.proto == protoWG {
			fmt.Fprintln(os.Stderr, "-gen-junk needs AmneziaWG: use -proto awg or -proto both")
			os.Exit(2)
		}
		applyGenJunk()
	}
	applyGenI1(&o)
	if o.findJunk {
		applyFindJunk(&o)
	}
	validateJunkParams()
	applyTarget(&o)
	applyNode(&o)
	return o
}

func applyTarget(o *options) {
	if o.target == "" {
		return
	}
	targets, err := parseTargets(o.target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	o.targets = targets
	o.ipv6 = !targets[0].Addr().Is4()
}

func applyNode(o *options) {
	if o.node == "" {
		return
	}
	if o.findJunk {
		fmt.Fprintln(os.Stderr, "-find-junk never resolves the exit colo: drop -node")
		os.Exit(2)
	}
	for _, code := range strings.Split(o.node, ",") {
		if code = strings.ToUpper(strings.TrimSpace(code)); code != "" {
			o.colos = append(o.colos, code)
		}
	}
	if len(o.colos) == 0 {
		fmt.Fprintln(os.Stderr, "-node is empty")
		os.Exit(2)
	}
}

func applyFindJunk(o *options) {
	if o.proto != protoAWG {
		fmt.Fprintln(os.Stderr, "-find-junk searches AmneziaWG junk params: use -proto awg")
		os.Exit(2)
	}
	o.pingCheck = true

	explicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "n" || f.Name == "sample" {
			explicit = true
		}
	})
	if !explicit {
		o.perSubnet = findJunkSample
	}
}

func applyGenI1(o *options) {
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	o.i1Explicit = explicit["i1"] || o.genI1 != ""

	if o.genI1 == "" {
		if explicit["i1-sni"] {
			fmt.Fprintln(os.Stderr, "-i1-sni needs -gen-i1 PROTO")
			os.Exit(2)
		}
		return
	}
	if o.proto == protoWG {
		fmt.Fprintln(os.Stderr, "-gen-i1 needs AmneziaWG: use -proto awg or -proto both")
		os.Exit(2)
	}
	if explicit["i1"] {
		fmt.Fprintln(os.Stderr, "-gen-i1 and -i1 set the same init packet: drop one")
		os.Exit(2)
	}
	if err := regenI1(*o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func applyGenJunk() {
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	jc, jmin, jmax := awgJc, awgJmin, awgJmax
	genJunkParams()
	if explicit["jc"] {
		awgJc = jc
	}
	if explicit["jmin"] {
		awgJmin = jmin
	}
	if explicit["jmax"] {
		awgJmax = jmax
	}
}

func validateJunkParams() {
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "invalid junk params: "+format+"\n", args...)
		os.Exit(2)
	}
	if awgJc < junkCountLimitMin || awgJc > junkCountLimitMax {
		fail("-jc (%d) must be between %d and %d", awgJc, junkCountLimitMin, junkCountLimitMax)
	}
	if awgJmin > awgJmax {
		fail("-jmin (%d) must be <= -jmax (%d)", awgJmin, awgJmax)
	}
	if awgJmax > tunnelMTU {
		fail("-jmax (%d) must be <= %d", awgJmax, tunnelMTU)
	}
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
	fmt.Fprintln(w, "Working endpoints are reported grouped per subnet")
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
