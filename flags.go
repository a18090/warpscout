package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type options struct {
	tunnelParallel int
	timeoutSec     int
	perSubnet      int
	tunPingCount   int
	junkThreshold  int
	mtu            int
	proto          string
	output         string
	conf           string
	confType       string
	dns            string
	proxy          string
	freshAccount   bool
	iface          string
	accountPath    string
	genI1          string
	i1Host         string
	target         string
	node           string
	country        string
	targets        []netip.Prefix
	colos          []string
	countries      []string
	best           bool
	noReport       bool
	tableOff       bool
	noDNS          bool
	i1Explicit     bool
	tunPingCheck   bool
	genJunk        bool
	wantMeta       bool
	ipv6           bool
	full           bool
	plain          bool
	emoji          bool
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

var (
	netSpecs = []flagSpec{
		{"t", "timeout", "SEC", "per-request timeout"},
		{"6", "ipv6", "", "use IPv6 endpoint pools instead of IPv4"},
		{"", "target", "ADDR", "use these addresses instead of the built-in pools: comma-separated IPs or CIDRs"},
		{"I", "interface", "NAME", "work through this interface (bind to device; Linux, may need CAP_NET_RAW)"},
		{"a", "account", "FILE", "cached WARP account file"},
	}

	scanGroup = flagGroup{"Scan tuning", append([]flagSpec{
		{"jt", "tunnel-jobs", "N", "phase 2 tunnel workers"},
		{"P", "tun-ping", "", fmt.Sprintf("add the TUN PING/LOSS columns: RTT and packet loss measured inside the tunnel to %s, and flag endpoints DPI tears down mid-stream; off by default for speed", pingTarget)},
		{"", "tun-ping-count", "N", fmt.Sprintf("echoes per durability burst, %dms apart - a longer burst catches tunnels DPI kills late (default %d, implies -tun-ping)", pingInterval.Milliseconds(), durabilityPings)},
		{"n", "sample", "N", "addresses to sample per subnet"},
		{"f", "full", "", "scan all 256 addresses per subnet (overrides -sample)"},
	}, netSpecs...)}

	masqueGroup = flagGroup{"MASQUE", []flagSpec{
		{"", "masque-sni", "HOST", "SNI to present to the MASQUE endpoint; a different name often gets through DPI"},
		{"", "masque-attempts", "N", "how many times to re-check a failing MASQUE endpoint before calling it dead"},
	}}

	protoGroup = flagGroup{"Protocol", []flagSpec{
		{"p", "proto", "wg|awg|masque", "tunnel protocol: wg (WireGuard), awg (AmneziaWG) or masque (QUIC)"},
	}}

	awgGroup = flagGroup{"AmneziaWG obfuscation parameters", []flagSpec{
		{"", "gen-junk", "", "randomize junk params per run (overridden by -jc/-jmin/-jmax)"},
		{"", "gen-i1", "PROTO", "generate the init packet per run: quic, dns, sip, stun or random"},
		{"", "i1-sni", "HOST", "host to mimic in the generated I1 (default: a random well-known host)"},
		{"", "jc", "N", "junk packet count"},
		{"", "jmin", "N", "min junk packet size"},
		{"", "jmax", "N", "max junk packet size"},
		{"", "i1", "PKT", "custom init packet, or \"none\" to send none (default: built-in iCloud probe)"},
	}}

	outputGroup = flagGroup{"Output", []flagSpec{
		{"o", "output", "FILE", "full per-endpoint report file (default warpscout-report-<timestamp>.txt)"},
		{"", "no-report", "", "skip the report file entirely (overrides -o)"},
		{"", "conf", "FILE", "write a ready-to-import config for the best endpoint (\"-\" prints it instead)"},
		{"", "conf-type", "KIND", "format of -conf: native (wg/awg .conf, usque config.json) or mihomo"},
		{"", "table-off", "", "add \"Table = off\" to the generated config: bring the interface up without touching routes"},
		{"", "mtu", "N", "set MTU in the generated config (default: leave the line out)"},
		{"", "dns", "LIST", "DNS servers in the generated config: comma-separated (default: Cloudflare, following -6)"},
		{"", "no-dns", "", "leave the DNS line out of the generated config"},
		{"", "node", "COLO", "keep only endpoints landing on these edge nodes: comma-separated IATA codes"},
		{"", "country", "ISO", "keep only endpoints whose edge node sits in these countries: comma-separated ISO codes"},
		{"", "best", "", "print just the best endpoint as ip:port on stdout (for scripts and pipes)"},
		{"", "plain", "", "force plain line output (no live TUI)"},
		{"", "emoji", "", "prefix the colo region with a country flag emoji (rendering depends on the terminal)"},
	}}

	registerGroup = flagGroup{"Registration", append([]flagSpec{
		{"x", "proxy", "URL", "http(s)/socks5 proxy for registration"},
		{"", "fresh", "", "ignore the existing account file and register a brand-new account"},
	}, netSpecs...)}

	findJunkGroup = flagGroup{"Search tuning", append([]flagSpec{
		{"jt", "tunnel-jobs", "N", "tunnel workers per attempt"},
		{"n", "sample", "N", "addresses to sample per subnet"},
		{"", "threshold", "PCT", "accept a junk set once this share of sampled endpoints works"},
	}, netSpecs...)}

	findJunkI1Group = flagGroup{"AmneziaWG init packet", []flagSpec{
		{"", "gen-i1", "PROTO", "generate the init packet per attempt: quic, dns, sip, stun or random"},
		{"", "i1-sni", "HOST", "host to mimic in the generated I1 (default: a random well-known host)"},
	}}

	plainGroup = flagGroup{"Output", []flagSpec{
		{"", "plain", "", "force plain line output (no live TUI)"},
	}}
)

const defaultTunnelJobs = 10

func intFlag(fs *flag.FlagSet, p *int, def int, short, long string) {
	fs.IntVar(p, short, def, "")
	fs.IntVar(p, long, def, "")
}

func strFlag(fs *flag.FlagSet, p *string, def, short, long string) {
	fs.StringVar(p, short, def, "")
	fs.StringVar(p, long, def, "")
}

func boolFlag(fs *flag.FlagSet, p *bool, short, long string) {
	fs.BoolVar(p, short, false, "")
	fs.BoolVar(p, long, false, "")
}

func addNetFlags(fs *flag.FlagSet, o *options) {
	intFlag(fs, &o.timeoutSec, 2, "t", "timeout")
	boolFlag(fs, &o.ipv6, "6", "ipv6")
	strFlag(fs, &o.iface, "", "I", "interface")
	strFlag(fs, &o.accountPath, defaultAccount, "a", "account")
	fs.StringVar(&o.target, "target", "", "")
}

func addAWGFlags(fs *flag.FlagSet, o *options) {
	fs.BoolVar(&o.genJunk, "gen-junk", false, "")
	fs.IntVar(&awgJc, "jc", awgJc, "")
	fs.IntVar(&awgJmin, "jmin", awgJmin, "")
	fs.IntVar(&awgJmax, "jmax", awgJmax, "")
	fs.StringVar(&awgI1, "i1", awgI1, "")
	addI1GenFlags(fs, o)
}

func addI1GenFlags(fs *flag.FlagSet, o *options) {
	fs.StringVar(&o.genI1, "gen-i1", "", "")
	fs.StringVar(&o.i1Host, "i1-sni", "", "")
}

func setupScanFlags(fs *flag.FlagSet, o *options) {
	addNetFlags(fs, o)
	addAWGFlags(fs, o)
	intFlag(fs, &o.tunnelParallel, defaultTunnelJobs, "jt", "tunnel-jobs")
	intFlag(fs, &o.perSubnet, 5, "n", "sample")
	strFlag(fs, &o.proto, protoWG, "p", "proto")
	strFlag(fs, &o.output, "", "o", "output")
	fs.BoolVar(&o.noReport, "no-report", false, "")
	boolFlag(fs, &o.tunPingCheck, "P", "tun-ping")
	fs.IntVar(&o.tunPingCount, "tun-ping-count", 0, "")
	boolFlag(fs, &o.full, "f", "full")
	fs.StringVar(&o.node, "node", "", "")
	fs.StringVar(&o.country, "country", "", "")
	fs.BoolVar(&o.best, "best", false, "")
	fs.StringVar(&o.conf, "conf", "", "")
	fs.StringVar(&o.confType, "conf-type", confTypeNative, "")
	fs.StringVar(&masqueSNI, "masque-sni", masqueDefaultSNI, "")
	fs.IntVar(&masqueAttempts, "masque-attempts", masqueDefaultAttempts, "")
	fs.BoolVar(&o.tableOff, "table-off", false, "")
	fs.IntVar(&o.mtu, "mtu", 0, "")
	fs.StringVar(&o.dns, "dns", "", "")
	fs.BoolVar(&o.noDNS, "no-dns", false, "")
	fs.BoolVar(&o.plain, "plain", false, "")
	fs.BoolVar(&o.emoji, "emoji", false, "")
	o.wantMeta = true
}

func setupRegisterFlags(fs *flag.FlagSet, o *options) {
	addNetFlags(fs, o)
	addAWGFlags(fs, o)
	strFlag(fs, &o.proxy, "", "x", "proxy")
	fs.BoolVar(&o.freshAccount, "fresh", false, "")
	fs.BoolVar(&o.plain, "plain", false, "")
	// The tunnel fallback sweeps both protocols anyway; awg goes first because it
	// is the one that survives DPI, which is why the fallback ran at all.
	o.proto = protoAWG
	o.perSubnet = registerSample
}

func setupFindJunkFlags(fs *flag.FlagSet, o *options) {
	addNetFlags(fs, o)
	addI1GenFlags(fs, o)
	intFlag(fs, &o.tunnelParallel, defaultTunnelJobs, "jt", "tunnel-jobs")
	intFlag(fs, &o.perSubnet, findJunkSample, "n", "sample")
	fs.IntVar(&o.junkThreshold, "threshold", defaultJunkThreshold, "")
	fs.BoolVar(&o.plain, "plain", false, "")
	o.proto = protoAWG
	o.tunPingCheck = true
}

// Flags a command does not register stay at their zero value, so each step here
// is a no-op for the commands it does not apply to.
func applyCommonFlags(fs *flag.FlagSet, o *options) {
	for _, f := range []struct{ name, value string }{{"conf", o.conf}, {"o", o.output}} {
		if f.name == "conf" && f.value == confStdout {
			continue
		}
		if strings.HasPrefix(f.value, "-") {
			fmt.Fprintf(os.Stderr, "-%s needs a file name, got %q\n", f.name, f.value)
			os.Exit(2)
		}
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q\n", fs.Arg(0))
		os.Exit(2)
	}
	if awgI1 == i1Keyword {
		awgI1 = ""
	}
	// One invariant for everything downstream: pings is the burst length and
	// tunPingCheck is "burst at all", so -tun-ping-count alone turns the measurement on rather than
	// silently measuring nothing.
	o.tunPingCount = max(o.tunPingCount, 0)
	if o.tunPingCount > 0 {
		o.tunPingCheck = true
	} else if o.tunPingCheck {
		o.tunPingCount = durabilityPings
	}
	// Too short a burst hands back dead endpoints as working: measured 8 of 70
	// "working" wg peers at -tun-ping-count 2 (where a tail run does not even fit) and 13 at
	// -tun-ping-count 3, all of which -tun-ping-count 10 proved dead.
	if o.tunPingCount > 0 && o.tunPingCount < minDurabilityPings {
		fmt.Fprintf(os.Stderr, "-tun-ping-count must be at least %d: a shorter burst reports torn-down endpoints as working\n", minDurabilityPings)
		os.Exit(2)
	}
	if o.genJunk {
		if o.proto != protoAWG {
			fmt.Fprintln(os.Stderr, "-gen-junk needs AmneziaWG: use -proto awg")
			os.Exit(2)
		}
		applyGenJunk(fs)
	}
	applyGenI1(fs, o)
	validateJunkParams()
	validateMTU(*o)
	validateConfType(*o)
	applyDNS(o)
	applyTarget(o)
	applyNode(o)
	rejectMasqueFilters(*o)
	validateMasqueAttempts()
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
	o.colos = splitList(o.node, "-node")
	o.countries = splitList(o.country, "-country")
}

func splitList(value, flagName string) []string {
	if value == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.ToUpper(strings.TrimSpace(item)); item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		fmt.Fprintln(os.Stderr, flagName+" is empty")
		os.Exit(2)
	}
	return out
}

func applyGenI1(fs *flag.FlagSet, o *options) {
	explicit := explicitFlags(fs)
	o.i1Explicit = explicit["i1"] || o.genI1 != ""

	if o.genI1 == "" {
		if explicit["i1-sni"] {
			fmt.Fprintln(os.Stderr, "-i1-sni needs -gen-i1 PROTO")
			os.Exit(2)
		}
		return
	}
	if o.proto != protoAWG {
		fmt.Fprintln(os.Stderr, "-gen-i1 needs AmneziaWG: use -proto awg")
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

func applyGenJunk(fs *flag.FlagSet) {
	explicit := explicitFlags(fs)

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

func explicitFlags(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
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

func validateMTU(o options) {
	if o.mtu == 0 {
		return
	}
	if o.mtu < mtuMin || o.mtu > mtuMax {
		fmt.Fprintf(os.Stderr, "-mtu (%d) must be between %d and %d\n", o.mtu, mtuMin, mtuMax)
		os.Exit(2)
	}
}

func validateConfType(o options) {
	if o.confType == "" {
		return
	}
	if !slices.Contains(confTypes, o.confType) {
		fmt.Fprintf(os.Stderr, "-conf-type %q must be one of %s\n", o.confType, strings.Join(confTypes, ", "))
		os.Exit(2)
	}
	if o.conf == "" && o.confType != confTypeNative {
		fmt.Fprintln(os.Stderr, "-conf-type needs -conf FILE")
		os.Exit(2)
	}
	if o.tableOff && o.confType == confTypeMihomo {
		fmt.Fprintln(os.Stderr, "-table-off does not apply to -conf-type mihomo: the client owns the routes")
		os.Exit(2)
	}
}

func applyDNS(o *options) {
	if o.dns == "" && !o.noDNS {
		return
	}
	if o.conf == "" {
		fmt.Fprintln(os.Stderr, "-dns and -no-dns need -conf FILE")
		os.Exit(2)
	}
	if o.dns != "" && o.noDNS {
		fmt.Fprintln(os.Stderr, "-dns and -no-dns contradict each other: drop one")
		os.Exit(2)
	}
	if o.noDNS {
		return
	}

	var servers []string
	for _, item := range strings.Split(o.dns, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if net.ParseIP(item) == nil {
			fmt.Fprintf(os.Stderr, "-dns %q is not an IP address\n", item)
			os.Exit(2)
		}
		servers = append(servers, item)
	}
	if len(servers) == 0 {
		fmt.Fprintln(os.Stderr, "-dns is empty")
		os.Exit(2)
	}
	o.dns = strings.Join(servers, ", ")
}

func rootUsage(w io.Writer) {
	st := newConStyles(lipgloss.NewRenderer(w))

	fmt.Fprintln(w, st.title.Render("warpscout")+" - find the exit colo and region of Cloudflare WARP endpoints")
	fmt.Fprintln(w)
	fmt.Fprintln(w, st.title.Render("Usage:"))
	fmt.Fprintf(w, "  %s <command> [options]\n", st.accent.Render("warpscout"))
	fmt.Fprintf(w, "\n%s\n", st.title.Render("Commands"))

	col := 0
	for _, c := range commands {
		if len(c.name) > col {
			col = len(c.name)
		}
	}
	for _, c := range commands {
		fmt.Fprintf(w, "  %s%s%s\n", st.accent.Render(c.name), strings.Repeat(" ", col-len(c.name)+2), c.brief)
	}
	fmt.Fprintf(w, "\nRun %s for the options of a command.\n", st.accent.Render("warpscout <command> -h"))
	fmt.Fprintln(w, "Start with "+st.accent.Render("warpscout register")+" - every other command needs a WARP account.")
}

func commandUsage(w io.Writer, cmd command, fs *flag.FlagSet) {
	st := newConStyles(lipgloss.NewRenderer(w))

	fmt.Fprintln(w, st.title.Render("warpscout "+cmd.name)+" - "+cmd.brief)
	fmt.Fprintln(w)
	for _, line := range cmd.intro {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, st.title.Render("Usage:"))
	fmt.Fprintf(w, "  %s [options]\n", st.accent.Render("warpscout "+cmd.name))

	col := flagColumnWidth(cmd.groups)
	for _, g := range cmd.groups {
		fmt.Fprintf(w, "\n%s\n", st.title.Render(g.title))
		for _, s := range g.specs {
			names := flagNames(s)
			fmt.Fprintf(w, "%s%s%s%s\n",
				st.accent.Render(names), strings.Repeat(" ", col-len(names)+2), s.help, defaultNote(st, fs, s.long))
		}
	}
}

func flagNames(s flagSpec) string {
	if s.short == "" {
		return fmt.Sprintf("  -%s %s", s.long, s.meta)
	}
	return fmt.Sprintf("  -%s, -%s %s", s.short, s.long, s.meta)
}

func flagColumnWidth(groups []flagGroup) int {
	max := 0
	for _, g := range groups {
		for _, s := range g.specs {
			if n := len(flagNames(s)); n > max {
				max = n
			}
		}
	}
	return max
}

func defaultNote(st conStyles, fs *flag.FlagSet, long string) string {
	f := fs.Lookup(long)
	if f == nil || f.DefValue == "" || f.DefValue == "false" || f.DefValue == "0" {
		return ""
	}
	if len(f.DefValue) > 40 {
		return ""
	}
	return st.dim.Render(fmt.Sprintf(" (default %s)", f.DefValue))
}

func rejectMasqueFilters(o options) {
	if o.proto != protoMASQUE {
		return
	}
	for _, f := range []struct {
		name string
		set  bool
	}{{"-node", len(o.colos) > 0}, {"-country", len(o.countries) > 0}} {
		if f.set {
			fmt.Fprintf(os.Stderr, "%s does not apply to -proto masque: every MASQUE endpoint exits through the same node\n", f.name)
			os.Exit(2)
		}
	}
}

func validateMasqueAttempts() {
	if masqueAttempts < 1 {
		fmt.Fprintln(os.Stderr, "-masque-attempts must be at least 1")
		os.Exit(2)
	}
}
