package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/crypto/curve25519"
)

func TestWriteConsolePalette(t *testing.T) {
	ph := phaseResult{
		run: protoRun{kindWG, "wg"},
		results: []endpointResult{{
			ip:       netip.MustParseAddr("8.47.69.86"),
			exit:     metaResult{loc: "RU", colo: "DME"},
			endpoint: "8.47.69.86:2408",
			ok:       true,
			durable:  true,
		}},
	}

	var plain bytes.Buffer
	rPlain := lipgloss.NewRenderer(&plain)
	rPlain.SetColorProfile(termenv.Ascii)
	writeConsole(&plain, ph, rPlain, false)
	if strings.Contains(plain.String(), "\033") {
		t.Error("plain (non-TTY) console output must not contain ANSI escapes")
	}
	if !strings.Contains(plain.String(), "8.47.69.86:2408") {
		t.Error("console output missing the working endpoint")
	}

	var colored bytes.Buffer
	rColor := lipgloss.NewRenderer(&colored)
	rColor.SetColorProfile(termenv.TrueColor)
	writeConsole(&colored, ph, rColor, false)
	if !strings.Contains(colored.String(), "\033") {
		t.Error("colored console output should contain ANSI escapes")
	}
}

func TestWriteFullReport(t *testing.T) {
	mk := func(ip, colo, city string, ms int) endpointResult {
		return endpointResult{
			ip:       netip.MustParseAddr(ip),
			endpoint: ip + ":2408",
			exit:     metaResult{loc: "RU", colo: colo, coloCity: city, coloISO: "RU"},
			epPing:   time.Duration(ms) * time.Millisecond,
			ok:       true,
			durable:  true,
		}
	}
	// Two addresses of the same /24 landing on different nodes - the case the
	// old per-subnet summary collapsed to a single row.
	results := []endpointResult{
		mk("188.114.96.28", "ARN", "Stockholm", 63),
		mk("188.114.96.99", "DME", "Moscow", 41),
		mk("162.159.195.192", "KJA", "Krasnoyarsk", 22),
	}

	var buf bytes.Buffer
	writeFullReport(&buf, results, false)
	out := buf.String()

	if strings.Contains(out, "═") || strings.Contains(out, "──") {
		t.Error("report must not contain box drawing characters")
	}
	order := []string{"162.159.195.192:2408", "188.114.96.99:2408", "188.114.96.28:2408"}
	for i := 1; i < len(order); i++ {
		if strings.Index(out, order[i-1]) > strings.Index(out, order[i]) {
			t.Errorf("endpoints not sorted by ping: %s came after %s", order[i-1], order[i])
		}
	}

	_, picks, ok := strings.Cut(out, "# Best endpoint per node")
	if !ok {
		t.Fatal("report missing the per-node summary")
	}
	for _, node := range []string{"ARN", "DME", "KJA"} {
		if !strings.Contains(picks, node) {
			t.Errorf("per-node summary missing node %s", node)
		}
	}
}

func TestLessByLossRTT(t *testing.T) {
	mk := func(ep string, ms int, loss float32, measured bool) endpointResult {
		return endpointResult{endpoint: ep, tunPing: time.Duration(ms) * time.Millisecond, loss: loss, measured: measured}
	}
	cases := []struct {
		name string
		a, b endpointResult
		want bool // a ranks before b
	}{
		{"lower loss beats lower ping", mk("a", 200, 0, true), mk("b", 20, 0.2, true), true},
		{"equal loss falls back to ping", mk("a", 20, 0.1, true), mk("b", 90, 0.1, true), true},
		{"unmeasured ranks by host ping", endpointResult{endpoint: "a", epPing: 20 * time.Millisecond}, endpointResult{endpoint: "b", epPing: 90 * time.Millisecond}, true},
		{"tie broken by endpoint", mk("a", 20, 0, true), mk("b", 20, 0, true), true},
	}
	for _, c := range cases {
		if got := lessByLossRTT(c.a, c.b); got != c.want {
			t.Errorf("%s: lessByLossRTT = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPingDiagnostics(t *testing.T) {
	cases := []struct {
		name     string
		total    time.Duration
		got      int
		count    int
		wantRTT  time.Duration
		wantLoss float32
	}{
		{"no loss", 400 * time.Millisecond, 4, 4, 100 * time.Millisecond, 0},
		{"half loss", 100 * time.Millisecond, 2, 4, 50 * time.Millisecond, 0.5},
		{"total loss", 0, 0, 4, 0, 1},
	}
	for _, c := range cases {
		if rtt := pingSummary(c.total, c.got); rtt != c.wantRTT {
			t.Errorf("%s: pingSummary = %v, want %v", c.name, rtt, c.wantRTT)
		}
		if loss := lossFraction(c.got, c.count); loss != c.wantLoss {
			t.Errorf("%s: lossFraction = %v, want %v", c.name, loss, c.wantLoss)
		}
	}
}

func TestTeardown(t *testing.T) {
	cases := []struct {
		name    string
		results []bool
		want    bool
	}{
		{"all ok", []bool{true, true, true, true, true}, false},
		{"sporadic single drop is loss, not torn", []bool{true, false, true, true, true}, false},
		{"two mid drops recover", []bool{true, false, false, true, true}, false},
		{"tail teardown (DPI)", []bool{true, true, true, false, false, false}, true},
		{"trips early, never recovers", []bool{true, false, false, false, false}, true},
		{"short trailing run below threshold", []bool{true, true, true, true, false, false}, false},
	}
	for _, c := range cases {
		if got := teardown(c.results); got != c.want {
			t.Errorf("%s: teardown(%v) = %v, want %v", c.name, c.results, got, c.want)
		}
	}
}

func TestBestByPing(t *testing.T) {
	mk := func(ep string, ms int) endpointResult {
		return endpointResult{endpoint: ep, epPing: time.Duration(ms) * time.Millisecond}
	}

	picks := []endpointResult{mk("a", 0), mk("b", 90), mk("c", 40)}
	if got := bestByPing(picks); got.endpoint != "c" {
		t.Errorf("bestByPing = %q, want c (40ms)", got.endpoint)
	}

	allUnknown := []endpointResult{mk("x", 0), mk("y", 0)}
	if got := bestByPing(allUnknown); got.endpoint != "x" {
		t.Errorf("bestByPing(all unknown) = %q, want x", got.endpoint)
	}
}

func TestBaseUAPI(t *testing.T) {
	wg, err := baseUAPI(false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wg, "private_key=") {
		t.Error("base config missing private_key")
	}
	if strings.Contains(wg, "jc=") || strings.Contains(wg, "i1=") {
		t.Error("plain WireGuard config must not contain junk params")
	}

	awg, err := baseUAPI(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"jc=6", "jmin=10", "jmax=50", "i1=" + i1Default} {
		if !strings.Contains(awg, want) {
			t.Errorf("AmneziaWG config missing %q", want)
		}
	}
}

func TestRenderConf(t *testing.T) {
	awg := renderConf(options{ipv6: true}, "188.114.98.5:2408", protoRun{kindAWG, protoAWG})
	for _, want := range []string{
		"[Interface]",
		"Address = " + warpAddressV6 + "/128",
		"AllowedIPs = ::/0",
		"PrivateKey = " + warpPrivateKey,
		"Jc = 6", "Jmin = 10", "Jmax = 50",
		"I1 = " + i1Default,
		"DNS = " + warpDNSv6,
		"[Peer]",
		"PublicKey = " + warpPublicKey,
		"Endpoint = 188.114.98.5:2408",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(awg, want) {
			t.Errorf("AmneziaWG config missing %q:\n%s", want, awg)
		}
	}
	if strings.Contains(awg, "Table") {
		t.Errorf("Table must be absent without -table-off:\n%s", awg)
	}
	if strings.Contains(awg, "MTU") {
		t.Errorf("MTU must be absent without -mtu:\n%s", awg)
	}
	if strings.Contains(awg, "0.0.0.0") || strings.Contains(awg, warpAddress) {
		t.Errorf("IPv6 config must not carry IPv4:\n%s", awg)
	}

	wg := renderConf(options{tableOff: true, mtu: 1420}, "188.114.98.5:2408", protoRun{kindWG, protoWG})
	for _, unwanted := range []string{"Jc = ", "Jmin = ", "Jmax = ", "I1 = ", "::"} {
		if strings.Contains(wg, unwanted) {
			t.Errorf("plain WireGuard config must not contain %q:\n%s", unwanted, wg)
		}
	}
	if !strings.Contains(wg, "Table = off") {
		t.Errorf("-table-off not reflected:\n%s", wg)
	}
	if !strings.Contains(wg, "MTU = 1420") {
		t.Errorf("-mtu not reflected:\n%s", wg)
	}
}

func TestRenderMihomoConf(t *testing.T) {
	conf, err := renderMihomoConf(options{confType: confTypeMihomo}, "188.114.98.5:2408", protoRun{kindAWG, protoAWG})
	if err != nil {
		t.Fatal(err)
	}
	awg := string(conf)
	for _, want := range []string{
		"proxies:",
		"- name: \"WARP 188.114.98.5:2408\"",
		"server: 188.114.98.5",
		"port: 2408",
		"type: wireguard",
		"private-key: " + warpPrivateKey,
		"public-key: " + warpPublicKey,
		"ip: " + warpAddress,
		"allowed-ips: ['0.0.0.0/0']",
		"amnezia-wg-option:",
		"jc: 6", "jmin: 10", "jmax: 50",
		"h4: 4",
		"i1: " + i1Default,
		"udp: true",
	} {
		if !strings.Contains(awg, want) {
			t.Errorf("mihomo config missing %q:\n%s", want, awg)
		}
	}
	if strings.Contains(awg, "mtu:") {
		t.Errorf("mtu must be absent without -mtu:\n%s", awg)
	}
	if strings.Contains(awg, "ipv6:") || strings.Contains(awg, "::") {
		t.Errorf("IPv4 config must not carry IPv6:\n%s", awg)
	}

	conf, err = renderMihomoConf(options{confType: confTypeMihomo, ipv6: true}, "[2606:4700:d0::1]:2408", protoRun{kindAWG, protoAWG})
	if err != nil {
		t.Fatal(err)
	}
	v6 := string(conf)
	for _, want := range []string{"server: 2606:4700:d0::1", "ipv6: " + warpAddressV6, "allowed-ips: ['::/0']", "dns: [" + warpDNSv6 + "]"} {
		if !strings.Contains(v6, want) {
			t.Errorf("IPv6 mihomo config missing %q:\n%s", want, v6)
		}
	}
	if strings.Contains(v6, "ip: ") || strings.Contains(v6, "1.1.1.1") {
		t.Errorf("IPv6 config must not carry IPv4:\n%s", v6)
	}

	conf, err = renderMihomoConf(options{confType: confTypeMihomo}, "188.114.98.5:2408", protoRun{kindWG, protoWG})
	if err != nil {
		t.Fatal(err)
	}
	if wg := string(conf); strings.Contains(wg, "amnezia-wg-option") {
		t.Errorf("plain WireGuard config must not carry junk params:\n%s", wg)
	}
}

func TestConfDNS(t *testing.T) {
	wg := renderConf(options{}, "188.114.98.5:2408", protoRun{kindWG, protoWG})
	if !strings.Contains(wg, "DNS = "+warpDNSv4) {
		t.Errorf("default DNS missing:\n%s", wg)
	}

	custom := renderConf(options{dns: "9.9.9.9"}, "188.114.98.5:2408", protoRun{kindWG, protoWG})
	if !strings.Contains(custom, "DNS = 9.9.9.9") || strings.Contains(custom, warpDNSv4) {
		t.Errorf("-dns not reflected:\n%s", custom)
	}

	off := renderConf(options{noDNS: true}, "188.114.98.5:2408", protoRun{kindWG, protoWG})
	if strings.Contains(off, "DNS = ") {
		t.Errorf("-no-dns must drop the DNS line:\n%s", off)
	}

	conf, err := renderMihomoConf(options{confType: confTypeMihomo, noDNS: true}, "188.114.98.5:2408", protoRun{kindWG, protoWG})
	if err != nil {
		t.Fatal(err)
	}
	mihomo := string(conf)
	if strings.Contains(mihomo, "dns:") || strings.Contains(mihomo, "remote-dns-resolve") {
		t.Errorf("-no-dns must drop both DNS lines in mihomo:\n%s", mihomo)
	}
}

func TestRenderConfNoInitPacket(t *testing.T) {
	orig := awgI1
	defer func() { awgI1 = orig }()

	awgI1 = ""
	if conf := renderConf(options{}, "188.114.98.5:2408", protoRun{kindAWG, protoAWG}); strings.Contains(conf, "I1 = ") {
		t.Errorf("init packet must be omitted when empty:\n%s", conf)
	}
}

func TestBaseUAPINoInitPacket(t *testing.T) {
	orig := awgI1
	defer func() { awgI1 = orig }()

	awgI1 = ""
	awg, err := baseUAPI(true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(awg, "i1=") {
		t.Errorf("init packet must be omitted when empty: %q", awg)
	}
}

func TestBaseUAPIOverridesJunkParams(t *testing.T) {
	orig := awgJc
	defer func() { awgJc = orig }()

	awgJc = 99
	awg, err := baseUAPI(true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(awg, "jc=99") {
		t.Errorf("override not reflected in UAPI: %q", awg)
	}
}

func TestGenJunkParams(t *testing.T) {
	jc, jmin, jmax := awgJc, awgJmin, awgJmax
	defer func() { awgJc, awgJmin, awgJmax = jc, jmin, jmax }()

	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		genJunkParams()
		if awgJc < junkCountLimitMin || awgJc > junkCountLimitMax {
			t.Fatalf("jc out of range: %d", awgJc)
		}
		if awgJmin > awgJmax {
			t.Fatalf("jmin %d > jmax %d", awgJmin, awgJmax)
		}
		if awgJmax > tunnelMTU {
			t.Fatalf("jmax exceeds MTU: %d", awgJmax)
		}
		seen[awgJc] = true
	}
	if len(seen) < 2 {
		t.Errorf("jc never varied over 200 runs: %v", seen)
	}
}

func TestJunkCommand(t *testing.T) {
	c := junkCandidate{jc: 5, jmin: 22, jmax: 80, i1: i1Default}
	if got, want := junkCommand(c), "-proto awg -jc 5 -jmin 22 -jmax 80"; !strings.HasSuffix(got, want) {
		t.Errorf("junkCommand() = %q, want suffix %q", got, want)
	}

	c.i1 = ""
	if got := junkCommand(c); !strings.HasSuffix(got, "-i1 none") {
		t.Errorf("junkCommand() = %q, want -i1 none", got)
	}

	c.i1, c.i1Label = "<r 4>", "quic(www.apple.com)"
	if got := junkCommand(c); !strings.HasSuffix(got, `-i1 "<r 4>"`) {
		t.Errorf("junkCommand() = %q, want the generated I1", got)
	}
}

func TestParseProto(t *testing.T) {
	for _, p := range []string{protoWG, protoAWG, protoMASQUE} {
		run, err := parseProto(p)
		if err != nil || run.name != p || run.isAWG() != (p == protoAWG) || run.isMASQUE() != (p == protoMASQUE) {
			t.Errorf("parseProto(%q) = %+v, %v", p, run, err)
		}
	}
	if _, err := parseProto("both"); err == nil {
		t.Error("parseProto(\"both\") accepted, want an error")
	}
}

func TestPoolsFor(t *testing.T) {
	masque := protoRun{kindMASQUE, protoMASQUE}
	if got := poolsFor(masque, false); len(got) != len(masquePoolsV4) || got[0] != masquePoolsV4[0] {
		t.Errorf("poolsFor(masque, v4) = %v, want the MASQUE pools", got)
	}
	if got := poolsFor(masque, true); len(got) != len(masquePoolsV6) {
		t.Errorf("poolsFor(masque, v6) = %v, want the MASQUE v6 pools", got)
	}
	if got := poolsFor(protoRun{kindAWG, protoAWG}, false); len(got) != len(poolsV4) {
		t.Errorf("poolsFor(awg, v4) = %d prefixes, want the WireGuard pools", len(got))
	}
}

// The MASQUE prefixes are single addresses, so expansion must hand back exactly
// those and never sample them away.
func TestExpandMasquePools(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pool  []netip.Prefix
		count int
	}{{"v4", masquePoolsV4, 2}, {"v6", masquePoolsV6, 2}} {
		pools = tc.pool
		for _, sample := range []int{0, 1, 5} {
			if got := expandPools(sample); len(got) != tc.count {
				t.Errorf("expandPools(%d) over %s = %v, want %d addresses", sample, tc.name, got, tc.count)
			}
		}
	}
	pools = poolsV4
}

func TestProbeTargets(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("162.159.198.1"), netip.MustParseAddr("162.159.198.2")}
	ports := []int{443, 8443}

	wg := probeTargets(protoRun{kindAWG, protoAWG}, ips, ports)
	if len(wg) != len(ips) {
		t.Fatalf("wg targets = %d, want one per address", len(wg))
	}
	for _, tg := range wg {
		if tg.port != 0 {
			t.Errorf("wg target %v pins a port, want the tunnel's own list", tg)
		}
	}

	// Working ports differ per MASQUE address, so every pair must be its own row.
	masque := probeTargets(protoRun{kindMASQUE, protoMASQUE}, ips, ports)
	if len(masque) != len(ips)*len(ports) {
		t.Fatalf("masque targets = %d, want %d", len(masque), len(ips)*len(ports))
	}
	seen := map[string]bool{}
	for _, tg := range masque {
		seen[tg.ip.String()+":"+strconv.Itoa(tg.port)] = true
	}
	for _, want := range []string{"162.159.198.1:443", "162.159.198.1:8443", "162.159.198.2:443", "162.159.198.2:8443"} {
		if !seen[want] {
			t.Errorf("masque targets missing %s", want)
		}
	}
}

// A dead WireGuard peer is dead; a MASQUE endpoint has to fail every attempt
// before it counts, because the same one answers on a later try.
func TestTunnelAttempts(t *testing.T) {
	if got := (&wgTunnel{}).attempts(); got != 1 {
		t.Errorf("wgTunnel.attempts() = %d, want 1", got)
	}
	if masqueDefaultAttempts < 2 {
		t.Errorf("masqueDefaultAttempts = %d, want more than one try", masqueDefaultAttempts)
	}
	saved := masqueAttempts
	defer func() { masqueAttempts = saved }()
	masqueAttempts = 7
	if got := (&masqueTunnel{}).attempts(); got != 7 {
		t.Errorf("masqueTunnel.attempts() = %d, want the -masque-attempts value", got)
	}
}

func TestRenderMasqueConf(t *testing.T) {
	saved := masqueAcct
	defer func() { masqueAcct = saved }()
	masqueAcct = &masqueAccount{
		PrivateKey: "cHJpdg==", PeerPublicKey: "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n",
		ID: "dev-1", Token: "tok", IPv4: "172.16.0.2", IPv6: "2606:4700:110::1",
	}

	out, err := renderMasqueConf("162.159.198.1:8443")
	if err != nil {
		t.Fatalf("renderMasqueConf: %v", err)
	}
	var c usqueConf
	if err := json.Unmarshal(out, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.EndpointV4 != "162.159.198.1" {
		t.Errorf("EndpointV4 = %q, want the scanned address without its port", c.EndpointV4)
	}
	// The other family keeps a usable default instead of being blanked out.
	if c.EndpointV6 == "" {
		t.Error("EndpointV6 is empty, want the default MASQUE v6 endpoint")
	}
	if c.ID != "dev-1" || c.AccessToken != "tok" || c.IPv4 != "172.16.0.2" {
		t.Errorf("conf lost account fields: %+v", c)
	}

	if _, err := renderMasqueConf("162.159.198.1"); err == nil {
		t.Error("renderMasqueConf accepted an endpoint without a port")
	}
}

func TestRenderMasqueConfV6Endpoint(t *testing.T) {
	saved := masqueAcct
	defer func() { masqueAcct = saved }()
	masqueAcct = &masqueAccount{PrivateKey: "cHJpdg==", ID: "dev-1"}

	out, err := renderMasqueConf("[2606:4700:103::1]:443")
	if err != nil {
		t.Fatalf("renderMasqueConf: %v", err)
	}
	var c usqueConf
	if err := json.Unmarshal(out, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.EndpointV6 != "2606:4700:103::1" {
		t.Errorf("EndpointV6 = %q, want the scanned v6 address", c.EndpointV6)
	}
	if c.EndpointV4 == "" {
		t.Error("EndpointV4 is empty, want the default MASQUE v4 endpoint")
	}
}

func TestScoreJunk(t *testing.T) {
	ph := phaseResult{results: []endpointResult{
		{ok: true, durable: true},
		{ok: true, durable: false},
		{},
	}}
	if c := scoreJunk(ph); c.working != 1 || c.total != 3 {
		t.Errorf("scoreJunk() = %d/%d, want 1/3", c.working, c.total)
	}
	if c := scoreJunk(phaseResult{}); c.total != 0 {
		t.Errorf("scoreJunk(empty) total = %d, want 0", c.total)
	}
}

func TestScoreSNI(t *testing.T) {
	ph := phaseResult{results: []endpointResult{
		{ok: true, durable: true},
		{ok: true, durable: true},
		{ok: true, durable: false},
		{},
	}}
	c := scoreSNI("www.apple.com", ph)
	if c.working != 2 || c.total != 4 {
		t.Errorf("scoreSNI() = %d/%d, want 2/4", c.working, c.total)
	}
	if !c.meets(50) || c.meets(51) {
		t.Errorf("meets() at 2/4 = (%v, %v), want (true, false)", c.meets(50), c.meets(51))
	}
	if (sniCandidate{}).meets(1) {
		t.Error("meets() on an empty candidate = true, want false")
	}
}

func TestSNICommand(t *testing.T) {
	got := sniCommand(sniCandidate{sni: "www.apple.com"})
	if want := "scan -proto masque -masque-sni www.apple.com"; !strings.HasSuffix(got, want) {
		t.Errorf("sniCommand() = %q, want suffix %q", got, want)
	}
	got = sniCommand(sniCandidate{sni: masqueDefaultSNI})
	if want := "scan -proto masque"; !strings.HasSuffix(got, want) {
		t.Errorf("sniCommand(default) = %q, want suffix %q", got, want)
	}
}

func TestPeerUAPI(t *testing.T) {
	peer, err := peerUAPI("1.2.3.4:2408")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"replace_peers=true", "public_key=", "endpoint=1.2.3.4:2408", "allowed_ip=0.0.0.0/0"} {
		if !strings.Contains(peer, want) {
			t.Errorf("missing %q in peer config", want)
		}
	}
}

func TestGenerateKeypair(t *testing.T) {
	privB64, pubB64, err := generateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil || len(priv) != 32 {
		t.Fatalf("bad private key: %v (len %d)", err, len(priv))
	}
	// Clamp bits must be set (RFC 7748 / wg key format).
	if priv[0]&7 != 0 || priv[31]&128 != 0 || priv[31]&64 == 0 {
		t.Error("private key not clamped")
	}
	want, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(want) != pubB64 {
		t.Error("public key does not match private key")
	}
}

func TestParseRegResp(t *testing.T) {
	body := []byte(`{"id":"dev123","token":"tok456","config":{` +
		`"interface":{"addresses":{"v4":"172.16.0.5/32"}},` +
		`"peers":[{"public_key":"PEERPUBKEY"}]}}`)
	a, err := parseRegResp(body, "MYPRIVKEY")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "dev123" || a.Token != "tok456" {
		t.Errorf("id/token = %q/%q", a.ID, a.Token)
	}
	if a.PrivateKey != "MYPRIVKEY" || a.PeerPublicKey != "PEERPUBKEY" {
		t.Errorf("account = %+v", a)
	}
}

func TestRotatedAccount(t *testing.T) {
	body := []byte(`{"id":"dev123","config":{"peers":[{"public_key":"NEWPEER"}]}}`)
	existing := account{PrivateKey: "OLDPRIV", PeerPublicKey: "OLDPEER", ID: "dev123", Token: "tok456"}
	a, err := rotatedAccount(body, "NEWPRIV", existing)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "dev123" || a.Token != "tok456" {
		t.Errorf("id/token = %q/%q, want dev123/tok456", a.ID, a.Token)
	}
	if a.PrivateKey != "NEWPRIV" || a.PeerPublicKey != "NEWPEER" {
		t.Errorf("account = %+v", a)
	}
}

func TestExpandPools(t *testing.T) {
	if n := len(expandPools(0)); n != len(pools)*256 {
		t.Errorf("full scan = %d IPs, want %d", n, len(pools)*256)
	}
	if n := len(expandPools(8)); n != len(pools)*8 {
		t.Errorf("partial scan = %d IPs, want %d", n, len(pools)*8)
	}
	seen := map[netip.Addr]bool{}
	for _, ip := range expandPools(8) {
		if seen[ip] {
			t.Errorf("duplicate host %v in a subnet", ip)
		}
		seen[ip] = true
	}
}

func TestParseTargets(t *testing.T) {
	ok := map[string][]string{
		"188.114.98.5":                    {"188.114.98.5/32"},
		" 188.114.98.0/28 , 8.6.112.0/24": {"188.114.98.0/28", "8.6.112.0/24"},
		"2606:4700:d0::1":                 {"2606:4700:d0::1/128"},
	}
	for spec, want := range ok {
		got, err := parseTargets(spec)
		if err != nil {
			t.Errorf("parseTargets(%q) failed: %v", spec, err)
			continue
		}
		var have []string
		for _, p := range got {
			have = append(have, p.String())
		}
		if strings.Join(have, ",") != strings.Join(want, ",") {
			t.Errorf("parseTargets(%q) = %v, want %v", spec, have, want)
		}
	}

	for _, spec := range []string{"", "nonsense", "8.6.112.0/8", "188.114.98.5,2606:4700:d0::1"} {
		if _, err := parseTargets(spec); err == nil {
			t.Errorf("parseTargets(%q) should have failed", spec)
		}
	}
}

func TestExpandTargets(t *testing.T) {
	defer func(saved []netip.Prefix) { pools = saved }(pools)

	pools, _ = parseTargets("188.114.98.5,162.159.192.0/28")
	ips := expandPools(10)
	const want = 1 + 10 // the /28 is sampled down to -n
	if len(ips) != want {
		t.Fatalf("expandPools = %d IPs, want %d", len(ips), want)
	}
	if ips[0].String() != "188.114.98.5" {
		t.Errorf("single-address target expanded to %v", ips[0])
	}
	for _, ip := range ips[1:] {
		if !pools[1].Contains(ip) {
			t.Errorf("%v not in %s", ip, pools[1])
		}
	}

	pools, _ = parseTargets("2606:4700:d0::1")
	if ips := expandPools(10); len(ips) != 1 || ips[0].String() != "2606:4700:d0::1" {
		t.Errorf("single-address IPv6 target expanded to %v", ips)
	}
}

func TestFilterByColo(t *testing.T) {
	ph := phaseResult{run: protoRun{kindAWG, "awg"}, results: []endpointResult{
		{endpoint: "1.1.1.1:2408", exit: metaResult{colo: "HEL"}},
		{endpoint: "2.2.2.2:2408", exit: metaResult{colo: "FRA"}},
		{endpoint: "3.3.3.3:2408"},
	}}

	got := filterByColo(ph, []string{"HEL"})
	if len(got.results) != 1 {
		t.Fatalf("filterByColo kept %v results, want 1", got.results)
	}
	if ep := got.results[0].endpoint; ep != "1.1.1.1:2408" {
		t.Errorf("filterByColo kept %s, want the HEL endpoint", ep)
	}
	if got.run.name != "awg" {
		t.Error("filterByColo dropped the proto run")
	}
}

func TestFilterByCountry(t *testing.T) {
	ph := phaseResult{run: protoRun{kindAWG, "awg"}, results: []endpointResult{
		{endpoint: "1.1.1.1:2408", exit: metaResult{colo: "HEL", coloISO: "FI"}},
		{endpoint: "2.2.2.2:2408", exit: metaResult{colo: "FRA", coloISO: "DE"}},
		{endpoint: "3.3.3.3:2408"},
	}}

	got := filterByCountry(ph, []string{"DE"})
	if len(got.results) != 1 {
		t.Fatalf("filterByCountry kept %v results, want 1", got.results)
	}
	if ep := got.results[0].endpoint; ep != "2.2.2.2:2408" {
		t.Errorf("filterByCountry kept %s, want the FRA endpoint", ep)
	}
	if got := filterByCountry(ph, []string{"US"}); len(got.results) != 0 {
		t.Errorf("filterByCountry(US) kept %v, want nothing", got.results)
	}
}

func TestFlagEmoji(t *testing.T) {
	showEmoji = true
	t.Cleanup(func() { showEmoji = false })
	cases := map[string]string{
		"RU":  "\U0001F1F7\U0001F1FA",
		"de":  "\U0001F1E9\U0001F1EA",
		"?":   "",
		"":    "",
		"USA": "",
		"R1":  "",
	}
	for in, want := range cases {
		if got := flagEmoji(in); got != want {
			t.Errorf("flagEmoji(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMeta(t *testing.T) {
	body := `{"clientIp":"1.2.3.4","country":"RU","city":"Moscow",
		"colo":{"iata":"ARN","cca2":"SE","city":"Stockholm"}}`
	got := parseMeta(body)
	if got.loc != "RU" || got.colo != "ARN" || got.coloCity != "Stockholm" || got.coloISO != "SE" {
		t.Errorf("parseMeta = %+v", got)
	}
	if got := parseMeta("not json"); got != (metaResult{}) {
		t.Errorf("parseMeta(garbage) = %+v, want zero", got)
	}
}

func TestHandshakeDone(t *testing.T) {
	cases := map[string]bool{
		"last_handshake_time_sec=1700000000\nlast_handshake_time_nsec=0\n": true,
		"last_handshake_time_sec=0\n":                                      false,
		"public_key=abc\n":                                                 false,
		"":                                                                 false,
	}
	for conf, want := range cases {
		if got := handshakeDone(conf); got != want {
			t.Errorf("handshakeDone(%q) = %v, want %v", conf, got, want)
		}
	}
}

func TestExpandV6(t *testing.T) {
	p := netip.MustParsePrefix("2606:4700:d0::/48")
	const want = 10
	ips := expandV6(p, want)
	if len(ips) != want {
		t.Fatalf("expandV6 count = %d, want %d", len(ips), want)
	}
	for _, ip := range ips {
		if !ip.Is6() {
			t.Errorf("%s is not IPv6", ip)
		}
		if !p.Contains(ip) {
			t.Errorf("%s not in %s", ip, p)
		}
	}
}

func TestRegI1Candidates(t *testing.T) {
	const cur = "<b 0xdead>"
	if got := regI1Candidates(protoRun{kindWG, protoWG}, options{}, cur, ""); len(got) != 1 || got[0].chain != cur {
		t.Errorf("wg candidates = %v, want the current I1 only", got)
	}
	if got := regI1Candidates(protoRun{kindAWG, protoAWG}, options{i1Explicit: true}, cur, "x"); len(got) != 1 || got[0].chain != cur {
		t.Errorf("explicit I1 candidates = %v, want the current I1 only", got)
	}

	got := regI1Candidates(protoRun{kindAWG, protoAWG}, options{}, cur, "")
	if want := 1 + len(i1Profiles()); len(got) != want {
		t.Fatalf("awg candidates = %d, want %d", len(got), want)
	}
	if got[0].chain != i1Default || got[0].label != "" {
		t.Errorf("first candidate = %+v, want the default probe", got[0])
	}
	for _, c := range got[1:] {
		if c.chain == "" || c.label == "" {
			t.Errorf("generated candidate %+v is incomplete", c)
		}
	}
}

func TestJunkCandidateMeets(t *testing.T) {
	cases := []struct {
		working, total, pct int
		want                bool
	}{
		{40, 42, defaultJunkThreshold, true},
		{39, 42, defaultJunkThreshold, false},
		{42, 42, 100, true},
		{41, 42, 100, false},
		{0, 0, defaultJunkThreshold, false},
	}
	for _, c := range cases {
		got := junkCandidate{working: c.working, total: c.total}.meets(c.pct)
		if got != c.want {
			t.Errorf("%d/%d at %d%% = %v, want %v", c.working, c.total, c.pct, got, c.want)
		}
	}
}

func TestNoEndpointMsg(t *testing.T) {
	cases := []struct {
		name string
		opts options
		want string
	}{
		{"awg without gen-i1", options{proto: protoAWG}, "no working endpoints found - try -gen-i1 quic"},
		{"wg without gen-i1", options{proto: protoWG}, "no working endpoints found - try -p awg -gen-i1 quic"},
		{"gen-i1 already set", options{proto: protoAWG, genI1: "quic"}, "no working endpoints found"},
		{"filters win over the hint", options{proto: protoAWG, colos: []string{"HEL"}}, "no endpoint landed on node HEL"},
	}
	for _, c := range cases {
		if got := noEndpointMsg(c.opts); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestMbits(t *testing.T) {
	cases := []struct {
		bytes int64
		d     time.Duration
		want  float64
	}{
		{1_250_000, time.Second, 10},
		{5 << 20, 4 * time.Second, 10.485760},
		{1000, 0, 0},
		{0, time.Second, 0},
	}
	for _, c := range cases {
		if got := mbits(c.bytes, c.d); math.Abs(got-c.want) > 0.0001 {
			t.Errorf("mbits(%d, %v) = %v, want %v", c.bytes, c.d, got, c.want)
		}
	}
}

func TestReportSpeedColumn(t *testing.T) {
	r := endpointResult{endpoint: "1.2.3.4:2408", speed: 42.5, ok: true, durable: true}
	if !anySpeed([]endpointResult{{}, r}) {
		t.Error("anySpeed missed a measured endpoint")
	}
	if anySpeed([]endpointResult{{}, {endpoint: "5.6.7.8:2408"}}) {
		t.Error("anySpeed reported an unmeasured set as measured")
	}
	if got := speedStr(0); got != "-" {
		t.Errorf("speedStr(0) = %q, want %q", got, "-")
	}

	var withSpeed bytes.Buffer
	writeRows(&withSpeed, []endpointResult{r}, false, true)
	for _, want := range []string{"SPEED", "42.5 Mbps"} {
		if !strings.Contains(withSpeed.String(), want) {
			t.Errorf("-speed report is missing %q:\n%s", want, withSpeed.String())
		}
	}

	var noSpeed bytes.Buffer
	writeRows(&noSpeed, []endpointResult{r}, false, false)
	if strings.Contains(noSpeed.String(), "SPEED") || strings.Contains(noSpeed.String(), "42.5") {
		t.Errorf("report without -speed leaks the column:\n%s", noSpeed.String())
	}
}

func TestSpeedTargets(t *testing.T) {
	defer func(saved []netip.Prefix) { pools = saved }(pools)
	pools, _ = parseTargets("8.47.69.0/24,188.114.96.0/24")

	ok := func(addr string, ms int, colo string) endpointResult {
		return endpointResult{
			ip:       netip.MustParseAddr(addr),
			endpoint: addr + ":2408",
			epPing:   time.Duration(ms) * time.Millisecond,
			exit:     metaResult{colo: colo},
			ok:       true,
			durable:  true,
		}
	}
	results := []endpointResult{
		ok("8.47.69.10", 3, "DME"),    // subnet pick, and the DME node pick - counted once
		ok("8.47.69.11", 9, "FRA"),    // not its subnet's pick, but it is the FRA node pick
		ok("188.114.96.5", 40, "FRA"), // subnet pick only
		ok("188.114.96.6", 41, "FRA"), // shown by neither table
		{endpoint: "8.47.69.12:2408", ip: netip.MustParseAddr("8.47.69.12")}, // not working
	}

	var got []string
	for _, r := range speedTargets(results) {
		got = append(got, r.endpoint)
	}
	want := []string{"8.47.69.10:2408", "8.47.69.11:2408", "188.114.96.5:2408"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("speedTargets = %v, want %v", got, want)
	}
}

func TestFastestNote(t *testing.T) {
	got := fastestNote(map[string]float64{"a:2408": 90.4, "b:2408": 310.2, "c:2408": 0})
	if want := "fastest 310.2 Mbps at b:2408"; got != want {
		t.Errorf("fastestNote = %q, want %q", got, want)
	}
	if got := fastestNote(map[string]float64{"a:2408": 0}); got != "nothing measured" {
		t.Errorf("fastestNote with no measurement = %q", got)
	}
}

func TestShowsSpeed(t *testing.T) {
	cases := []struct {
		name string
		opts options
		want bool
	}{
		{"tables", options{}, true},
		{"best alone", options{best: true}, false},
		{"conf file", options{conf: "wg.conf"}, true},
		{"conf stdout", options{conf: confStdout}, false},
		{"best with report file", options{best: true, output: "r.txt"}, true},
		{"best with report file but no-report", options{best: true, output: "r.txt", noReport: true}, false},
	}
	for _, c := range cases {
		if got := showsSpeed(c.opts); got != c.want {
			t.Errorf("%s: showsSpeed = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestReportPingColumns(t *testing.T) {
	r := endpointResult{
		endpoint: "1.2.3.4:2408",
		epPing:   30 * time.Millisecond,
		tunPing:  90 * time.Millisecond,
		loss:     0.1,
		measured: true,
		ok:       true,
		durable:  true,
	}

	var withPing bytes.Buffer
	writeRows(&withPing, []endpointResult{r}, true, false)
	for _, want := range []string{"ENDPOINT PING", "TUN PING", "LOSS", "30ms", "90ms", "10%"} {
		if !strings.Contains(withPing.String(), want) {
			t.Errorf("-tun-ping report is missing %q:\n%s", want, withPing.String())
		}
	}

	var noPing bytes.Buffer
	writeRows(&noPing, []endpointResult{r}, false, false)
	for _, unwanted := range []string{"TUN PING", "LOSS", "90ms", "10%"} {
		if strings.Contains(noPing.String(), unwanted) {
			t.Errorf("report without -tun-ping leaks %q:\n%s", unwanted, noPing.String())
		}
	}
	if !strings.Contains(noPing.String(), "30ms") {
		t.Errorf("report without -tun-ping lost the endpoint ping:\n%s", noPing.String())
	}
}

func TestTornDownReportBlock(t *testing.T) {
	torn := endpointResult{endpoint: "1.2.3.4:2408", epPing: 30 * time.Millisecond, measured: true, ok: true}
	var buf bytes.Buffer
	writeFullReport(&buf, []endpointResult{torn}, true)
	out := buf.String()
	if !strings.Contains(out, "1 torn down") || !strings.Contains(out, "1.2.3.4:2408") {
		t.Errorf("torn-down endpoint is not reported as such:\n%s", out)
	}
	if strings.Contains(out, "# Best endpoint per node") {
		t.Errorf("a torn-down endpoint must not be picked as best:\n%s", out)
	}
}
