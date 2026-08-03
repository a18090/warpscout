package main

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/crypto/curve25519"
)

func TestWriteConsolePalette(t *testing.T) {
	ph := phaseResult{
		run: protoRun{false, "wg"},
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
			latency:  time.Duration(ms) * time.Millisecond,
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
		return endpointResult{endpoint: ep, rtt: time.Duration(ms) * time.Millisecond, loss: loss, measured: measured}
	}
	cases := []struct {
		name string
		a, b endpointResult
		want bool // a ranks before b
	}{
		{"lower loss beats lower ping", mk("a", 200, 0, true), mk("b", 20, 0.2, true), true},
		{"equal loss falls back to ping", mk("a", 20, 0.1, true), mk("b", 90, 0.1, true), true},
		{"unmeasured ranks by host ping", endpointResult{endpoint: "a", latency: 20 * time.Millisecond}, endpointResult{endpoint: "b", latency: 90 * time.Millisecond}, true},
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
		{"sporadic single drop is loss, not flaky", []bool{true, false, true, true, true}, false},
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
		return endpointResult{endpoint: ep, latency: time.Duration(ms) * time.Millisecond}
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
	awg := renderConf(options{ipv6: true}, "188.114.98.5:2408", true)
	for _, want := range []string{
		"[Interface]",
		"Address = " + warpAddressV6 + "/128",
		"AllowedIPs = ::/0",
		"PrivateKey = " + warpPrivateKey,
		"Jc = 6", "Jmin = 10", "Jmax = 50",
		"I1 = " + i1Default,
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

	wg := renderConf(options{tableOff: true, mtu: 1420}, "188.114.98.5:2408", false)
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

func TestRenderConfNoInitPacket(t *testing.T) {
	orig := awgI1
	defer func() { awgI1 = orig }()

	awgI1 = ""
	if conf := renderConf(options{}, "188.114.98.5:2408", true); strings.Contains(conf, "I1 = ") {
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
	for _, p := range []string{protoWG, protoAWG} {
		run, err := parseProto(p)
		if err != nil || run.name != p || run.awg != (p == protoAWG) {
			t.Errorf("parseProto(%q) = %+v, %v", p, run, err)
		}
	}
	if _, err := parseProto("both"); err == nil {
		t.Error("parseProto(\"both\") accepted, want an error")
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
	ph := phaseResult{run: protoRun{true, "awg"}, results: []endpointResult{
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
	ph := phaseResult{run: protoRun{true, "awg"}, results: []endpointResult{
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
	if got := regI1Candidates(false, options{}, cur, ""); len(got) != 1 || got[0].chain != cur {
		t.Errorf("wg candidates = %v, want the current I1 only", got)
	}
	if got := regI1Candidates(true, options{i1Explicit: true}, cur, "x"); len(got) != 1 || got[0].chain != cur {
		t.Errorf("explicit I1 candidates = %v, want the current I1 only", got)
	}

	got := regI1Candidates(true, options{}, cur, "")
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
