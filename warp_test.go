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
			exit:     traceResult{loc: "RU", colo: "DME"},
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
		{"tail teardown (TSPU)", []bool{true, true, true, false, false, false}, true},
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

func TestScoreJunk(t *testing.T) {
	phases := []phaseResult{{results: []endpointResult{
		{ok: true, durable: true},
		{ok: true, durable: false},
		{},
	}}}
	if c := scoreJunk(phases); c.working != 1 || c.total != 3 {
		t.Errorf("scoreJunk() = %d/%d, want 1/3", c.working, c.total)
	}
	if c := scoreJunk(nil); c.total != 0 {
		t.Errorf("scoreJunk(nil) total = %d, want 0", c.total)
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

func TestFlagEmoji(t *testing.T) {
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

func TestParseTrace(t *testing.T) {
	body := "fl=123\nip=1.2.3.4\ncolo=FRA\nloc=DE\nwarp=on\n"
	got := parseTrace(body)
	if got.colo != "FRA" || got.loc != "DE" || got.warp != "on" {
		t.Errorf("parseTrace = %+v", got)
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
