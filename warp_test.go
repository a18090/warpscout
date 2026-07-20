package main

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

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
	writeConsole(&plain, ph, palette{enabled: false})
	if strings.Contains(plain.String(), "\033") {
		t.Error("plain (non-TTY) console output must not contain ANSI escapes")
	}
	if !strings.Contains(plain.String(), "8.47.69.86:2408") {
		t.Error("console output missing the working endpoint")
	}

	var colored bytes.Buffer
	writeConsole(&colored, ph, palette{enabled: true})
	if !strings.Contains(colored.String(), "\033") {
		t.Error("colored console output should contain ANSI escapes")
	}
}

func TestDurableVerdict(t *testing.T) {
	cases := []struct {
		name    string
		results []bool
		want    bool
	}{
		{"all ok", []bool{true, true, true, true}, true},
		{"any single loss is flaky", []bool{true, false, true, true}, false},
		{"tail drop (TSPU)", []bool{true, true, true, false, false}, false},
		{"first loss is flaky", []bool{false, true, true}, false},
		{"empty is durable", nil, true},
	}
	for _, c := range cases {
		if got := durableVerdict(c.results); got != c.want {
			t.Errorf("%s: durableVerdict(%v) = %v, want %v", c.name, c.results, got, c.want)
		}
	}
}

func TestBestByPing(t *testing.T) {
	mk := func(ep string, ms int) endpointResult {
		return endpointResult{endpoint: ep, latency: time.Duration(ms) * time.Millisecond}
	}

	// Lowest known ping wins; the 0 (unknown) must not be treated as fastest.
	picks := []endpointResult{mk("a", 0), mk("b", 90), mk("c", 40)}
	if got := bestByPing(picks); got.endpoint != "c" {
		t.Errorf("bestByPing = %q, want c (40ms)", got.endpoint)
	}

	// All unknown: fall back to the first.
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
	for _, want := range []string{"jc=6", "jmin=10", "jmax=50", "i1="} {
		if !strings.Contains(awg, want) {
			t.Errorf("AmneziaWG config missing %q", want)
		}
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
		"de":  "\U0001F1E9\U0001F1EA", // case-insensitive
		"?":   "",                     // missing field
		"":    "",
		"USA": "", // not two letters
		"R1":  "", // digit
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
