package main

import (
	"strings"
	"testing"
)

func TestBuildUAPI(t *testing.T) {
	wg, err := buildUAPI("1.2.3.4:2408", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(wg, "jc=") || strings.Contains(wg, "i1=") {
		t.Error("plain WireGuard config must not contain junk params")
	}
	for _, want := range []string{"private_key=", "public_key=", "endpoint=1.2.3.4:2408", "allowed_ip=0.0.0.0/0"} {
		if !strings.Contains(wg, want) {
			t.Errorf("missing %q in config", want)
		}
	}

	awg, err := buildUAPI("1.2.3.4:2408", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"jc=6", "jmin=10", "jmax=50", "i1="} {
		if !strings.Contains(awg, want) {
			t.Errorf("AmneziaWG config missing %q", want)
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
