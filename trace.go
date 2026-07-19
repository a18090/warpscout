package main

import (
	"bufio"
	"strings"
)

// traceResult holds the fields we care about from /cdn-cgi/trace.
type traceResult struct {
	colo string
	loc  string
	warp string
}

// parseTrace reads the key=value body of /cdn-cgi/trace (same keys as the bash
// script: colo, loc, warp).
func parseTrace(body string) traceResult {
	var t traceResult
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "colo":
			t.colo = val
		case "loc":
			t.loc = val
		case "warp":
			t.warp = val
		}
	}
	return t
}
