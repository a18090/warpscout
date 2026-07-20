package main

import (
	"bufio"
	"strings"
)

type traceResult struct {
	colo string
	loc  string
	warp string
}

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
