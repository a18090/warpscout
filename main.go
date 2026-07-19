package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	parallel := flag.Int("j", 50, "phase-1 (discovery) parallel workers")
	// ponytail: single shared WARP key => WireGuard keeps one session per key,
	// so parallel tunnels clobber each other server-side. Keep phase-2 low until
	// per-run key registration (wgcf) lands, then raise the default.
	tunnelParallel := flag.Int("jt", 4, "phase-2 (tunnel) parallel workers")
	timeoutSec := flag.Int("t", 5, "per-request timeout in seconds")
	proto := flag.String("proto", "wg", "protocol: wg (WireGuard) or awg (AmneziaWG)")
	output := flag.String("o", "", "also write the report to this file")
	flag.Parse()

	awg, err := parseProto(*proto)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	timeout := time.Duration(*timeoutSec) * time.Second
	ctx := context.Background()

	ips := expandPools()
	fmt.Fprintf(os.Stderr, "Phase 1: discovering edge colo for %d IPs...\n", len(ips))

	// Phase 1: keep only IPs whose edge answers, remembering its region/colo.
	type edge struct {
		ip    netip.Addr
		trace traceResult
	}
	var alive []edge
	var mu sync.Mutex
	runPool(*parallel, len(ips), func(i int) {
		if t, ok := discoverColo(ctx, ips[i], timeout); ok {
			mu.Lock()
			alive = append(alive, edge{ips[i], t})
			mu.Unlock()
		}
	})
	fmt.Fprintf(os.Stderr, "Phase 1: %d responsive IPs\n", len(alive))

	// Phase 2: bring up a tunnel to each responsive IP and read the exit colo.
	fmt.Fprintf(os.Stderr, "Phase 2: verifying tunnels (proto=%s)...\n", *proto)
	results := make([]endpointResult, len(alive))
	var done int64
	runPool(*tunnelParallel, len(alive), func(i int) {
		e := alive[i]
		r := endpointResult{ip: e.ip, edge: e.trace}
		if t, endpoint, ok := verifyEndpoint(ctx, e.ip, awg, timeout); ok {
			r.exit, r.endpoint, r.ok = t, endpoint, true
		}
		results[i] = r
		n := atomic.AddInt64(&done, 1)
		fmt.Fprintf(os.Stderr, "\rPhase 2: %d/%d", n, len(alive))
	})
	fmt.Fprintln(os.Stderr)

	writeReport(os.Stdout, results)
	if *output != "" {
		if err := writeToFile(*output, results); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", *output, err)
		}
	}
}

func parseProto(p string) (awg bool, err error) {
	switch p {
	case "wg":
		return false, nil
	case "awg":
		return true, nil
	default:
		return false, fmt.Errorf("invalid -proto %q: use wg or awg", p)
	}
}

// runPool runs fn(0..n-1) with at most workers running concurrently.
func runPool(workers, n int, fn func(i int)) {
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

func writeToFile(path string, results []endpointResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var w io.Writer = f
	writeReport(w, results)
	return nil
}
