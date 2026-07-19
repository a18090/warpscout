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
	// Real WARP handshakes complete in ~100-250ms; the timeout only bounds how
	// long a dead endpoint (answers HTTPS in phase 1 but no tunnel) stalls a
	// worker. 2s keeps a wide margin over real latency while cutting that stall.
	timeoutSec := flag.Int("t", 2, "per-request timeout in seconds")
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

	// Phase 2: bring up a small pool of persistent tunnels and reuse each across
	// many IPs, reading the exit colo. Creating one tunnel per IP leaks gvisor
	// stacks and OOMs (see tunnel.go), so live stacks are bounded to the pool.
	fmt.Fprintf(os.Stderr, "Phase 2: verifying tunnels (proto=%s)...\n", *proto)
	results := make([]endpointResult, len(alive))
	var done int64
	work := func(tn *tunnel, i int) {
		e := alive[i]
		r := endpointResult{ip: e.ip, edge: e.trace}
		if t, endpoint, ok := tn.trace(ctx, e.ip, timeout); ok {
			r.exit, r.endpoint, r.ok = t, endpoint, true
		}
		results[i] = r
		n := atomic.AddInt64(&done, 1)
		fmt.Fprintf(os.Stderr, "\rPhase 2: %d/%d", n, len(alive))
	}
	if err := runTunnelPool(*tunnelParallel, awg, len(alive), work); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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

// runTunnelPool creates up to workers persistent tunnels and dispatches indices
// 0..n-1 across them, each worker reusing its tunnel for every job it pulls.
func runTunnelPool(workers int, awg bool, n int, fn func(tn *tunnel, i int)) error {
	if workers < 1 {
		workers = 1
	}

	var tunnels []*tunnel
	for len(tunnels) < workers {
		tn, err := newTunnel(awg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tunnel setup failed: %v\n", err)
			break
		}
		tunnels = append(tunnels, tn)
	}
	if len(tunnels) == 0 {
		return fmt.Errorf("no tunnels could be created")
	}
	defer func() {
		for _, tn := range tunnels {
			tn.Close()
		}
	}()

	jobs := make(chan int)
	var wg sync.WaitGroup
	for _, tn := range tunnels {
		wg.Add(1)
		go func(tn *tunnel) {
			defer wg.Done()
			for i := range jobs {
				fn(tn, i)
			}
		}(tn)
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return nil
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
