package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"sync"
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
	output := flag.String("o", "", "file for the full per-endpoint report (default warpscout-report-<timestamp>.txt)")
	proxy := flag.String("proxy", "", "http(s)/socks5 proxy URL for registration")
	register := flag.Bool("register", false, "only register a fresh WARP account (save it and exit, no scanning)")
	accountPath := flag.String("account", defaultAccount, "path to cached WARP account file")
	perSubnet := flag.Int("n", 10, "addresses to sample per /24 subnet")
	full := flag.Bool("full", false, "scan all 256 addresses per /24 (overrides -n)")
	flag.Parse()

	errPal = palette{enabled: colorEnabled(os.Stderr)}
	outPal := palette{enabled: colorEnabled(os.Stdout)}

	awg, err := parseProto(*proto)
	if err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(err.Error()))
		os.Exit(1)
	}
	timeout := time.Duration(*timeoutSec) * time.Second
	ctx := context.Background()

	// A cached account skips registration (and its API/tunnel dependency) entirely.
	haveConfig := false
	if !*register {
		if a, err := loadAccount(*accountPath); err == nil {
			applyAccount(a)
			haveConfig = true
			fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("Using cached WARP account from %s", *accountPath)))
		}
	}

	sample := *perSubnet
	if *full {
		sample = 0 // 0 => expandPools scans the whole /24
	}
	ips := expandPools(sample)

	// Registration first (if no cached account), so a user on a censored network
	// hits the "pass -proxy" hint immediately instead of after a full phase 1.
	// The tunnel fallback only needs a handful of live endpoints, discovered on
	// demand rather than from the full scan.
	if !haveConfig {
		a, err := obtainAccount(ctx, awg, *proxy, ips, *parallel, timeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("registration failed: %v", err)))
			if *proxy == "" {
				fmt.Fprintln(os.Stderr, errPal.fail("could not register directly or through a WARP tunnel; retry with -proxy <http(s)/socks5 URL>"))
			}
			os.Exit(1)
		}
		if err := saveAccount(*accountPath, a); err != nil {
			fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("warning: could not save account to %s: %v", *accountPath, err)))
		}
		applyAccount(a)
		fmt.Fprintln(os.Stderr, errPal.ok(fmt.Sprintf("Registered fresh WARP account -> %s", *accountPath)))
	}

	// -register is a register-only mode: save the account and stop, no scanning.
	if *register {
		return
	}

	// Phase 1: keep only IPs whose edge answers, remembering its region/colo.
	type edge struct {
		ip    netip.Addr
		trace traceResult
	}
	var alive []edge
	var mu sync.Mutex
	p1 := newProgress("Phase 1: discovering edge colo", len(ips), errPal)
	runPool(*parallel, len(ips), func(i int) {
		defer p1.inc()
		if t, ok := discoverColo(ctx, ips[i], timeout); ok {
			mu.Lock()
			alive = append(alive, edge{ips[i], t})
			mu.Unlock()
		}
	})
	p1.stop(errPal.ok(fmt.Sprintf("%d responsive IPs", len(alive))))

	// Phase 2: bring up a small pool of persistent tunnels and reuse each across
	// many IPs, reading the exit colo. Creating one tunnel per IP leaks gvisor
	// stacks and OOMs (see tunnel.go), so live stacks are bounded to the pool.
	results := make([]endpointResult, len(alive))
	p2 := newProgress(fmt.Sprintf("Phase 2: verifying tunnels (proto=%s)", *proto), len(alive), errPal)
	work := func(tn *tunnel, i int) {
		defer p2.inc()
		e := alive[i]
		r := endpointResult{ip: e.ip, edge: e.trace}
		if t, endpoint, ok := tn.trace(ctx, e.ip, timeout); ok {
			r.exit, r.endpoint, r.ok = t, endpoint, true
		}
		results[i] = r
	}
	if err := runTunnelPool(*tunnelParallel, awg, len(alive), work); err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(err.Error()))
		os.Exit(1)
	}
	p2.stop(errPal.ok("done"))

	writeConsole(os.Stdout, results, outPal)
	reportPath := *output
	if reportPath == "" {
		reportPath = fmt.Sprintf("warpscout-report-%s.txt", time.Now().Format("2006-01-02-150405"))
	}
	if err := writeToFile(reportPath, results); err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("failed to write %s: %v", reportPath, err)))
	} else {
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("\nFull report written to %s", reportPath)))
	}
}

// tunnelCandidates is how many live endpoints the fallback discovers before it
// stops scanning and starts bringing up a registration tunnel.
const tunnelCandidates = 20

// obtainAccount registers a fresh WARP config, choosing how to reach the API:
// via proxy if given, directly if reachable, otherwise through a WARP tunnel on
// a handful of live endpoints discovered on demand.
func obtainAccount(ctx context.Context, awg bool, proxy string, ips []netip.Addr, workers int, timeout time.Duration) (account, error) {
	if proxy != "" {
		c, err := proxyClient(proxy)
		if err != nil {
			return account{}, err
		}
		return registerWARP(ctx, c)
	}

	fmt.Fprintln(os.Stderr, errPal.dim("Checking Cloudflare API availability..."))
	direct := &http.Client{Timeout: registerTimeout}
	if apiReachable(direct) {
		return registerWARP(ctx, direct)
	}

	fmt.Fprintln(os.Stderr, errPal.dim("API unreachable directly; registering through a WARP tunnel (pass -proxy to use a proxy instead)"))
	fmt.Fprintln(os.Stderr, errPal.dim("  discovering a live endpoint for the tunnel..."))
	candidates := discoverAlive(ctx, ips, workers, timeout, tunnelCandidates)
	if len(candidates) == 0 {
		return account{}, fmt.Errorf("no live endpoints for tunnel fallback")
	}

	// Try the requested protocol first, then the other: plain WireGuard often
	// completes a handshake but passes no data on censored networks, where
	// AmneziaWG's junk gets through (see DESC.md). Registration itself is the
	// data-path test, so fall through to the other proto if it fails.
	var lastErr error
	for _, p := range []bool{awg, !awg} {
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("  trying %s tunnel...", protoName(p))))
		a, err := registerViaTunnel(ctx, p, candidates, timeout)
		if err == nil {
			return a, nil
		}
		fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("  %s tunnel failed: %v", protoName(p), err)))
		lastErr = err
	}
	return account{}, lastErr
}

// discoverAlive scans ips and returns up to want edge-responsive ones, stopping
// early once enough are found (cheaper than a full phase 1 just to bootstrap the
// registration tunnel).
func discoverAlive(ctx context.Context, ips []netip.Addr, workers int, timeout time.Duration, want int) []netip.Addr {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	var found []netip.Addr
	runPool(workers, len(ips), func(i int) {
		if ctx.Err() != nil {
			return
		}
		if _, ok := discoverColo(ctx, ips[i], timeout); !ok {
			return
		}
		mu.Lock()
		if len(found) < want {
			found = append(found, ips[i])
			if len(found) >= want {
				cancel()
			}
		}
		mu.Unlock()
	})
	return found
}

// registerViaTunnel brings up a tunnel on hardcoded keys, points it at the first
// live endpoint that handshakes, and registers through it.
func registerViaTunnel(ctx context.Context, awg bool, ips []netip.Addr, timeout time.Duration) (account, error) {
	tn, err := newTunnel(awg)
	if err != nil {
		return account{}, err
	}
	defer tn.Close()

	connectCtx, cancel := context.WithTimeout(ctx, tunnelDialTimout)
	defer cancel()
	connected := false
	for _, ip := range ips {
		if tn.connect(connectCtx, ip, timeout) {
			connected = true
			break
		}
	}
	if !connected {
		return account{}, fmt.Errorf("could not tunnel to any live endpoint")
	}

	client, err := tunnelClient(tn.tnet)
	if err != nil {
		return account{}, err
	}
	return registerWARP(ctx, client)
}

func protoName(awg bool) string {
	if awg {
		return "awg"
	}
	return "wg"
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
	writeFullReport(f, results)
	return nil
}
