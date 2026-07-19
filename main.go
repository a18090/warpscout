package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"
)

func main() {
	opts := parseFlags()

	errPal = palette{enabled: colorEnabled(os.Stderr)}
	outPal := palette{enabled: colorEnabled(os.Stdout)}

	runs, err := parseProto(opts.proto)
	if err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(err.Error()))
		os.Exit(1)
	}
	timeout := time.Duration(opts.timeoutSec) * time.Second
	ctx := context.Background()

	// A cached account skips registration (and its API/tunnel dependency) entirely.
	haveConfig := false
	if !opts.register {
		if a, err := loadAccount(opts.accountPath); err == nil {
			applyAccount(a)
			haveConfig = true
			fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("Using cached WARP account from %s", opts.accountPath)))
			fmt.Fprintln(os.Stderr)
		}
	}

	sample := opts.perSubnet
	if opts.full {
		sample = 0 // 0 => expandPools scans the whole /24
	}
	ips := expandPools(sample)

	// Registration first (if no cached account), so a user on a censored network
	// hits the "pass -proxy" hint immediately instead of after a full phase 1.
	// The tunnel fallback only needs a handful of live endpoints, discovered on
	// demand rather than from the full scan.
	if !haveConfig {
		a, err := obtainAccount(ctx, runs[0].awg, opts.proxy, ips, fallbackDiscoveryWorkers, timeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("registration failed: %v", err)))
			if opts.proxy == "" {
				fmt.Fprintln(os.Stderr, errPal.fail("could not register directly or through a WARP tunnel; retry with -proxy <http(s)/socks5 URL>"))
			}
			os.Exit(1)
		}
		if err := saveAccount(opts.accountPath, a); err != nil {
			fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("warning: could not save account to %s: %v", opts.accountPath, err)))
		}
		applyAccount(a)
		fmt.Fprintln(os.Stderr, errPal.ok(fmt.Sprintf("Registered fresh WARP account -> %s", opts.accountPath)))
	}

	// -register is a register-only mode: save the account and stop, no scanning.
	if opts.register {
		return
	}

	// Phase 1: find which WARP ports get through this network. Reachability is a
	// network property (DPI / port filtering), not per-IP, so this probes a sample
	// rather than every IP; phase 2 then scans all IPs on only the reachable ports.
	// Probe with awg when any run needs it: AmneziaWG's junk evades DPI that plain
	// wg trips, so its reachable ports are a superset - narrowing on wg could drop
	// a port the awg run needs.
	const phase1 = "Phase 1: probing reachable WARP ports"
	stepStart(phase1, errPal)
	open, err := reachablePorts(ctx, anyAWG(runs), ips, timeout, portProbeSample)
	if err != nil {
		stepFail(fmt.Sprintf("phase 1 failed: %v", err), errPal)
		os.Exit(1)
	}
	if len(open) == 0 {
		stepFail("no WARP port is reachable on this network", errPal)
		os.Exit(1)
	}
	warpPorts = open // narrow phase 2 to the reachable ports
	stepDone(phase1, fmt.Sprintf("reachable ports %v", open), errPal)

	// Phase 2: bring up a small pool of persistent tunnels and reuse each across
	// many IPs, reading the exit colo. Creating one tunnel per IP leaks gvisor
	// stacks and OOMs (see tunnel.go), so live stacks are bounded to the pool.
	// With -proto both this runs once per protocol (wg first) over the same IPs.
	var phases []phaseResult
	for _, run := range runs {
		results := make([]endpointResult, len(ips))
		// The durability ping check only makes sense for wg: awg's junk params
		// already fix the death-on-data-volume, so a lost ping through an awg
		// tunnel is measurement noise, not a real drop. Trust the awg trace.
		durability := opts.durability
		if run.awg {
			durability = 0
		}
		p2 := newProgress(fmt.Sprintf("Phase 2: verifying tunnels (proto=%s)", run.name), len(ips), errPal)
		work := func(tn *tunnel, i int) {
			defer p2.inc()
			ip := ips[i]
			r := endpointResult{ip: ip}
			if t, endpoint, ok, durable := tn.trace(ctx, ip, timeout, durability); ok {
				r.exit, r.endpoint, r.ok, r.durable = t, endpoint, true, durable
			}
			results[i] = r
		}
		if err := runTunnelPool(opts.tunnelParallel, run.awg, len(ips), work); err != nil {
			fmt.Fprintln(os.Stderr, errPal.fail(err.Error()))
			os.Exit(1)
		}
		p2.stop(errPal.ok("done"))
		phases = append(phases, phaseResult{run, results})
	}

	if len(phases) == 1 {
		writeConsole(os.Stdout, phases[0], outPal)
	} else {
		writeConsoleBoth(os.Stdout, phases, outPal)
	}
	reportPath := opts.output
	if reportPath == "" {
		reportPath = fmt.Sprintf("warpscout-report-%s.txt", time.Now().Format("2006-01-02-150405"))
	}
	if err := writeToFile(reportPath, phases); err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("failed to write %s: %v", reportPath, err)))
	} else {
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("\nFull report written to %s", reportPath)))
	}
}

// phaseResult pairs a protocol run with its per-endpoint results.
type phaseResult struct {
	run     protoRun
	results []endpointResult
}

// tunnelCandidates is how many live endpoints the fallback discovers before it
// stops scanning and starts bringing up a registration tunnel.
const tunnelCandidates = 20

// fallbackDiscoveryWorkers is the TCP-probe concurrency for that fallback
// endpoint discovery (discoverAlive). Only used when the API is unreachable
// directly and no cached account exists.
const fallbackDiscoveryWorkers = 50

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

	fmt.Fprintf(os.Stderr, "\n%s\n\n", errPal.fail("API unreachable directly"))
	fmt.Fprintln(os.Stderr, errPal.dim("Registering through a WARP tunnel (pass -proxy to use a proxy instead)"))
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

// portProbeSample is how many pool IPs phase 1 tries before deciding a port is
// blocked. A reachable network is confirmed on the first live endpoint; only a
// fully blocked network pays the whole sample.
const portProbeSample = 12

// anyAWG reports whether any run uses AmneziaWG.
func anyAWG(runs []protoRun) bool {
	for _, r := range runs {
		if r.awg {
			return true
		}
	}
	return false
}

// reachablePorts is phase 1: it finds which WARP ports a WireGuard handshake
// reaches on this network. A completed handshake is enough - it proves the port
// is open and basic connectivity exists. Whether data then survives is the
// protocol's job (plain wg may die where AmneziaWG's obfuscation gets through),
// decided per-endpoint in phase 2, so phase 1 stays a cheap handshake probe. It
// walks a sample of pool IPs until one endpoint handshakes on any port - that
// endpoint is reachable, so the ports it answers on are the ones the network
// lets through and the ports it stays silent on are blocked (a live WARP
// endpoint listens on all of warpPorts). Returns the reachable subset of
// warpPorts in their original order, or empty if nothing got through.
func reachablePorts(ctx context.Context, awg bool, ips []netip.Addr, timeout time.Duration, sample int) ([]int, error) {
	tn, err := newTunnel(awg)
	if err != nil {
		return nil, err
	}
	defer tn.Close()

	open := make(map[int]bool)
	for _, ip := range sampleAddrs(ips, sample) {
		for _, port := range warpPorts {
			if tn.handshake(ctx, fmt.Sprintf("%s:%d", ip, port), timeout) {
				open[port] = true
			}
		}
		if len(open) > 0 {
			break // this endpoint is reachable; open now holds the network's ports
		}
	}

	var ports []int
	for _, port := range warpPorts {
		if open[port] {
			ports = append(ports, port)
		}
	}
	return ports, nil
}

// sampleAddrs returns up to n random addresses from ips (all of them if n covers
// the slice), so phase 1 spreads its probes rather than hitting one dead subnet.
func sampleAddrs(ips []netip.Addr, n int) []netip.Addr {
	if n <= 0 || n >= len(ips) {
		return ips
	}
	out := make([]netip.Addr, n)
	for i, j := range rand.Perm(len(ips))[:n] {
		out[i] = ips[j]
	}
	return out
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

// protoRun is one protocol to verify endpoints with.
type protoRun struct {
	awg  bool
	name string
}

// parseProto expands -proto into the ordered list of runs. "both" verifies wg
// first (preferred, no obfuscation) then awg.
func parseProto(p string) ([]protoRun, error) {
	wg := protoRun{false, "wg"}
	awg := protoRun{true, "awg"}
	switch p {
	case "wg":
		return []protoRun{wg}, nil
	case "awg":
		return []protoRun{awg}, nil
	case "both":
		return []protoRun{wg, awg}, nil
	default:
		return nil, fmt.Errorf("invalid -proto %q: use wg, awg or both", p)
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

func writeToFile(path string, phases []phaseResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for i, ph := range phases {
		if len(phases) > 1 {
			if i > 0 {
				fmt.Fprintln(f)
			}
			fmt.Fprintf(f, "########## proto=%s ##########\n", ph.run.name)
		}
		writeFullReport(f, ph.results)
	}
	return nil
}
