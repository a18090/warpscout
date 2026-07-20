package main

import (
	"context"
	"fmt"
	"os"
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
		// The ping check is opt-in (-ping) and only makes sense for wg: awg's junk
		// params already fix the death-on-data-volume, so a lost ping through an
		// awg tunnel is measurement noise, not a real drop. Trust the awg trace.
		pings := 0
		if opts.pingCheck && !run.awg {
			pings = durabilityPings
		}
		p2 := newProgress(fmt.Sprintf("Phase 2: verifying tunnels (proto=%s)", run.name), len(ips), errPal)
		work := func(tn *tunnel, i int) {
			defer p2.inc()
			ip := ips[i]
			r := endpointResult{ip: ip}
			if t, endpoint, ok, durable := tn.trace(ctx, ip, timeout, pings); ok {
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

	coloISO = resolveColoISO(ctx, exitColosOf(phases))

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
