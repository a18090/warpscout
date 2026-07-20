package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func main() {
	opts := parseFlags()

	errPal = palette{enabled: colorEnabled(os.Stderr)}

	runs, err := parseProto(opts.proto)
	if err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(err.Error()))
		os.Exit(1)
	}
	timeout := time.Duration(opts.timeoutSec) * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		fmt.Fprintln(os.Stderr)
	}

	// -register is a register-only mode: save the account and stop, no scanning.
	if opts.register {
		return
	}

	// The scan (phase 1 -> phase 2 -> colo resolve) runs through an emit seam: a
	// live bubbletea dashboard on an interactive terminal, or plain lines on a
	// pipe / NO_COLOR / -plain. In TUI mode the scan runs in a goroutine feeding
	// program.Send while Run() owns the terminal; scanDone gates the result read
	// so a q/Ctrl-C abort (which cancels ctx) can't race the workers.
	var phases []phaseResult
	var scanErr error
	if usePlainOutput(opts) {
		phases, scanErr = runScan(ctx, opts, runs, ips, timeout, plainEmit)
	} else {
		scanDone := make(chan struct{})
		p := tea.NewProgram(newScanModel(cancel), tea.WithOutput(os.Stderr))
		go func() {
			phases, scanErr = runScan(ctx, opts, runs, ips, timeout, p.Send)
			close(scanDone)
		}()
		if _, err := p.Run(); err != nil {
			fmt.Fprintln(os.Stderr, errPal.fail(err.Error()))
			os.Exit(1)
		}
		<-scanDone
	}
	if scanErr != nil {
		os.Exit(1) // the emitter already printed the failing phase
	}

	out := lipgloss.NewRenderer(os.Stdout)
	if len(phases) == 1 {
		writeConsole(os.Stdout, phases[0], out)
	} else {
		writeConsoleBoth(os.Stdout, phases, out)
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

// usePlainOutput reports whether to skip the live TUI and emit plain lines:
// stderr is not a terminal, NO_COLOR is set, or -plain was passed.
func usePlainOutput(opts options) bool {
	return opts.plain || os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stderr)
}

// runScan runs the two-phase scan, emitting progress through emit at each
// milestone, and returns the per-protocol results. The returned error is the
// source of truth (emit only drives the UI). host-ping is folded into phase 2 so
// the live feed shows each endpoint with its latency as it is found.
func runScan(ctx context.Context, opts options, runs []protoRun, ips []netip.Addr, timeout time.Duration, emit emitter) ([]phaseResult, error) {
	// Phase 1: find which WARP ports get through this network. Reachability is a
	// network property (DPI / port filtering), not per-IP, so this probes a sample
	// rather than every IP; phase 2 then scans all IPs on only the reachable ports.
	// Probe with awg when any run needs it: AmneziaWG's junk evades DPI that plain
	// wg trips, so its reachable ports are a superset - narrowing on wg could drop
	// a port the awg run needs.
	const phase1 = "Phase 1: probing reachable WARP ports"
	emit(stepMsg{label: phase1})
	open, err := reachablePorts(ctx, anyAWG(runs), ips, timeout, portProbeSample)
	if err != nil {
		emit(stepMsg{label: phase1, fail: true, summary: fmt.Sprintf("phase 1 failed: %v", err)})
		return nil, err
	}
	if len(open) == 0 {
		emit(stepMsg{label: phase1, fail: true, summary: "no WARP port is reachable on this network"})
		return nil, fmt.Errorf("no reachable WARP port")
	}
	warpPorts = open // narrow phase 2 to the reachable ports
	emit(stepMsg{label: phase1, done: true, summary: fmt.Sprintf("reachable ports %v", open)})

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
		label := fmt.Sprintf("Phase 2: verifying tunnels (proto=%s)", run.name)
		emit(barBeginMsg{label: label, total: len(ips)})
		work := func(tn *tunnel, i int) {
			defer emit(probedMsg{})
			ip := ips[i]
			r := endpointResult{ip: ip}
			if t, endpoint, ok, durable := tn.trace(ctx, ip, timeout, pings); ok {
				r.exit, r.endpoint, r.ok, r.durable = t, endpoint, true, durable
				// ponytail: host-ping inline in the narrow phase-2 pool (tunnel-jobs
				// workers); if the working set grows large, move ping to an async wide
				// pool feeding a pingedMsg.
				if rtt, pok := pingHost(ip, timeout); pok {
					r.latency = rtt
				}
				emit(foundMsg{endpoint: endpoint, latency: r.latency, exit: exitRegion(t), colo: exitColo(t), flaky: !durable})
			}
			results[i] = r
		}
		if err := runTunnelPool(opts.tunnelParallel, run.awg, len(ips), work); err != nil {
			emit(stepMsg{fail: true, summary: err.Error()})
			return nil, err
		}
		emit(barEndMsg{label: label, summary: "done"})
		phases = append(phases, phaseResult{run, results})
	}

	const coloStep = "Resolving exit regions"
	emit(stepMsg{label: coloStep})
	coloISO = resolveColoISO(ctx, exitColosOf(phases))
	emit(stepMsg{label: coloStep, done: true, summary: "done"})

	emit(doneMsg{})
	return phases, nil
}
