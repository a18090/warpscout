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
	noEmoji = opts.noEmoji || usePlainOutput(opts)

	runs, err := parseProto(opts.proto)
	if err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(err.Error()))
		os.Exit(1)
	}
	timeout := time.Duration(opts.timeoutSec) * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		sample = 0
	}
	ips := expandPools(sample)

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

	if opts.register {
		return
	}

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
		os.Exit(1)
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

func usePlainOutput(opts options) bool {
	return opts.plain || os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stderr)
}

func runScan(ctx context.Context, opts options, runs []protoRun, ips []netip.Addr, timeout time.Duration, emit emitter) ([]phaseResult, error) {
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
	warpPorts = open
	emit(stepMsg{label: phase1, done: true, summary: fmt.Sprintf("reachable ports %v", open)})

	var phases []phaseResult
	for _, run := range runs {
		results := make([]endpointResult, len(ips))
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
