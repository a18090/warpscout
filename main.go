package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// register needs this too - its tunnel fallback registers through one of the
// sampled addresses.
func setupScan(opts options) ([]protoRun, []netip.Addr, error) {
	runs, err := parseProto(opts.proto)
	if err != nil {
		return nil, nil, err
	}

	if opts.ipv6 {
		pools = poolsV6
	}
	if len(opts.targets) > 0 {
		pools = opts.targets
	}
	// With -interface, interfaceAddr is the authoritative family check (per-interface,
	// precise error); the host-wide check only runs without it.
	if opts.iface != "" {
		if !deviceBindSupported {
			return nil, nil, fmt.Errorf("-interface requires Linux (SO_BINDTODEVICE)")
		}
		ip, err := interfaceAddr(opts.iface, opts.ipv6)
		if err != nil {
			return nil, nil, err
		}
		scanInterface = opts.iface
		scanSourceIP = ip
	} else if !haveAddrFamily(opts.ipv6) {
		return nil, nil, fmt.Errorf("no routable %s address on this host - nothing to scan", famName(opts.ipv6))
	}

	sample := opts.perSubnet
	if opts.full {
		sample = 0
	}
	return runs, expandPools(sample), nil
}

func loadScanAccount(path string) error {
	a, err := loadAccount(path)
	if err != nil {
		return fmt.Errorf("no WARP account at %s: run \"warpscout register\" first", path)
	}
	applyAccount(a)
	fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("Using cached WARP account from %s", path)))
	fmt.Fprintln(os.Stderr)
	return nil
}

func runRegisterCmd(ctx context.Context, opts options) error {
	_, ips, err := setupScan(opts)
	if err != nil {
		return err
	}
	timeout := time.Duration(opts.timeoutSec) * time.Second

	a, err := obtainAccount(ctx, opts, true, ips, timeout)
	if err != nil {
		if opts.proxy == "" {
			return fmt.Errorf("registration failed: %v\ncould not register directly or through a WARP tunnel; retry with -proxy <http(s)/socks5 URL>", err)
		}
		return fmt.Errorf("registration failed: %v", err)
	}
	if err := saveAccount(opts.accountPath, a); err != nil {
		return fmt.Errorf("could not save account to %s: %v", opts.accountPath, err)
	}
	fmt.Fprintln(os.Stderr, errPal.ok(fmt.Sprintf("Registered fresh WARP account -> %s", opts.accountPath)))
	return nil
}

func runFindJunkCmd(ctx context.Context, opts options) error {
	if err := loadScanAccount(opts.accountPath); err != nil {
		return err
	}
	runs, _, err := setupScan(opts)
	if err != nil {
		return err
	}
	return runFindJunk(ctx, opts, runs, time.Duration(opts.timeoutSec)*time.Second)
}

func runScanCmd(ctx context.Context, opts options) error {
	if err := loadScanAccount(opts.accountPath); err != nil {
		return err
	}
	runs, ips, err := setupScan(opts)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	phases, err := runScanUI(ctx, cancel, opts, runs, ips, time.Duration(opts.timeoutSec)*time.Second, "", "")
	if err != nil {
		// runScan already reported the failure through the emit seam.
		os.Exit(1)
	}

	if len(opts.colos) > 0 {
		phases = filterByColo(phases, opts.colos)
		pools = poolsWithHits(phases)
	}

	// Nothing to report: say so on stderr and fail, instead of leaving a report
	// file whose only content is "No working endpoints found".
	if !anyEndpoint(phases) {
		return fmt.Errorf("%s", noEndpointMsg(opts))
	}

	if opts.best {
		printBest(phases)
	} else {
		out := lipgloss.NewRenderer(os.Stdout)
		if len(phases) == 1 {
			writeConsole(os.Stdout, phases[0], out, opts.pingCheck)
		} else {
			writeConsoleBoth(os.Stdout, phases, out, opts.pingCheck)
		}
	}
	reportPath := opts.output
	// A pipe consumer asked for one line, not a stray report file.
	if reportPath == "" && opts.best {
		return nil
	}
	if reportPath == "" {
		reportPath = fmt.Sprintf("warpscout-report-%s.txt", time.Now().Format("2006-01-02-150405"))
	}
	if err := writeToFile(reportPath, phases, opts.pingCheck); err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("failed to write %s: %v", reportPath, err)))
	} else {
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("\nFull report written to %s", reportPath)))
	}
	return nil
}

func anyEndpoint(phases []phaseResult) bool {
	for _, ph := range phases {
		for _, r := range ph.results {
			if r.ok {
				return true
			}
		}
	}
	return false
}

func noEndpointMsg(opts options) string {
	if len(opts.colos) > 0 {
		return "no endpoint landed on " + strings.Join(opts.colos, ", ")
	}
	return "no working endpoints found"
}

func printBest(phases []phaseResult) {
	var working []endpointResult
	for _, ph := range phases {
		working = append(working, workingSorted(ph.results)...)
	}
	if len(working) == 0 {
		fmt.Fprintln(os.Stderr, errPal.fail("every matching endpoint is flaky"))
		os.Exit(1)
	}
	fmt.Println(bestByPing(working).endpoint)
}

func runScanUI(ctx context.Context, cancel context.CancelFunc, opts options, runs []protoRun, ips []netip.Addr, timeout time.Duration, header, quitHint string) ([]phaseResult, error) {
	if usePlainOutput(opts) {
		return runScan(ctx, opts, runs, ips, timeout, plainEmit)
	}

	m := newScanModel(cancel, opts.pingCheck)
	m.header = header
	if quitHint != "" {
		m.quitHint = quitHint
	}
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))

	var phases []phaseResult
	var scanErr error
	scanDone := make(chan struct{})
	go func() {
		phases, scanErr = runScan(ctx, opts, runs, ips, timeout, p.Send)
		close(scanDone)
	}()
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(err.Error()))
		return nil, err
	}
	<-scanDone
	return phases, scanErr
}

func usePlainOutput(opts options) bool {
	return opts.plain || os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stderr)
}

func runScan(ctx context.Context, opts options, runs []protoRun, ips []netip.Addr, timeout time.Duration, emit emitter) ([]phaseResult, error) {
	if scanSourceIP.IsValid() {
		emit(stepMsg{done: true, label: "Interface", summary: fmt.Sprintf("%s (%s)", opts.iface, scanSourceIP)})
	}
	open, err := reachablePorts(ctx, anyAWG(runs), ips, timeout, portProbeSample, emit)
	if err != nil {
		emit(stepMsg{fail: true, summary: fmt.Sprintf("phase 1 failed: %v", err)})
		return nil, err
	}
	if len(open) == 0 {
		emit(stepMsg{fail: true, summary: "no WARP port is reachable on this network"})
		return nil, fmt.Errorf("no reachable WARP port")
	}
	warpPorts = open

	var phases []phaseResult
	for _, run := range runs {
		results := make([]endpointResult, len(ips))
		pings := opts.pingCount
		label := fmt.Sprintf("Phase 2: verifying tunnels (proto=%s)", run.name)
		emit(barBeginMsg{label: label, total: len(ips)})
		work := func(tn *tunnel, i int) {
			defer emit(probedMsg{})
			ip := ips[i]
			r := endpointResult{ip: ip}
			if t, endpoint, ok, rtt, loss, flaky := tn.trace(ctx, ip, timeout, pings, opts.wantTrace); ok {
				r.exit, r.endpoint, r.ok, r.durable = t, endpoint, true, true
				if pings > 0 {
					r.rtt, r.loss, r.measured, r.durable = rtt, loss, true, !flaky
				}
				if hrtt, pok := pingHost(ip, timeout); pok {
					r.latency = hrtt
				}
				found := foundMsg{endpoint: endpoint, latency: r.ping(), loss: r.loss, measured: r.measured, flaky: !r.durable}
				if opts.wantTrace {
					found.exit, found.colo = exitRegion(t), exitColo(t)
				}
				emit(found)
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

	if opts.wantTrace {
		const coloStep = "Resolving exit regions"
		emit(stepMsg{label: coloStep})
		coloISO = resolveColoISO(ctx, exitColosOf(phases))
		emit(stepMsg{label: coloStep, done: true, summary: "done"})
	}

	emit(doneMsg{})
	return phases, nil
}
