package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// register needs this too - its tunnel fallback registers through one of the
// sampled addresses.
func setupScan(opts options) (protoRun, []netip.Addr, error) {
	run, err := parseProto(opts.proto)
	if err != nil {
		return run, nil, err
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
			return run, nil, fmt.Errorf("-interface requires Linux (SO_BINDTODEVICE)")
		}
		ip, err := interfaceAddr(opts.iface, opts.ipv6)
		if err != nil {
			return run, nil, err
		}
		scanInterface = opts.iface
		scanSourceIP = ip
	} else if !haveAddrFamily(opts.ipv6) {
		return run, nil, fmt.Errorf("no routable %s address on this host - nothing to scan", famName(opts.ipv6))
	}

	sample := opts.perSubnet
	if opts.full {
		sample = 0
	}
	return run, expandPools(sample), nil
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

	var existing account
	if !opts.freshAccount {
		existing, _ = loadAccount(opts.accountPath)
	}

	a, err := obtainAccount(ctx, opts, true, ips, timeout, existing)
	if err != nil {
		if opts.proxy == "" {
			return fmt.Errorf("registration failed: %v\ncould not register directly or through a WARP tunnel; retry with -proxy <http(s)/socks5 URL>", err)
		}
		return fmt.Errorf("registration failed: %v", err)
	}
	if err := saveAccount(opts.accountPath, a); err != nil {
		return fmt.Errorf("could not save account to %s: %v", opts.accountPath, err)
	}
	what := "Registered fresh WARP account"
	if a.ID == existing.ID {
		what = "Rotated the keys of the existing WARP account"
	}
	fmt.Fprintln(os.Stderr, errPal.ok(fmt.Sprintf("%s -> %s", what, opts.accountPath)))
	return nil
}

func runFindJunkCmd(ctx context.Context, opts options) error {
	if opts.junkThreshold < 1 || opts.junkThreshold > 100 {
		return fmt.Errorf("-threshold (%d) must be between 1 and 100", opts.junkThreshold)
	}
	if err := loadScanAccount(opts.accountPath); err != nil {
		return err
	}
	run, _, err := setupScan(opts)
	if err != nil {
		return err
	}
	return runFindJunk(ctx, opts, run, time.Duration(opts.timeoutSec)*time.Second)
}

func runScanCmd(ctx context.Context, opts options) error {
	if err := loadScanAccount(opts.accountPath); err != nil {
		return err
	}
	run, ips, err := setupScan(opts)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ph, err := runScanUI(ctx, cancel, opts, run, ips, time.Duration(opts.timeoutSec)*time.Second, "", "")
	if err != nil {
		// runScan already reported the failure through the emit seam.
		os.Exit(1)
	}

	if len(opts.colos) > 0 {
		ph = filterByColo(ph, opts.colos)
	}
	if len(opts.countries) > 0 {
		ph = filterByCountry(ph, opts.countries)
	}
	if len(opts.colos) > 0 || len(opts.countries) > 0 {
		pools = poolsWithHits(ph)
	}

	// Nothing to report: say so on stderr and fail, instead of leaving a report
	// file whose only content is "No working endpoints found".
	if !anyEndpoint(ph) {
		return fmt.Errorf("%s", noEndpointMsg(opts))
	}

	if opts.best {
		printBest(ph)
	} else {
		writeConsole(os.Stdout, ph, consoleRenderer(os.Stdout), opts.pingCheck)
	}
	if opts.conf != "" {
		writeConfFile(opts, ph)
	}

	if opts.noReport {
		return nil
	}

	reportPath := opts.output
	// A pipe consumer asked for one line, not a stray report file.
	if reportPath == "" && opts.best {
		return nil
	}
	if reportPath == "" {
		reportPath = fmt.Sprintf("warpscout-report-%s.txt", time.Now().Format("2006-01-02-150405"))
	}
	if err := writeToFile(reportPath, ph, opts.pingCheck); err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("failed to write %s: %v", reportPath, err)))
	} else {
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("\nFull report written to %s", reportPath)))
	}
	return nil
}

func anyEndpoint(ph phaseResult) bool {
	for _, r := range ph.results {
		if r.ok {
			return true
		}
	}
	return false
}

func noEndpointMsg(opts options) string {
	var filters []string
	if len(opts.colos) > 0 {
		filters = append(filters, "node "+strings.Join(opts.colos, ", "))
	}
	if len(opts.countries) > 0 {
		filters = append(filters, "country "+strings.Join(opts.countries, ", "))
	}
	if len(filters) > 0 {
		return "no endpoint landed on " + strings.Join(filters, " and ")
	}
	if opts.genI1 == "" {
		if opts.proto == protoAWG {
			return "no working endpoints found - try -gen-i1 quic"
		}
		return "no working endpoints found - try -p awg -gen-i1 quic"
	}
	return "no working endpoints found"
}

const noWorkingMsg = "every matching endpoint is flaky"

func writeConfFile(opts options, ph phaseResult) {
	best, ok := bestOverall(ph)
	if !ok {
		fmt.Fprintln(os.Stderr, errPal.fail(noWorkingMsg))
		return
	}
	if err := writeConf(opts, best.endpoint, ph.run.awg); err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("failed to write %s: %v", opts.conf, err)))
		return
	}
	fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("\n%s config for %s written to %s", ph.run.name, best.endpoint, opts.conf)))
}

func bestOverall(ph phaseResult) (endpointResult, bool) {
	var best endpointResult
	found := false
	for _, r := range workingSorted(ph.results) {
		if !found || lessByLossRTT(r, best) {
			best, found = r, true
		}
	}
	return best, found
}

func printBest(ph phaseResult) {
	best, ok := bestOverall(ph)
	if !ok {
		fmt.Fprintln(os.Stderr, errPal.fail(noWorkingMsg))
		os.Exit(1)
	}
	fmt.Println(best.endpoint)
}

func runScanUI(ctx context.Context, cancel context.CancelFunc, opts options, run protoRun, ips []netip.Addr, timeout time.Duration, header, quitHint string) (phaseResult, error) {
	if usePlainOutput(opts) {
		return runScan(ctx, opts, run, ips, timeout, plainEmit)
	}

	m := newScanModel(cancel, opts.pingCheck)
	m.header = header
	if quitHint != "" {
		m.quitHint = quitHint
	}
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))

	var ph phaseResult
	var scanErr error
	scanDone := make(chan struct{})
	go func() {
		ph, scanErr = runScan(ctx, opts, run, ips, timeout, p.Send)
		close(scanDone)
	}()
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(err.Error()))
		return phaseResult{}, err
	}
	<-scanDone
	return ph, scanErr
}

func usePlainOutput(opts options) bool {
	return opts.plain || os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stderr)
}

func runScan(ctx context.Context, opts options, run protoRun, ips []netip.Addr, timeout time.Duration, emit emitter) (phaseResult, error) {
	if scanSourceIP.IsValid() {
		emit(stepMsg{done: true, label: "Interface", summary: fmt.Sprintf("%s (%s)", opts.iface, scanSourceIP)})
	}
	open, err := reachablePorts(ctx, run.awg, ips, timeout, portProbeSample, emit)
	if err != nil {
		emit(stepMsg{fail: true, summary: fmt.Sprintf("phase 1 failed: %v", err)})
		return phaseResult{}, err
	}
	if len(open) == 0 {
		emit(stepMsg{fail: true, summary: "no WARP port is reachable on this network"})
		return phaseResult{}, fmt.Errorf("no reachable WARP port")
	}
	warpPorts = open

	results := make([]endpointResult, len(ips))
	pings := opts.pingCount
	label := fmt.Sprintf("Phase 2: verifying tunnels (proto=%s)", run.name)
	emit(barBeginMsg{label: label, total: len(ips)})
	work := func(tn *tunnel, i int) {
		defer emit(probedMsg{})
		ip := ips[i]
		r := endpointResult{ip: ip}
		if t, endpoint, ok, rtt, loss, flaky := tn.probe(ctx, ip, timeout, pings, opts.wantMeta); ok {
			r.exit, r.endpoint, r.ok, r.durable = t, endpoint, true, true
			if pings > 0 {
				r.rtt, r.loss, r.measured, r.durable = rtt, loss, true, !flaky
			}
			if hrtt, pok := pingHost(ip, timeout); pok {
				r.latency = hrtt
			}
			found := foundMsg{endpoint: endpoint, latency: r.ping(), loss: r.loss, measured: r.measured, flaky: !r.durable}
			if opts.wantMeta {
				found.exit, found.colo = exitRegion(t), exitColo(t)
			}
			emit(found)
		}
		results[i] = r
	}
	if err := runTunnelPool(opts.tunnelParallel, run.awg, len(ips), work); err != nil {
		emit(stepMsg{fail: true, summary: err.Error()})
		return phaseResult{}, err
	}
	emit(barEndMsg{label: label, summary: "done"})

	emit(doneMsg{})
	return phaseResult{run, results}, nil
}
