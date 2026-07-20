package main

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

const traceURL = "https://cloudflare.com/cdn-cgi/trace"

// discoverColo makes a direct HTTPS request to Cloudflare's edge with the
// connection forced to ip (equivalent to curl --resolve), reporting which edge
// colo answers for that IP without any tunnel. Used by discoverAlive to find
// live endpoints for the registration fallback.
func discoverColo(ctx context.Context, ip netip.Addr, timeout time.Duration) (traceResult, bool) {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		// Ignore the requested host, always dial the pool IP on 443.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), "443"))
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	body, ok := fetchTrace(ctx, client, traceURL)
	if !ok {
		return traceResult{}, false
	}
	t := parseTrace(body)
	return t, t.colo != ""
}

// fetchTrace performs the GET and returns the body text.
func fetchTrace(ctx context.Context, client *http.Client, url string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", false
	}
	return string(body), true
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
