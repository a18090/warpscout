package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
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
