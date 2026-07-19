package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// cloudflareIP is dialed through the tunnel for the trace request, avoiding any
// in-tunnel DNS. TLS SNI stays cloudflare.com so the certificate verifies.
const cloudflareIP = "1.1.1.1:443"

// tunnel is a persistent userspace WireGuard device reused across many IPs. The
// gvisor stack behind netstack.CreateNetTUN is never freed by the library
// (netTun.Close only RemoveNIC), so creating one per IP leaks and OOMs. Reusing
// a fixed pool of tunnels and swapping only the peer endpoint bounds live stacks
// to the worker count.
type tunnel struct {
	dev    *device.Device
	client *http.Client
}

// newTunnel brings up one device with the interface config applied once.
func newTunnel(awg bool) (*tunnel, error) {
	base, err := baseUAPI(awg)
	if err != nil {
		return nil, err
	}

	localAddr := netip.MustParseAddr(warpAddress)
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{localAddr}, nil, tunnelMTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	if err := dev.IpcSet(base); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}

	transport := &http.Transport{
		// Fresh connection each request so no TCP state from a previous endpoint
		// carries over after the peer is swapped.
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return tnet.DialContext(ctx, "tcp", cloudflareIP)
		},
	}
	return &tunnel{dev: dev, client: &http.Client{Transport: transport}}, nil
}

func (t *tunnel) Close() { t.dev.Close() }

// trace points the tunnel at ip (trying each candidate port in order), confirms
// the handshake by fetching /cdn-cgi/trace through it, and returns the real exit
// colo. endpoint is the ip:port that worked.
func (t *tunnel) trace(ctx context.Context, ip netip.Addr, timeout time.Duration) (tr traceResult, endpoint string, ok bool) {
	for _, port := range warpPorts {
		endpoint = fmt.Sprintf("%s:%d", ip, port)
		if tr, ok = t.traceEndpoint(ctx, endpoint, timeout); ok {
			return tr, endpoint, true
		}
	}
	return traceResult{}, endpoint, false
}

func (t *tunnel) traceEndpoint(ctx context.Context, endpoint string, timeout time.Duration) (traceResult, bool) {
	peer, err := peerUAPI(endpoint)
	if err != nil {
		return traceResult{}, false
	}
	if err := t.dev.IpcSet(peer); err != nil {
		return traceResult{}, false
	}

	// persistent_keepalive triggers a handshake initiation. Wait for it to
	// complete before sending traffic, otherwise the first TCP SYN is dropped by
	// the not-yet-established peer and netstack stalls past the timeout.
	if !waitHandshake(ctx, t.dev, timeout) {
		return traceResult{}, false
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t.client.Timeout = timeout
	body, ok := fetchTrace(reqCtx, t.client, traceURL)
	if !ok {
		return traceResult{}, false
	}
	return parseTrace(body), true
}

// waitHandshake polls the device until the peer reports a completed handshake
// or the timeout elapses.
func waitHandshake(ctx context.Context, dev *device.Device, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		conf, err := dev.IpcGet()
		if err == nil && handshakeDone(conf) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// handshakeDone reports whether the UAPI dump contains a non-zero
// last_handshake_time_sec.
func handshakeDone(conf string) bool {
	const key = "last_handshake_time_sec="
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(line, key) && strings.TrimPrefix(line, key) != "0" {
			return true
		}
	}
	return false
}
