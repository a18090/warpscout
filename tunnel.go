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

// verifyEndpoint brings up a userspace tunnel to ip (trying each candidate port
// in order), confirms the handshake by fetching /cdn-cgi/trace through it, and
// returns the real exit colo. endpoint is the ip:port that worked.
func verifyEndpoint(ctx context.Context, ip netip.Addr, awg bool, timeout time.Duration) (t traceResult, endpoint string, ok bool) {
	for _, port := range warpPorts {
		endpoint = fmt.Sprintf("%s:%d", ip, port)
		if t, ok = tunnelTrace(ctx, endpoint, awg, timeout); ok {
			return t, endpoint, true
		}
	}
	return traceResult{}, endpoint, false
}

func tunnelTrace(ctx context.Context, endpoint string, awg bool, timeout time.Duration) (traceResult, bool) {
	uapi, err := buildUAPI(endpoint, awg)
	if err != nil {
		return traceResult{}, false
	}

	localAddr := netip.MustParseAddr(warpAddress)
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{localAddr}, nil, tunnelMTU)
	if err != nil {
		return traceResult{}, false
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	if err := dev.IpcSet(uapi); err != nil {
		return traceResult{}, false
	}
	if err := dev.Up(); err != nil {
		return traceResult{}, false
	}

	// persistent_keepalive triggers a handshake initiation on Up. Wait for it to
	// complete before sending traffic, otherwise the first TCP SYN is dropped by
	// the not-yet-established peer and netstack stalls past the timeout.
	if !waitHandshake(ctx, dev, timeout) {
		return traceResult{}, false
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return tnet.DialContext(ctx, "tcp", cloudflareIP)
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, ok := fetchTrace(reqCtx, client, traceURL)
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
		time.Sleep(100 * time.Millisecond)
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
