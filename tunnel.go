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
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const cloudflareIP = "1.1.1.1:443"

// The gvisor stack behind netstack.CreateNetTUN is never freed by the library
// (netTun.Close only RemoveNIC), so one tunnel per IP leaks and OOMs. Tunnels
// are pooled and only the peer endpoint is swapped, bounding live stacks to the
// worker count.
type tunnel struct {
	dev    *device.Device
	tnet   *netstack.Net
	client *http.Client
}

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
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return tnet.DialContext(ctx, "tcp", cloudflareIP)
		},
	}
	return &tunnel{dev: dev, tnet: tnet, client: &http.Client{Transport: transport}}, nil
}

func (t *tunnel) Close() { t.dev.Close() }

func (t *tunnel) trace(ctx context.Context, ip netip.Addr, timeout time.Duration, pings int) (tr traceResult, endpoint string, ok, durable bool) {
	for _, port := range warpPorts {
		endpoint = fmt.Sprintf("%s:%d", ip, port)
		if tr, durable, ok = t.traceEndpoint(ctx, endpoint, timeout, pings); ok {
			return tr, endpoint, true, durable
		}
	}
	return traceResult{}, endpoint, false, false
}

func (t *tunnel) connect(ctx context.Context, ip netip.Addr, timeout time.Duration) bool {
	for _, port := range warpPorts {
		if t.handshake(ctx, fmt.Sprintf("%s:%d", ip, port), timeout) {
			return true
		}
	}
	return false
}

func (t *tunnel) handshake(ctx context.Context, endpoint string, timeout time.Duration) bool {
	peer, err := peerUAPI(endpoint)
	if err != nil {
		return false
	}
	if err := t.dev.IpcSet(peer); err != nil {
		return false
	}
	return waitHandshake(ctx, t.dev, timeout)
}

func (t *tunnel) traceEndpoint(ctx context.Context, endpoint string, timeout time.Duration, pings int) (tr traceResult, durable, ok bool) {
	peer, err := peerUAPI(endpoint)
	if err != nil {
		return traceResult{}, false, false
	}
	if err := t.dev.IpcSet(peer); err != nil {
		return traceResult{}, false, false
	}

	// Wait for the handshake before sending traffic, otherwise the first TCP SYN
	// is dropped by the not-yet-established peer and netstack stalls past timeout.
	if !waitHandshake(ctx, t.dev, timeout) {
		return traceResult{}, false, false
	}

	body, ok := t.fetch(ctx, timeout)
	if !ok {
		return traceResult{}, false, false
	}
	if pings <= 0 {
		return parseTrace(body), true, true
	}
	return parseTrace(body), t.pingDurable(pings, timeout), true
}

func (t *tunnel) fetch(ctx context.Context, timeout time.Duration) (string, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t.client.Timeout = timeout
	return fetchTrace(reqCtx, t.client, traceURL)
}

const (
	pingTarget      = "1.1.1.1"
	pingInterval    = 500 * time.Millisecond
	durabilityPings = 10
)

func (t *tunnel) pingDurable(count int, timeout time.Duration) bool {
	dst := netip.MustParseAddr(pingTarget)
	pc, err := t.tnet.DialPingAddr(netip.Addr{}, dst)
	if err != nil {
		return true
	}
	defer pc.Close()

	buf := make([]byte, 1500)
	var results []bool
	for seq := 0; seq < count; seq++ {
		if seq > 0 {
			time.Sleep(pingInterval)
		}
		results = append(results, t.pingOnce(pc, seq, buf, timeout))
		if !durableVerdict(results) {
			return false
		}
	}
	return true
}

func durableVerdict(results []bool) bool {
	for _, ok := range results {
		if !ok {
			return false
		}
	}
	return true
}

func (t *tunnel) pingOnce(pc *netstack.PingConn, seq int, buf []byte, timeout time.Duration) bool {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0xbeef, Seq: seq, Data: []byte("warpscout")},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	if _, err := pc.Write(wire); err != nil {
		return false
	}
	pc.SetReadDeadline(time.Now().Add(timeout))
	_, err = pc.Read(buf)
	return err == nil
}

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

func handshakeDone(conf string) bool {
	const key = "last_handshake_time_sec="
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(line, key) && strings.TrimPrefix(line, key) != "0" {
			return true
		}
	}
	return false
}
