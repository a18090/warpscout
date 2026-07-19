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
	tnet   *netstack.Net
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
	return &tunnel{dev: dev, tnet: tnet, client: &http.Client{Transport: transport}}, nil
}

func (t *tunnel) Close() { t.dev.Close() }

// trace points the tunnel at ip (trying each candidate port in order), confirms
// the handshake by fetching /cdn-cgi/trace through it, and returns the real exit
// colo. endpoint is the ip:port that worked. durable reports whether the tunnel
// survived the re-probe (see traceEndpoint); it is meaningful only when ok.
func (t *tunnel) trace(ctx context.Context, ip netip.Addr, timeout time.Duration, pings int) (tr traceResult, endpoint string, ok, durable bool) {
	for _, port := range warpPorts {
		endpoint = fmt.Sprintf("%s:%d", ip, port)
		if tr, durable, ok = t.traceEndpoint(ctx, endpoint, timeout, pings); ok {
			return tr, endpoint, true, durable
		}
	}
	return traceResult{}, endpoint, false, false
}

// connect points the tunnel at ip (first candidate port that completes a
// handshake) without fetching anything, so the caller can send its own traffic
// (e.g. the registration requests) through t.tnet.
func (t *tunnel) connect(ctx context.Context, ip netip.Addr, timeout time.Duration) bool {
	for _, port := range warpPorts {
		peer, err := peerUAPI(fmt.Sprintf("%s:%d", ip, port))
		if err != nil {
			continue
		}
		if err := t.dev.IpcSet(peer); err != nil {
			continue
		}
		if waitHandshake(ctx, t.dev, timeout) {
			return true
		}
	}
	return false
}

// traceEndpoint brings the peer up and fetches the trace. When pings > 0 it then
// pings through the same established session to catch the delayed drop:
// censorship gear (TSPU) lets a WireGuard handshake and a few packets through,
// then drops the flagged peer, so a single fetch is a false positive. durable is
// meaningful only when ok (the initial fetch succeeded).
func (t *tunnel) traceEndpoint(ctx context.Context, endpoint string, timeout time.Duration, pings int) (tr traceResult, durable, ok bool) {
	peer, err := peerUAPI(endpoint)
	if err != nil {
		return traceResult{}, false, false
	}
	if err := t.dev.IpcSet(peer); err != nil {
		return traceResult{}, false, false
	}

	// persistent_keepalive triggers a handshake initiation. Wait for it to
	// complete before sending traffic, otherwise the first TCP SYN is dropped by
	// the not-yet-established peer and netstack stalls past the timeout.
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

// fetch does one trace request through the currently established peer.
func (t *tunnel) fetch(ctx context.Context, timeout time.Duration) (string, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t.client.Timeout = timeout
	return fetchTrace(reqCtx, t.client, traceURL)
}

const (
	pingTarget   = "1.1.1.1"
	pingInterval = 500 * time.Millisecond
)

// pingDurable sends up to count ICMP echoes through the established tunnel to
// 1.1.1.1 and returns whether every one round-tripped. A censored (TSPU-dropped)
// peer passes the first few packets, then dies on data volume and never
// recovers, so any lost reply means flaky - it stops early on the first loss.
//
// ponytail: falls back to durable=true if ICMP can't be set up at all, so an
// endpoint whose data path already proved good via the TCP trace is never
// downgraded just because the ping socket failed to open.
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
			return false // a reply was lost, stop early
		}
	}
	return true
}

// durableVerdict reports whether every ping so far round-tripped. A single lost
// reply means the peer is dying on data volume (flaky), so it is not tolerated.
func durableVerdict(results []bool) bool {
	for _, ok := range results {
		if !ok {
			return false
		}
	}
	return true
}

// pingOnce sends one echo and reports whether a reply came back within timeout.
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
