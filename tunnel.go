package main

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

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
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{localAddr}, []netip.Addr{netip.MustParseAddr(pingTarget)}, tunnelMTU)
	if err != nil {
		return nil, err
	}
	bind := conn.Bind(conn.NewDefaultBind())
	if scanInterface != "" {
		bind = newDeviceBind(scanInterface)
	}
	dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelSilent, ""))

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
			return tnet.DialContext(ctx, "tcp", metaAddr)
		},
	}
	return &tunnel{dev: dev, tnet: tnet, client: &http.Client{Transport: transport}}, nil
}

func (t *tunnel) Close() { t.dev.Close() }

func (t *tunnel) probe(ctx context.Context, ip netip.Addr, timeout time.Duration, pings int, wantMeta bool) (tr metaResult, endpoint string, ok bool, rtt time.Duration, loss float32, torn bool) {
	for _, port := range warpPorts {
		endpoint = net.JoinHostPort(ip.String(), strconv.Itoa(port))
		if tr, rtt, loss, torn, ok = t.probeEndpoint(ctx, endpoint, timeout, pings, wantMeta); ok {
			return tr, endpoint, true, rtt, loss, torn
		}
	}
	return metaResult{}, endpoint, false, 0, 0, false
}

func (t *tunnel) connect(ctx context.Context, ip netip.Addr, timeout time.Duration) bool {
	for _, port := range warpPorts {
		if t.handshake(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(port)), timeout) {
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

func (t *tunnel) probeEndpoint(ctx context.Context, endpoint string, timeout time.Duration, pings int, wantMeta bool) (tr metaResult, rtt time.Duration, loss float32, torn, ok bool) {
	peer, err := peerUAPI(endpoint)
	if err != nil {
		return metaResult{}, 0, 0, false, false
	}
	if err := t.dev.IpcSet(peer); err != nil {
		return metaResult{}, 0, 0, false, false
	}

	// Wait for the handshake before sending traffic, otherwise the first TCP SYN
	// is dropped by the not-yet-established peer and netstack stalls past timeout.
	if !waitHandshake(ctx, t.dev, timeout) {
		return metaResult{}, 0, 0, false, false
	}

	// find-junk only asks whether the peer comes up, and the durability ping
	// already proves the tunnel passes data - the meta fetch adds nothing.
	if !wantMeta {
		if pings <= 0 {
			return metaResult{}, 0, 0, false, true
		}
		rtt, loss, torn = t.durability(pings, timeout)
		return metaResult{}, rtt, loss, torn, true
	}

	body, ok := t.fetch(ctx, timeout)
	if !ok {
		return metaResult{}, 0, 0, false, false
	}
	if pings <= 0 {
		return parseMeta(body), 0, 0, false, true
	}
	rtt, loss, torn = t.durability(pings, timeout)
	return parseMeta(body), rtt, loss, torn, true
}

// A real DPI teardown stays dead across both bursts; transient loss does not,
// so the second burst's numbers are the ones reported when the first was noise.
// Running right after the meta fetch lets the burst read the tunnel's state once a
// real request has already given DPI something to kill.
func (t *tunnel) durability(count int, timeout time.Duration) (time.Duration, float32, bool) {
	rtt, loss, torn := t.tunnelPing(count, timeout)
	if !torn {
		return rtt, loss, false
	}
	rtt2, loss2, torn2 := t.tunnelPing(count, timeout)
	if !torn2 {
		return rtt2, loss2, false
	}
	return rtt, loss, true
}

func (t *tunnel) fetch(ctx context.Context, timeout time.Duration) (string, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if !resolveMetaAddr(reqCtx, t.tnet) {
		return "", false
	}
	t.client.Timeout = timeout
	return fetchMeta(reqCtx, t.client, metaURL)
}

var (
	metaAddrMu sync.Mutex
	metaAddr   string
)

// Resolved through the tunnel, not on the host: a host resolver can answer with
// an address that only routes outside the tunnel. The first worker to get
// through fills it in for the rest of the run.
func resolveMetaAddr(ctx context.Context, tnet *netstack.Net) bool {
	metaAddrMu.Lock()
	defer metaAddrMu.Unlock()
	if metaAddr != "" {
		return true
	}
	ips, err := tnet.LookupContextHost(ctx, metaHost)
	if err != nil || len(ips) == 0 {
		return false
	}
	metaAddr = net.JoinHostPort(ips[0], "443")
	return true
}

const (
	pingTarget      = "1.1.1.1"
	pingInterval    = 200 * time.Millisecond
	durabilityPings = 10
	// torn down = the tunnel passes data and is then cut mid-stream, never recovering,
	// i.e. a trailing run of dropped pings. Sporadic single drops are loss, not a teardown, so we
	// key off a run of consecutive tail failures rather than a loss percentage.
	tornTailFails = 3
	// A burst of tornTailFails echoes technically fits a tail run, but with no
	// margin at all for a single stray drop:
	// measured 13 of 70 dead wg peers reported as working at 3 echoes, none at 10.
	minDurabilityPings = 5
)

// Echoes are spread over time to give DPI traffic to react to, but replies are
// matched by sequence in a shared window: a reply merely delayed by a contended
// netstack (many userspace tunnels at once) still counts instead of scoring as
// a loss.
func (t *tunnel) tunnelPing(count int, timeout time.Duration) (time.Duration, float32, bool) {
	dst := netip.MustParseAddr(pingTarget)
	pc, err := t.tnet.DialPingAddr(netip.Addr{}, dst)
	if err != nil {
		return 0, 0, false
	}
	defer pc.Close()

	sent := make([]time.Time, count)
	got := make([]bool, count)
	buf := make([]byte, 1500)
	n := 0
	var total time.Duration

	drain := func(deadline time.Time) {
		for n < count {
			pc.SetReadDeadline(deadline)
			m, err := pc.Read(buf)
			if err != nil {
				return
			}
			seq, ok := parseEchoSeq(buf[:m])
			if !ok || seq < 0 || seq >= count || got[seq] || sent[seq].IsZero() {
				continue
			}
			got[seq] = true
			total += time.Since(sent[seq])
			n++
		}
	}

	for seq := 0; seq < count; seq++ {
		if t.sendEcho(pc, seq) {
			sent[seq] = time.Now()
		}
		drain(time.Now().Add(pingInterval))
	}
	drain(time.Now().Add(timeout)) // final window for stragglers before scoring loss

	return pingSummary(total, n), lossFraction(n, count), teardown(got)
}

func (t *tunnel) sendEcho(pc *netstack.PingConn, seq int) bool {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0xbeef, Seq: seq, Data: []byte("warpscout")},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	_, err = pc.Write(wire)
	return err == nil
}

func parseEchoSeq(b []byte) (int, bool) {
	m, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), b)
	if err != nil {
		return 0, false
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok || m.Type != ipv4.ICMPTypeEchoReply {
		return 0, false
	}
	return echo.Seq, true
}

func pingSummary(total time.Duration, got int) time.Duration {
	if got == 0 {
		return 0
	}
	return total / time.Duration(got)
}

func lossFraction(got, count int) float32 {
	if count == 0 {
		return 0
	}
	return float32(count-got) / float32(count)
}

// A trailing run of at least tornTailFails unanswered echoes means the tunnel
// stopped passing traffic and did not come back.
func teardown(results []bool) bool {
	if len(results) < tornTailFails {
		return false
	}
	for _, ok := range results[len(results)-tornTailFails:] {
		if ok {
			return false
		}
	}
	return true
}

const handshakePollInterval = 50 * time.Millisecond

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
		time.Sleep(handshakePollInterval)
	}
	return false
}

const handshakeKey = "last_handshake_time_sec="

func handshakeDone(conf string) bool {
	i := strings.Index(conf, handshakeKey)
	if i < 0 {
		return false
	}
	v := i + len(handshakeKey)
	return v < len(conf) && conf[v] != '0'
}
