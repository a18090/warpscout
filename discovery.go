package main

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const traceURL = "https://cloudflare.com/cdn-cgi/trace"

func discoverColo(ctx context.Context, ip netip.Addr, timeout time.Duration) (traceResult, bool) {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
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

const portProbeSample = 12

func haveAddrFamily(v6 bool) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if v6 == (ipn.IP.To4() == nil) {
			return true
		}
	}
	return false
}

func anyAWG(runs []protoRun) bool {
	for _, r := range runs {
		if r.awg {
			return true
		}
	}
	return false
}

func reachablePorts(ctx context.Context, awg bool, ips []netip.Addr, timeout time.Duration, sample int, emit emitter) ([]int, error) {
	tn, err := newTunnel(awg)
	if err != nil {
		return nil, err
	}
	defer tn.Close()

	sampled := sampleAddrs(ips, sample)
	if ports := probePorts(ctx, tn, sampled, primaryWarpPorts, timeout, emit, "Phase 1: probing reachable WARP ports"); len(ports) > 0 {
		return ports, nil
	}
	// No primary port got through: locked-down network, sweep the alternates.
	return probePorts(ctx, tn, sampled, extendedWarpPorts, timeout, emit, "Phase 1: sweeping alternate WARP ports"), nil
}

func probePorts(ctx context.Context, tn *tunnel, ips []netip.Addr, ports []int, timeout time.Duration, emit emitter, label string) []int {
	emit(barBeginMsg{label: label, total: len(ips)})
	open := make(map[int]bool)
	for _, ip := range ips {
		for _, port := range ports {
			if tn.handshake(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(port)), timeout) {
				open[port] = true
			}
		}
		emit(probedMsg{})
		if len(open) > 0 {
			break
		}
	}

	var out []int
	for _, port := range ports {
		if open[port] {
			out = append(out, port)
		}
	}
	summary := "none reachable"
	if len(out) > 0 {
		summary = fmt.Sprintf("reachable ports %v", out)
	}
	emit(barEndMsg{label: label, summary: summary})
	return out
}

const (
	pingProbes = 3
	pingID     = 0xbeef
)

func pingHost(addr netip.Addr, timeout time.Duration) (time.Duration, bool) {
	conn, dst := listenPing(addr)
	if conn == nil {
		return 0, false
	}
	defer conn.Close()

	var total time.Duration
	got := 0
	buf := make([]byte, 1500)
	for seq := 0; seq < pingProbes; seq++ {
		if rtt, ok := pingHostOnce(conn, dst, seq, buf, timeout); ok {
			total += rtt
			got++
		}
	}
	if got == 0 {
		return 0, false
	}
	return total / time.Duration(got), true
}

func listenPing(addr netip.Addr) (*icmp.PacketConn, net.Addr) {
	udpNet, rawNet, bind := "udp4", "ip4:icmp", "0.0.0.0"
	if addr.Is6() {
		udpNet, rawNet, bind = "udp6", "ip6:ipv6-icmp", "::"
	}
	if conn, err := icmp.ListenPacket(udpNet, bind); err == nil {
		return conn, &net.UDPAddr{IP: addr.AsSlice()}
	}
	if conn, err := icmp.ListenPacket(rawNet, bind); err == nil {
		return conn, &net.IPAddr{IP: addr.AsSlice()}
	}
	return nil, nil
}

func pingHostOnce(conn *icmp.PacketConn, dst net.Addr, seq int, buf []byte, timeout time.Duration) (time.Duration, bool) {
	echoType, replyType := icmpEchoTypes(dst)
	msg := icmp.Message{
		Type: echoType,
		Body: &icmp.Echo{ID: pingID, Seq: seq, Data: []byte("warpscout")},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return 0, false
	}
	start := time.Now()
	if _, err := conn.WriteTo(wire, dst); err != nil {
		return 0, false
	}

	deadline := start.Add(timeout)
	conn.SetReadDeadline(deadline)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, false
		}
		reply, err := icmp.ParseMessage(replyType.Protocol(), buf[:n])
		if err != nil {
			continue
		}
		// The udp ICMP socket rewrites the ID, so match on the echoed sequence only.
		if echo, ok := reply.Body.(*icmp.Echo); ok && reply.Type == replyType && echo.Seq == seq {
			return time.Since(start), true
		}
	}
}

func icmpEchoTypes(dst net.Addr) (echo, reply icmp.Type) {
	if isV6Addr(dst) {
		return ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	return ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
}

func isV6Addr(dst net.Addr) bool {
	switch a := dst.(type) {
	case *net.UDPAddr:
		return a.IP.To4() == nil
	case *net.IPAddr:
		return a.IP.To4() == nil
	}
	return false
}

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
