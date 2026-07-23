package main

import (
	"net"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/conn"
)

// sourceBind is a minimal conn.Bind that ties the tunnel's outer UDP socket to a
// chosen source IP, so scan traffic egresses from a specific interface. amneziawg-go
// exposes no hook for this on its StdNetBind, so we replace the Bind entirely. A
// scanner talks to one peer at a time and needs no batching/GSO/sticky-socket
// machinery, so this is a single unconnected socket with BatchSize 1 rather than a
// copy of the 500-line StdNetBind.
//
// ponytail: source-IP bind, not SO_BINDTODEVICE. Forces the WARP source address to
// the interface's IP (correct when that interface is the real egress); does not pin
// the egress interface under policy routing. Upgrade path: a Control fn setting
// SO_BINDTODEVICE (needs CAP_NET_RAW).
type sourceBind struct {
	src  netip.Addr
	conn *net.UDPConn
}

type sourceEndpoint struct{ dst netip.AddrPort }

func newSourceBind(src netip.Addr) *sourceBind { return &sourceBind{src: src} }

func (b *sourceBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: b.src.AsSlice(), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.conn = c
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

func (b *sourceBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	n, addr, err := b.conn.ReadFromUDPAddrPort(bufs[0])
	if err != nil {
		// The only expected read error is the socket being closed; treat any as terminal
		// so the device's receive goroutine exits cleanly, as the Bind contract requires.
		return 0, net.ErrClosed
	}
	sizes[0] = n
	eps[0] = &sourceEndpoint{dst: addr}
	return 1, nil
}

func (b *sourceBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst := ep.(*sourceEndpoint).dst
	for _, buf := range bufs {
		if _, err := b.conn.WriteToUDPAddrPort(buf, dst); err != nil {
			return err
		}
	}
	return nil
}

func (b *sourceBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &sourceEndpoint{dst: addr}, nil
}

func (b *sourceBind) Close() error {
	if b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *sourceBind) SetMark(uint32) error { return nil }

func (b *sourceBind) BatchSize() int { return 1 }

func (e *sourceEndpoint) ClearSrc()           {}
func (e *sourceEndpoint) SrcToString() string { return "" }
func (e *sourceEndpoint) DstToString() string { return e.dst.String() }
func (e *sourceEndpoint) DstToBytes() []byte  { b, _ := e.dst.MarshalBinary(); return b }
func (e *sourceEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *sourceEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
