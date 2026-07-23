package main

import (
	"context"
	"net"
	"net/netip"
	"strconv"

	"github.com/amnezia-vpn/amneziawg-go/conn"
)

// deviceBind is a minimal conn.Bind that pins the tunnel's outer UDP socket to a
// chosen interface via SO_BINDTODEVICE (deviceControl), so scan traffic egresses
// through that interface - including a tun, which source-IP binding cannot route
// into.
type deviceBind struct {
	iface string
	conn  *net.UDPConn
}

type sourceEndpoint struct{ dst netip.AddrPort }

func newDeviceBind(iface string) *deviceBind { return &deviceBind{iface: iface} }

func (b *deviceBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	lc := net.ListenConfig{Control: deviceControl(b.iface, 0)}
	pc, err := lc.ListenPacket(context.Background(), "udp", net.JoinHostPort("", strconv.Itoa(int(port))))
	if err != nil {
		return nil, 0, err
	}
	c := pc.(*net.UDPConn)
	b.conn = c
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

func (b *deviceBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
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

func (b *deviceBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst := ep.(*sourceEndpoint).dst
	for _, buf := range bufs {
		if _, err := b.conn.WriteToUDPAddrPort(buf, dst); err != nil {
			return err
		}
	}
	return nil
}

func (b *deviceBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &sourceEndpoint{dst: addr}, nil
}

func (b *deviceBind) Close() error {
	if b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *deviceBind) SetMark(uint32) error { return nil }

func (b *deviceBind) BatchSize() int { return 1 }

func (e *sourceEndpoint) ClearSrc()           {}
func (e *sourceEndpoint) SrcToString() string { return "" }
func (e *sourceEndpoint) DstToString() string { return e.dst.String() }
func (e *sourceEndpoint) DstToBytes() []byte  { b, _ := e.dst.MarshalBinary(); return b }
func (e *sourceEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *sourceEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
