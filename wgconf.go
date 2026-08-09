package main

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
)

func renderConf(o options, endpoint string, run protoRun) string {
	var b strings.Builder

	// A .conf cannot express the chain - the client builds it - so the inner
	// tunnel of a nested run says so instead of silently exiting somewhere else.
	if outer != nil {
		fmt.Fprintf(&b, "# Inner tunnel of a WARP-in-WARP chain: it only reaches the region\n")
		fmt.Fprintf(&b, "# it was scanned in when run over %s.\n\n", outer.label)
	}

	fmt.Fprintf(&b, "[Interface]\n")
	if o.ipv6 {
		fmt.Fprintf(&b, "Address = %s/128\n", warpAddressV6)
	} else {
		fmt.Fprintf(&b, "Address = %s/32\n", warpAddress)
	}
	fmt.Fprintf(&b, "PrivateKey = %s\n", warpPrivateKey)
	if dns := confDNS(o); dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	if o.mtu > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", o.mtu)
	}
	if o.tableOff {
		fmt.Fprintf(&b, "Table = off\n")
	}
	if run.isAWG() {
		fmt.Fprintf(&b, "Jc = %d\n", awgJc)
		fmt.Fprintf(&b, "Jmin = %d\n", awgJmin)
		fmt.Fprintf(&b, "Jmax = %d\n", awgJmax)
		if awgI1 != "" {
			fmt.Fprintf(&b, "I1 = %s\n", awgI1)
		}
	}

	fmt.Fprintf(&b, "\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", warpPublicKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowedIPs(o.ipv6))
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepalive)

	return b.String()
}

// Routing a family the interface carries no address for only blackholes it, so
// AllowedIPs follows -6 the same way Address does.
func allowedIPs(ipv6 bool) string {
	if ipv6 {
		return "::/0"
	}
	return "0.0.0.0/0"
}

const confStdout = "-"

func writeConf(o options, endpoint string, run protoRun) error {
	conf, err := renderConfFor(o, endpoint, run)
	if err != nil {
		return err
	}
	if o.conf == confStdout {
		_, err := os.Stdout.Write(conf)
		return err
	}
	return os.WriteFile(o.conf, conf, 0600)
}

func renderConfFor(o options, endpoint string, run protoRun) ([]byte, error) {
	if o.confType == confTypeMihomo {
		return renderMihomoConf(o, endpoint, run)
	}
	if run.isMASQUE() {
		return renderMasqueConf(endpoint, run.isH2())
	}
	return []byte(renderConf(o, endpoint, run)), nil
}

const (
	confTypeNative = "native"
	confTypeMihomo = "mihomo"
)

var confTypes = []string{confTypeNative, confTypeMihomo}

const (
	warpDNSv4 = "1.1.1.1, 1.0.0.1"
	warpDNSv6 = "2606:4700:4700::1111, 2606:4700:4700::1001"
)

func confDNS(o options) string {
	if o.noDNS {
		return ""
	}
	if o.dns != "" {
		return o.dns
	}
	if o.ipv6 {
		return warpDNSv6
	}
	return warpDNSv4
}

func mihomoAddr(b *strings.Builder, v4, v6 string, ipv6 bool) {
	if ipv6 {
		fmt.Fprintf(b, "  ipv6: %s\n", v6)
		return
	}
	fmt.Fprintf(b, "  ip: %s\n", v4)
}

// mihomo lists proxies by name, so several warpscout configs pasted into one
// file have to differ by protocol. The endpoint address stays out of it: the run
// already picked the single best one, and the name would go stale on the next scan.
func mihomoName(run protoRun) string {
	switch run.kind {
	case kindAWG:
		return "AWG WARP"
	case kindMASQUE:
		return "MASQUE H3 WARP"
	case kindMASQUEH2:
		return "MASQUE H2 WARP"
	}
	return "WG WARP"
}

const mihomoOuterSuffix = " OUTER"

func renderMihomoConf(o options, endpoint string, run protoRun) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "proxies:\n")

	if outer == nil {
		block, err := mihomoProxy(o, mihomoName(run), endpoint, run, o.mtu, confDNS(o))
		if err != nil {
			return nil, err
		}
		b.WriteString(indentBlock(block))
		return []byte(b.String()), nil
	}

	// mihomo expresses the chain itself: the outer tunnel is a proxy of its own
	// and the inner one dials through it. The outer carries no DNS - it is only
	// the carrier, and the resolvers belong at the end of the chain.
	outerName := mihomoName(outer.run) + mihomoOuterSuffix
	var block string
	err := withOuterKeys(func() error {
		var err error
		block, err = mihomoProxy(o, outerName, outer.endpoint, outer.run, o.mtu, "")
		return err
	})
	if err != nil {
		return nil, err
	}
	b.WriteString(indentBlock(block))

	block, err = mihomoProxy(o, mihomoName(run), endpoint, run, nestedMTU(o.mtu), confDNS(o))
	if err != nil {
		return nil, err
	}
	b.WriteString(indentBlock(block + fmt.Sprintf("  dialer-proxy: \"%s\"\n", outerName)))
	return []byte(b.String()), nil
}

// The proxy writers lay a block out at column 0; the sequence itself sits under
// proxies:, so every line of it moves right by one level.
func indentBlock(s string) string {
	return "  " + strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n  ") + "\n"
}

// The inner WireGuard packet rides as UDP inside the outer tunnel, so it cannot
// be left at the client's default: at full MTU the handshake still completes and
// data dies silently (the same nestedOverhead tunnel.go subtracts).
func nestedMTU(mtu int) int {
	if mtu == 0 {
		mtu = tunnelMTU
	}
	return mtu - nestedOverhead
}

func mihomoProxy(o options, name, endpoint string, run protoRun, mtu int, dns string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}

	b := &strings.Builder{}
	fmt.Fprintf(b, "- name: \"%s\"\n", name)
	fmt.Fprintf(b, "  server: %s\n", host)
	fmt.Fprintf(b, "  port: %s\n", port)
	if err := mihomoPeer(b, run, o.ipv6); err != nil {
		return "", err
	}
	if mtu > 0 {
		fmt.Fprintf(b, "  mtu: %d\n", mtu)
	}
	fmt.Fprintf(b, "  udp: true\n")
	if dns != "" {
		fmt.Fprintf(b, "  remote-dns-resolve: true\n")
		fmt.Fprintf(b, "  dns: [%s]\n", dns)
	}
	return b.String(), nil
}

func mihomoPeer(b *strings.Builder, run protoRun, ipv6 bool) error {
	if run.isMASQUE() {
		if masqueAcct == nil {
			return fmt.Errorf("no MASQUE device in the account file")
		}
		pub, err := pemBody(masqueAcct.PeerPublicKey)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "  type: masque\n")
		// mihomo's default is HTTP/3; the TCP transport is the same type with a
		// network selector rather than a type of its own.
		if run.isH2() {
			fmt.Fprintf(b, "  network: h2\n")
		}
		fmt.Fprintf(b, "  sni: %s\n", masqueSNI)
		fmt.Fprintf(b, "  private-key: %s\n", masqueAcct.PrivateKey)
		fmt.Fprintf(b, "  public-key: %s\n", pub)
		mihomoAddr(b, masqueAcct.IPv4, masqueAcct.IPv6, ipv6)
		return nil
	}

	fmt.Fprintf(b, "  type: wireguard\n")
	fmt.Fprintf(b, "  private-key: %s\n", warpPrivateKey)
	fmt.Fprintf(b, "  public-key: %s\n", warpPublicKey)
	mihomoAddr(b, warpAddress, warpAddressV6, ipv6)
	fmt.Fprintf(b, "  allowed-ips: ['%s']\n", allowedIPs(ipv6))
	if !run.isAWG() {
		return nil
	}
	fmt.Fprintf(b, "  amnezia-wg-option:\n")
	fmt.Fprintf(b, "    jc: %d\n", awgJc)
	fmt.Fprintf(b, "    jmin: %d\n", awgJmin)
	fmt.Fprintf(b, "    jmax: %d\n", awgJmax)
	fmt.Fprintf(b, "    s1: 0\n")
	fmt.Fprintf(b, "    s2: 0\n")
	for i, h := range []int{1, 2, 3, 4} {
		fmt.Fprintf(b, "    h%d: %d\n", i+1, h)
	}
	if awgI1 != "" {
		fmt.Fprintf(b, "    i1: %s\n", awgI1)
	}
	return nil
}

func pemBody(key string) (string, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return "", fmt.Errorf("peer public key is not PEM")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}
