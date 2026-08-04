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

	fmt.Fprintf(&b, "[Interface]\n")
	if o.ipv6 {
		fmt.Fprintf(&b, "Address = %s/128\n", warpAddressV6)
	} else {
		fmt.Fprintf(&b, "Address = %s/32\n", warpAddress)
	}
	fmt.Fprintf(&b, "PrivateKey = %s\n", warpPrivateKey)
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

func writeConf(o options, endpoint string, run protoRun) error {
	conf, err := renderConfFor(o, endpoint, run)
	if err != nil {
		return err
	}
	return os.WriteFile(o.conf, conf, 0600)
}

func renderConfFor(o options, endpoint string, run protoRun) ([]byte, error) {
	if o.confType == confTypeMihomo {
		return renderMihomoConf(o, endpoint, run)
	}
	if run.isMASQUE() {
		return renderMasqueConf(endpoint)
	}
	return []byte(renderConf(o, endpoint, run)), nil
}

const (
	confTypeNative = "native"
	confTypeMihomo = "mihomo"
)

var confTypes = []string{confTypeNative, confTypeMihomo}

const (
	mihomoDNSv4 = "[1.1.1.1, 1.0.0.1]"
	mihomoDNSv6 = "[2606:4700:4700::1111, 2606:4700:4700::1001]"
)

func mihomoDNS(ipv6 bool) string {
	if ipv6 {
		return mihomoDNSv6
	}
	return mihomoDNSv4
}

func mihomoAddr(b *strings.Builder, v4, v6 string, ipv6 bool) {
	if ipv6 {
		fmt.Fprintf(b, "  ipv6: %s\n", v6)
		return
	}
	fmt.Fprintf(b, "  ip: %s\n", v4)
}

func renderMihomoConf(o options, endpoint string, run protoRun) ([]byte, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("endpoint %q: %w", endpoint, err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "proxies:\n")
	fmt.Fprintf(&b, "- name: \"WARP %s\"\n", endpoint)
	fmt.Fprintf(&b, "  server: %s\n", host)
	fmt.Fprintf(&b, "  port: %s\n", port)
	if err := mihomoPeer(&b, run, o.ipv6); err != nil {
		return nil, err
	}
	if o.mtu > 0 {
		fmt.Fprintf(&b, "  mtu: %d\n", o.mtu)
	}
	fmt.Fprintf(&b, "  udp: true\n")
	fmt.Fprintf(&b, "  remote-dns-resolve: true\n")
	fmt.Fprintf(&b, "  dns: %s\n", mihomoDNS(o.ipv6))

	return []byte(b.String()), nil
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
