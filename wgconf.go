package main

import (
	"fmt"
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
	return os.WriteFile(o.conf, []byte(renderConf(o, endpoint, run)), 0600)
}
