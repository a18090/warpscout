package main

import (
	"net/netip"
	"strconv"
)

// WARP endpoint pools (ported from warp_colo_check.sh POOLS). For each /24 base
// every last octet 0..255 is probed.
var pools = []string{
	"8.47.69.",
	"162.159.192.",
	"162.159.195.",
	"188.114.96.",
	"188.114.97.",
	"188.114.98.",
	"188.114.99.",
}

// expandPools returns every /24 host address across all pools.
func expandPools() []netip.Addr {
	ips := make([]netip.Addr, 0, len(pools)*256)
	for _, base := range pools {
		for octet := 0; octet < 256; octet++ {
			addr, err := netip.ParseAddr(base + strconv.Itoa(octet))
			if err != nil {
				continue
			}
			ips = append(ips, addr)
		}
	}
	return ips
}
