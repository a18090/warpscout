package main

import (
	"math/rand"
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

// expandPools returns host addresses across all pools. With perSubnet <= 0 or
// >= 256 it returns every /24 host (full scan); otherwise it returns perSubnet
// random hosts from each /24.
func expandPools(perSubnet int) []netip.Addr {
	full := perSubnet <= 0 || perSubnet >= 256
	perPool := 256
	if !full {
		perPool = perSubnet
	}
	ips := make([]netip.Addr, 0, len(pools)*perPool)
	for _, base := range pools {
		octets := make([]int, 256)
		for i := range octets {
			octets[i] = i
		}
		if !full {
			rand.Shuffle(len(octets), func(i, j int) { octets[i], octets[j] = octets[j], octets[i] })
			octets = octets[:perSubnet]
		}
		for _, octet := range octets {
			addr, err := netip.ParseAddr(base + strconv.Itoa(octet))
			if err != nil {
				continue
			}
			ips = append(ips, addr)
		}
	}
	return ips
}
