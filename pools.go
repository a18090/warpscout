package main

import (
	"math/rand"
	"net/netip"
)

var poolsV4 = []netip.Prefix{
	netip.MustParsePrefix("8.47.69.0/24"),
	netip.MustParsePrefix("162.159.192.0/24"),
	netip.MustParsePrefix("162.159.195.0/24"),
	netip.MustParsePrefix("188.114.96.0/24"),
	netip.MustParsePrefix("188.114.97.0/24"),
	netip.MustParsePrefix("188.114.98.0/24"),
	netip.MustParsePrefix("188.114.99.0/24"),
}

var poolsV6 = []netip.Prefix{
	netip.MustParsePrefix("2606:4700:d0::/48"),
	netip.MustParsePrefix("2606:4700:d1::/48"),
}

var pools = poolsV4

func expandPools(perSubnet int) []netip.Addr {
	var ips []netip.Addr
	for _, p := range pools {
		if p.Addr().Is4() {
			ips = append(ips, expandV4(p, perSubnet)...)
			continue
		}
		ips = append(ips, expandV6(p, perSubnet)...)
	}
	return ips
}

func expandV4(p netip.Prefix, perSubnet int) []netip.Addr {
	full := perSubnet <= 0 || perSubnet >= 256
	octets := make([]int, 256)
	for i := range octets {
		octets[i] = i
	}
	if !full {
		rand.Shuffle(len(octets), func(i, j int) { octets[i], octets[j] = octets[j], octets[i] })
		octets = octets[:perSubnet]
	}
	base := p.Addr().As4()
	ips := make([]netip.Addr, 0, len(octets))
	for _, octet := range octets {
		base[3] = byte(octet)
		ips = append(ips, netip.AddrFrom4(base))
	}
	return ips
}

func expandV6(p netip.Prefix, perSubnet int) []netip.Addr {
	count := perSubnet
	if count <= 0 || count >= 256 {
		count = 256
	}
	base := p.Addr().As16()
	ips := make([]netip.Addr, 0, count)
	for i := 0; i < count; i++ {
		a := base
		// ponytail: random low 64 bits, mirrors upstream endpoint6() (hextet 4 stays 0)
		for b := 8; b < 16; b++ {
			a[b] = byte(rand.Intn(256))
		}
		ips = append(ips, netip.AddrFrom16(a))
	}
	return ips
}
