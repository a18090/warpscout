package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Registration (register.go) overwrites these in place, so var not const.
var (
	warpPrivateKey = "4OnO86dDLpqJ2U10ODwX3tarx6xlRGLfkmbSBtMgaHg="
	warpPublicKey  = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	warpAddress    = "172.16.0.2"
)

const (
	tunnelMTU = 1280
	keepalive = 25
)

// -jc/-jmin/-jmax/-i1 override these in place (flags.go), so var not const.
var (
	awgJc   = 6
	awgJmin = 10
	awgJmax = 50
	awgI1   = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"
)

// Phase 1 probes primaryWarpPorts first; the extended set (alternate UDP ports
// Cloudflare also serves, from CloudflareWarpSpeedTest) is only swept when no
// primary port gets through, so a restrictive network still has a chance without
// making every scan pay 50 extra per-port timeouts. warpPorts holds the ports
// phase 1 found open and is what phase 2 iterates.
var (
	primaryWarpPorts  = []int{2408, 500, 1701, 4500}
	extendedWarpPorts = []int{
		854, 859, 864, 878, 880, 890, 891, 894, 903, 908,
		928, 934, 939, 942, 943, 945, 946, 955, 968, 987,
		988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843,
		2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279,
		5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
	}
	warpPorts = primaryWarpPorts
)

func base64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func baseUAPI(awg bool) (string, error) {
	privHex, err := base64ToHex(warpPrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	if awg {
		fmt.Fprintf(&b, "jc=%d\n", awgJc)
		fmt.Fprintf(&b, "jmin=%d\n", awgJmin)
		fmt.Fprintf(&b, "jmax=%d\n", awgJmax)
		fmt.Fprintf(&b, "i1=%s\n", awgI1)
	}
	return b.String(), nil
}

func peerUAPI(endpoint string) (string, error) {
	pubHex, err := base64ToHex(warpPublicKey)
	if err != nil {
		return "", fmt.Errorf("public key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pubHex)
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	return b.String(), nil
}

type protoRun struct {
	awg  bool
	name string
}

func parseProto(p string) ([]protoRun, error) {
	wg := protoRun{false, "wg"}
	awg := protoRun{true, "awg"}
	switch p {
	case "wg":
		return []protoRun{wg}, nil
	case "awg":
		return []protoRun{awg}, nil
	case "both":
		return []protoRun{wg, awg}, nil
	default:
		return nil, fmt.Errorf("invalid -proto %q: use wg, awg or both", p)
	}
}

func protoName(awg bool) string {
	if awg {
		return "awg"
	}
	return "wg"
}
