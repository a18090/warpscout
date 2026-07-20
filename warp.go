package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// WARP config. These are hardcoded fallbacks (see DESC.md); registration
// (register.go) overwrites them in place with a freshly registered config
// before phase 2, so they are vars, not consts.
var (
	warpPrivateKey = "4OnO86dDLpqJ2U10ODwX3tarx6xlRGLfkmbSBtMgaHg="
	warpPublicKey  = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	warpAddress    = "172.16.0.2"
)

const (
	tunnelMTU = 1280
	keepalive = 25
)

// AmneziaWG junk parameters (see DESC.md). Empty for plain WireGuard.
const (
	awgJc   = 6
	awgJmin = 10
	awgJmax = 50
	awgI1   = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"
)

// Candidate WARP UDP ports (the endpoint.ports list from a /reg response), tried
// in order until one completes a handshake. Phase 1 (reachablePorts) narrows this
// to the ports that get through the current network before phase 2 scans.
var warpPorts = []int{2408, 500, 1701, 4500}

func base64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// baseUAPI produces the interface-only IpcSet string, applied once when a tunnel
// is created. awg=true adds the junk parameters that turn the plain WireGuard
// handshake into an AmneziaWG one.
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

// peerUAPI produces the per-endpoint IpcSet delta. replace_peers clears the
// previous peer and its handshake state so a fresh handshake initiates to the
// new endpoint; the interface's private_key persists across the delta.
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

// protoRun is one protocol to verify endpoints with.
type protoRun struct {
	awg  bool
	name string
}

// parseProto expands -proto into the ordered list of runs. "both" verifies wg
// first (preferred, no obfuscation) then awg.
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
