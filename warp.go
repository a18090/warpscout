package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Hardcoded WARP config (see DESC.md). Registration/wgcf comes later.
const (
	warpPrivateKey = "4OnO86dDLpqJ2U10ODwX3tarx6xlRGLfkmbSBtMgaHg="
	warpPublicKey  = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	warpAddress    = "172.16.0.2"
	tunnelMTU      = 1280
	keepalive      = 25
)

// AmneziaWG junk parameters (see DESC.md). Empty for plain WireGuard.
const (
	awgJc   = 6
	awgJmin = 10
	awgJmax = 50
	awgI1   = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"
)

// Candidate WARP UDP ports, tried in order until one completes a handshake.
// ponytail: single known port for now; extend the slice when more are discovered.
var warpPorts = []int{2408}

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
