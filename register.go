package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/charmbracelet/bubbles/progress"
)

const (
	regBaseURL      = "https://api.cloudflareclient.com/v0a4005/reg"
	apiReachURL     = "https://api.cloudflareclient.com/"
	apiHost         = "api.cloudflareclient.com"
	cfClientVersion = "a-6.11-2223"
	cfUserAgent     = "okhttp/3.12.1"
	defaultAccount  = "warpscout-account.json"
	apiReachTimeout = 3 * time.Second
	registerTimeout = 15 * time.Second
	regTunnelMSS    = 1200
)

type account struct {
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
	ID            string `json:"id"`
	Token         string `json:"token"`
}

func generateKeypair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err = rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub), nil
}

func loadAccount(path string) (account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return account{}, err
	}
	var a account
	if err := json.Unmarshal(data, &a); err != nil {
		return account{}, err
	}
	if a.PrivateKey == "" || a.PeerPublicKey == "" {
		return account{}, fmt.Errorf("%s: incomplete account", path)
	}
	return a, nil
}

func saveAccount(path string, a account) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func applyAccount(a account) {
	warpPrivateKey = a.PrivateKey
	warpPublicKey = a.PeerPublicKey
}

type regResp struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
	} `json:"config"`
}

func parseRegResp(body []byte, privateKey string) (account, error) {
	var r regResp
	if err := json.Unmarshal(body, &r); err != nil {
		return account{}, fmt.Errorf("parse reg response: %w", err)
	}
	if len(r.Config.Peers) == 0 || r.Config.Peers[0].PublicKey == "" {
		return account{}, fmt.Errorf("reg response missing peer public key")
	}
	a := account{
		PrivateKey:    privateKey,
		PeerPublicKey: r.Config.Peers[0].PublicKey,
		ID:            r.ID,
		Token:         r.Token,
	}
	return a, nil
}

func registerWARP(ctx context.Context, client *http.Client) (account, error) {
	priv, pub, err := generateKeypair()
	if err != nil {
		return account{}, err
	}

	body, err := doJSON(ctx, client, http.MethodPost, regBaseURL, "",
		map[string]string{"key": pub})
	if err != nil {
		return account{}, fmt.Errorf("POST /reg: %w", err)
	}
	a, err := parseRegResp(body, priv)
	if err != nil {
		return account{}, err
	}

	patchURL := fmt.Sprintf("%s/%s", regBaseURL, a.ID)
	if _, err := doJSON(ctx, client, http.MethodPatch, patchURL, a.Token,
		map[string]bool{"warp_enabled": true}); err != nil {
		return account{}, fmt.Errorf("PATCH /reg/%s: %w", a.ID, err)
	}
	return a, nil
}

func doJSON(ctx context.Context, client *http.Client, method, urlStr, token string, payload any) ([]byte, error) {
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", cfUserAgent)
	req.Header.Set("CF-Client-Version", cfClientVersion)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

func apiReachable(client *http.Client) bool {
	ctx, cancel := context.WithTimeout(context.Background(), apiReachTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiReachURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func regTransport(proxy *url.URL) *http.Transport {
	d := &net.Dialer{}
	t := &http.Transport{DialContext: d.DialContext}
	if scanInterface != "" {
		d.Control = deviceControl(scanInterface, regTunnelMSS)
		// Force the interface's address family: a v6 dial through a v4-only tun
		// (or vice versa) blackholes, so pin the network to what the interface carries.
		network := "tcp4"
		if scanSourceIP.Is6() {
			network = "tcp6"
		}
		t.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}
	}
	if proxy != nil {
		t.Proxy = http.ProxyURL(proxy)
	}
	return t
}

func proxyClient(proxyURL string) (*http.Client, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid -proxy %q: %w", proxyURL, err)
	}
	return &http.Client{
		Timeout:   registerTimeout,
		Transport: regTransport(u),
	}, nil
}

func resolveIPv4(host string) (string, error) {
	ips, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no IPv4 address for %s", host)
}

func tunnelClient(tnet *netstack.Net) (*http.Client, error) {
	// The netstack tunnel only has a v4 address (warpAddress), so the API must be
	// dialed over IPv4 - a v6 target picked from LookupHost would blackhole.
	ip, err := resolveIPv4(apiHost)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", apiHost, err)
	}
	target := net.JoinHostPort(ip, "443")
	return &http.Client{
		Timeout: registerTimeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return tnet.DialContext(ctx, "tcp", target)
			},
		},
	}, nil
}

const tunnelDiscoverySample = 64

const tunnelDiscoveryBudget = 40 * time.Second

func obtainAccount(ctx context.Context, awg bool, proxy string, ips []netip.Addr, timeout time.Duration, plain bool) (account, error) {
	if proxy != "" {
		c, err := proxyClient(proxy)
		if err != nil {
			return account{}, err
		}
		return registerWARP(ctx, c)
	}

	fmt.Fprintln(os.Stderr, errPal.dim("Checking Cloudflare API availability..."))
	direct := &http.Client{Timeout: registerTimeout, Transport: regTransport(nil)}
	if apiReachable(direct) {
		return registerWARP(ctx, direct)
	}

	fmt.Fprintf(os.Stderr, "\n%s\n\n", errPal.fail("API unreachable directly"))
	fmt.Fprintln(os.Stderr, errPal.dim("Registering through a WARP tunnel (pass -proxy to use a proxy instead)"))

	sampled := sampleAddrs(ips, tunnelDiscoverySample)
	var lastErr error
	for _, p := range []bool{awg, !awg} {
		onProbe := discoveryProgress(protoName(p), len(sampled), plain)
		a, err := registerViaTunnel(ctx, p, sampled, timeout, onProbe)
		if onProbe != nil {
			fmt.Fprintln(os.Stderr)
		}
		if err == nil {
			return a, nil
		}
		fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("  %s: %v", protoName(p), err)))
		lastErr = err
	}
	return account{}, lastErr
}

const discoveryBarWidth = 28

// discoveryProgress returns an onProbe callback that renders an inline bar to
// stderr as endpoints are probed. In plain (non-TTY) mode it prints a single
// static line and returns nil, since a redrawing bar needs a terminal.
func discoveryProgress(proto string, total int, plain bool) func(probed int) {
	label := fmt.Sprintf("probing %s endpoints", proto)
	if plain {
		fmt.Fprintf(os.Stderr, "  %s...\n", label)
		return nil
	}
	bar := progress.New(progress.WithDefaultGradient(), progress.WithWidth(discoveryBarWidth))
	return func(probed int) {
		fmt.Fprintf(os.Stderr, "\r\033[K  %s %s", label, bar.ViewAs(float64(probed)/float64(total)))
	}
}

// registerViaTunnel sweeps candidate endpoints (reporting progress) and registers
// through the first that completes a handshake, reusing that live tunnel. The
// handshake is the only reachability test that survives the DPI which forced the
// tunnel fallback in the first place.
func registerViaTunnel(ctx context.Context, awg bool, ips []netip.Addr, timeout time.Duration, onProbe func(probed int)) (account, error) {
	tn, err := newTunnel(awg)
	if err != nil {
		return account{}, err
	}
	defer tn.Close()

	ctx, cancel := context.WithTimeout(ctx, tunnelDiscoveryBudget)
	defer cancel()
	for i, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		if onProbe != nil {
			onProbe(i + 1)
		}
		if !tn.connect(ctx, ip, timeout) {
			continue
		}
		client, err := tunnelClient(tn.tnet)
		if err != nil {
			return account{}, err
		}
		return registerWARP(ctx, client)
	}
	return account{}, fmt.Errorf("no reachable endpoint")
}
