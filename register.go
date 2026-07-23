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

func proxyClient(proxyURL string) (*http.Client, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid -proxy %q: %w", proxyURL, err)
	}
	return &http.Client{
		Timeout:   registerTimeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}, nil
}

func tunnelClient(tnet *netstack.Net) (*http.Client, error) {
	ips, err := net.LookupHost(apiHost)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: %w", apiHost, err)
	}
	target := net.JoinHostPort(ips[0], "443")
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

func obtainAccount(ctx context.Context, awg bool, proxy string, ips []netip.Addr, timeout time.Duration) (account, error) {
	if proxy != "" {
		c, err := proxyClient(proxy)
		if err != nil {
			return account{}, err
		}
		return registerWARP(ctx, c)
	}

	fmt.Fprintln(os.Stderr, errPal.dim("Checking Cloudflare API availability..."))
	direct := &http.Client{Timeout: registerTimeout}
	if apiReachable(direct) {
		return registerWARP(ctx, direct)
	}

	fmt.Fprintf(os.Stderr, "\n%s\n\n", errPal.fail("API unreachable directly"))
	fmt.Fprintln(os.Stderr, errPal.dim("Registering through a WARP tunnel (pass -proxy to use a proxy instead)"))

	sampled := sampleAddrs(ips, tunnelDiscoverySample)
	var lastErr error
	for _, p := range []bool{awg, !awg} {
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("  probing %s endpoints...", protoName(p))))
		a, err := registerViaTunnel(ctx, p, sampled, timeout)
		if err == nil {
			return a, nil
		}
		fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("  %s: %v", protoName(p), err)))
		lastErr = err
	}
	return account{}, lastErr
}

// registerViaTunnel sweeps candidate endpoints and registers through the first
// that completes a handshake, reusing that live tunnel. The handshake is the only
// reachability test that survives the DPI which forced the tunnel fallback in the
// first place.
func registerViaTunnel(ctx context.Context, awg bool, ips []netip.Addr, timeout time.Duration) (account, error) {
	tn, err := newTunnel(awg)
	if err != nil {
		return account{}, err
	}
	defer tn.Close()

	ctx, cancel := context.WithTimeout(ctx, tunnelDiscoveryBudget)
	defer cancel()
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
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
