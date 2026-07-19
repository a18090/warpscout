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
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

const (
	regBaseURL       = "https://api.cloudflareclient.com/v0a4005/reg"
	apiReachURL      = "https://api.cloudflareclient.com/"
	apiHost          = "api.cloudflareclient.com"
	cfClientVersion  = "a-6.11-2223"
	cfUserAgent      = "okhttp/3.12.1"
	defaultAccount   = "warpscout-account.json"
	defaultWARPAddr  = "172.16.0.2"
	apiReachTimeout  = 3 * time.Second
	registerTimeout  = 15 * time.Second
	tunnelDialTimout = 10 * time.Second
)

// account is the registered WARP config persisted between runs. PrivateKey is
// ours (generateKeypair); PeerPublicKey comes from the /reg response.
type account struct {
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
	Address       string `json:"address"`
}

// generateKeypair replaces `wg genkey | wg pubkey`: a clamped Curve25519 private
// key and its derived public key, both base64.
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

// applyAccount overwrites the WARP config vars (warp.go) so tunnels built
// afterwards use the registered keys.
func applyAccount(a account) {
	warpPrivateKey = a.PrivateKey
	warpPublicKey = a.PeerPublicKey
	if a.Address != "" {
		warpAddress = a.Address
	}
}

// regResp captures the fields we need from POST /reg (top-level, no envelope).
type regResp struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
	} `json:"config"`
}

// parseRegResp turns a /reg response body plus our private key into an account.
func parseRegResp(body []byte, privateKey string) (account, string, string, error) {
	var r regResp
	if err := json.Unmarshal(body, &r); err != nil {
		return account{}, "", "", fmt.Errorf("parse reg response: %w", err)
	}
	if len(r.Config.Peers) == 0 || r.Config.Peers[0].PublicKey == "" {
		return account{}, "", "", fmt.Errorf("reg response missing peer public key")
	}
	addr := strings.TrimSuffix(r.Config.Interface.Addresses.V4, "/32")
	if addr == "" {
		addr = defaultWARPAddr
	}
	a := account{
		PrivateKey:    privateKey,
		PeerPublicKey: r.Config.Peers[0].PublicKey,
		Address:       addr,
	}
	return a, r.ID, r.Token, nil
}

// registerWARP runs the two-request flow from REG.md over the given client
// (direct, via proxy, or through a WARP tunnel).
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
	a, id, token, err := parseRegResp(body, priv)
	if err != nil {
		return account{}, err
	}

	patchURL := fmt.Sprintf("%s/%s", regBaseURL, id)
	if _, err := doJSON(ctx, client, http.MethodPatch, patchURL, token,
		map[string]bool{"warp_enabled": true}); err != nil {
		return account{}, fmt.Errorf("PATCH /reg/%s: %w", id, err)
	}
	return a, nil
}

// doJSON sends a JSON request with the WARP client headers and returns the body.
// A non-empty token adds the Bearer authorization header.
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
	// calibration knob: if the API answers 403, adjust these client headers.
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

// apiReachable reports whether the registration API answers TLS at all (any
// status, even 404, means we can reach it).
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

// proxyClient builds a client that routes through an http(s) or socks5 proxy.
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

// tunnelClient builds a client whose connections go through an established WARP
// tunnel, dialing the API host by IP (no in-tunnel DNS).
func tunnelClient(tnet *netstack.Net) (*http.Client, error) {
	// ponytail: OS-resolve the API host; if DNS is poisoned, swap for DoH via 1.1.1.1.
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
