package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/api"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Values the official client uses, copied from Diniboy1123/usque (internal/, so
// not importable). The SNI never matches the endpoint address, which is why
// usque pins the peer's public key instead of verifying the certificate.
const (
	masqueConnectURI = "https://cloudflareaccess.com"
	masqueDefaultSNI = "consumer-masque.cloudflareclient.com"
	masqueKeepalive  = 30 * time.Second
	// Cloudflare never signs the client certificate: it only carries the key
	// enrolled through the API, and that enrolment is the whole authentication.
	masqueCertLifetime = 24 * time.Hour
	// Headroom over the MTU so an oversized frame is read rather than truncated.
	masqueReadBuf = tunnelMTU + 128
	// The same endpoint with the same SNI answers on one attempt and times out on
	// the next, so a single failure says nothing. Measured on a filtered network,
	// same endpoints and same SNI: one try scored 1-3 of 14 working, three tries
	// scored 11-13. Below this the scan reports mostly false negatives.
	masqueDefaultAttempts = 3
)

// MASQUE is served from two anycast addresses per family, not from the WireGuard
// pools: measured, every other address in 162.159.198.0/24 and every wg pool
// address answers QUIC but rejects the TLS handshake outright.
var (
	masquePoolsV4 = []netip.Prefix{
		netip.MustParsePrefix("162.159.198.1/32"),
		netip.MustParsePrefix("162.159.198.2/32"),
	}
	masquePoolsV6 = []netip.Prefix{
		netip.MustParsePrefix("2606:4700:103::1/128"),
		netip.MustParsePrefix("2606:4700:103::2/128"),
	}
)

// The API hands this list out per account, but it is the same everywhere and
// usque's own config.json has no port field at all, so it is a constant.
var masqueEndpointPorts = []int{443, 500, 1701, 4500, 4443, 8443, 8095}

// Set by applyAccount, like warpPrivateKey for the WireGuard family.
var masqueAcct *masqueAccount

// -masque-attempts overrides this.
var masqueAttempts = masqueDefaultAttempts

// -masque-sni overrides this. The endpoint never matches the SNI anyway and the
// peer is pinned by public key, so the name is free to be anything DPI lets
// through - the MASQUE equivalent of the AmneziaWG init packet.
var masqueSNI = masqueDefaultSNI

// The MASQUE flow lives on its own API version with its own client headers, and
// registers in two steps: POST /reg mints a device the same way the Android
// client does, PATCH /reg/{id} swaps its key for an ECDSA one and switches the
// tunnel type. Done through warpscout's own doJSON rather than usque's api
// package so -proxy, -interface and the tunnel fallback keep working.
const (
	masqueRegURL           = "https://api.cloudflareclient.com/v0a4471/reg"
	masqueClientVersion    = "a-6.35-4471"
	masqueUserAgent        = "WARP for Android"
	masqueKeyType          = "secp256r1"
	masqueTunnelType       = "masque"
	masqueRegKeyType       = "curve25519"
	masqueRegTunnelType    = "wireguard"
	masqueRegModel         = "PC"
	masqueRegLocale        = "en_US"
	masqueRegDeviceName    = "warpscout"
	masqueRegOSVersion     = "10"
	masqueRegSerialNumLen  = 8
	masqueRegPlaceholderKB = 32
)

type masqueRegResp struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func randomB64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func registerMasque(ctx context.Context, client *http.Client) (*masqueAccount, error) {
	// The first registration must look like a stock WireGuard enrolment - the
	// key here is a throwaway the API only checks the shape of.
	placeholder, err := randomB64(masqueRegPlaceholderKB)
	if err != nil {
		return nil, err
	}
	serial, err := randomB64(masqueRegSerialNumLen)
	if err != nil {
		return nil, err
	}
	body, err := doJSONAs(ctx, client, http.MethodPost, masqueRegURL, "",
		masqueUserAgent, masqueClientVersion, map[string]any{
			"key":           placeholder,
			"install_id":    "",
			"fcm_token":     "",
			"tos":           time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			"model":         masqueRegModel,
			"serial_number": serial,
			"os_version":    masqueRegOSVersion,
			"key_type":      masqueRegKeyType,
			"tunnel_type":   masqueRegTunnelType,
			"locale":        masqueRegLocale,
		})
	if err != nil {
		return nil, fmt.Errorf("POST /reg: %w", err)
	}
	var first masqueRegResp
	if err := json.Unmarshal(body, &first); err != nil {
		return nil, fmt.Errorf("parse masque reg response: %w", err)
	}
	if first.ID == "" || first.Token == "" {
		return nil, fmt.Errorf("masque reg response missing id or token")
	}

	privDER, pubDER, err := genECKeyPair()
	if err != nil {
		return nil, err
	}
	body, err = doJSONAs(ctx, client, http.MethodPatch, masqueRegURL+"/"+first.ID, first.Token,
		masqueUserAgent, masqueClientVersion, map[string]string{
			"key":         base64.StdEncoding.EncodeToString(pubDER),
			"key_type":    masqueKeyType,
			"tunnel_type": masqueTunnelType,
			"name":        masqueRegDeviceName,
		})
	if err != nil {
		return nil, fmt.Errorf("PATCH /reg/%s: %w", first.ID, err)
	}
	var enrolled masqueRegResp
	if err := json.Unmarshal(body, &enrolled); err != nil {
		return nil, fmt.Errorf("parse masque enrol response: %w", err)
	}
	if len(enrolled.Config.Peers) == 0 || enrolled.Config.Peers[0].PublicKey == "" {
		return nil, fmt.Errorf("masque enrol response missing peer public key")
	}
	return &masqueAccount{
		ID:            first.ID,
		Token:         first.Token,
		PrivateKey:    base64.StdEncoding.EncodeToString(privDER),
		PeerPublicKey: enrolled.Config.Peers[0].PublicKey,
		IPv4:          enrolled.Config.Interface.Addresses.V4,
		IPv6:          enrolled.Config.Interface.Addresses.V6,
	}, nil
}

func genECKeyPair() (privDER, pubDER []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if privDER, err = x509.MarshalECPrivateKey(priv); err != nil {
		return nil, nil, err
	}
	if pubDER, err = x509.MarshalPKIXPublicKey(&priv.PublicKey); err != nil {
		return nil, nil, err
	}
	return privDER, pubDER, nil
}

func selfSignedCert(priv *ecdsa.PrivateKey) ([][]byte, error) {
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(masqueCertLifetime),
	}, &x509.Certificate{}, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return [][]byte{der}, nil
}

func (a masqueAccount) tlsConfig() (*tls.Config, error) {
	privDER, err := base64.StdEncoding.DecodeString(a.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("masque private key: %w", err)
	}
	priv, err := x509.ParseECPrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("masque private key: %w", err)
	}
	block, _ := pem.Decode([]byte(a.PeerPublicKey))
	if block == nil {
		return nil, fmt.Errorf("masque peer public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("masque peer public key: %w", err)
	}
	peerPub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("masque peer public key is not ECDSA")
	}
	cert, err := selfSignedCert(priv)
	if err != nil {
		return nil, err
	}
	return api.PrepareTlsConfig(priv, peerPub, cert, masqueSNI)
}

func (a masqueAccount) localAddrs() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range []string{a.IPv4, a.IPv6} {
		if addr, err := netip.ParseAddr(s); err == nil {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("masque account carries no interface address")
	}
	return out, nil
}

// MASQUE has no wg-style .conf, so -conf writes the config.json usque reads.
// The endpoint the scan picked goes in as the v4 or v6 endpoint depending on its
// own family; the other one is left as usque's own default.
type usqueConf struct {
	PrivateKey     string `json:"private_key"`
	EndpointV4     string `json:"endpoint_v4"`
	EndpointV6     string `json:"endpoint_v6"`
	EndpointPubKey string `json:"endpoint_pub_key"`
	ID             string `json:"id"`
	AccessToken    string `json:"access_token"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`
}

func renderMasqueConf(endpoint string) ([]byte, error) {
	if masqueAcct == nil {
		return nil, fmt.Errorf("no MASQUE device in the account file")
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	c := usqueConf{
		PrivateKey:     masqueAcct.PrivateKey,
		EndpointV4:     masquePoolsV4[len(masquePoolsV4)-1].Addr().String(),
		EndpointV6:     masquePoolsV6[len(masquePoolsV6)-1].Addr().String(),
		EndpointPubKey: masqueAcct.PeerPublicKey,
		ID:             masqueAcct.ID,
		AccessToken:    masqueAcct.Token,
		IPv4:           masqueAcct.IPv4,
		IPv6:           masqueAcct.IPv6,
	}
	if addr.Is4() {
		c.EndpointV4 = host
	} else {
		c.EndpointV6 = host
	}
	return json.MarshalIndent(c, "", "  ")
}

// The netstack side outlives any single peer: handshake swaps the CONNECT-IP
// connection underneath it, exactly like IpcSet swaps the WireGuard peer.
type masqueTunnel struct {
	*ipStack
	dev    tun.Device
	tlsCfg *tls.Config

	mu   sync.Mutex
	conn *connectip.Conn
	drop func()
}

// quic-go and connect-ip-go write straight to the standard logger - a receive
// buffer warning, then a line per closed stream, and every endpoint swap closes
// one. warpscout never uses that logger itself, so the whole thing is muted
// rather than left to scribble over the live dashboard.
var muteLibLog sync.Once

func newMasqueTunnel() (*masqueTunnel, error) {
	muteLibLog.Do(func() { log.SetOutput(io.Discard) })
	if masqueAcct == nil {
		return nil, fmt.Errorf("no MASQUE device in the account file: run \"warpscout register\" again")
	}
	tlsCfg, err := masqueAcct.tlsConfig()
	if err != nil {
		return nil, err
	}
	local, err := masqueAcct.localAddrs()
	if err != nil {
		return nil, err
	}
	dev, stack, err := newIPStack(local)
	if err != nil {
		return nil, err
	}

	t := &masqueTunnel{ipStack: stack, dev: dev, tlsCfg: tlsCfg}
	go t.pumpOut()
	return t, nil
}

func (t *masqueTunnel) ports() []int    { return masqueEndpointPorts }
func (t *masqueTunnel) attempts() int   { return masqueAttempts }
func (t *masqueTunnel) stack() *ipStack { return t.ipStack }

func (t *masqueTunnel) Close() {
	t.dropPeer()
	t.dev.Close()
}

func (t *masqueTunnel) dropPeer() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.drop != nil {
		t.drop()
		t.drop = nil
	}
	t.conn = nil
}

func (t *masqueTunnel) currentConn() *connectip.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn
}

// One reader for the whole tunnel: the netstack device is reused across peers,
// so a per-peer reader would be left blocked in dev.Read after a swap.
func (t *masqueTunnel) pumpOut() {
	buf := make([]byte, masqueReadBuf)
	bufs := [][]byte{buf}
	sizes := []int{0}
	for {
		if _, err := t.dev.Read(bufs, sizes, 0); err != nil {
			return
		}
		conn := t.currentConn()
		if conn == nil {
			continue
		}
		if _, err := conn.WritePacket(buf[:sizes[0]]); err != nil {
			continue
		}
	}
}

func (t *masqueTunnel) pumpIn(ctx context.Context, conn *connectip.Conn) {
	buf := make([]byte, masqueReadBuf)
	for ctx.Err() == nil {
		n, err := conn.ReadPacket(buf, true)
		if err != nil {
			return
		}
		if _, err := t.dev.Write([][]byte{buf[:n]}, 0); err != nil {
			return
		}
	}
}

// A successful dial is the MASQUE equivalent of the WireGuard handshake, but a
// weaker signal: measured on a filtered network, every endpoint dialled and only
// two passed data, so callers must still verify with /meta or a ping.
func (t *masqueTunnel) handshake(ctx context.Context, endpoint string, timeout time.Duration) bool {
	t.dropPeer()

	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return false
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, timeout)
	defer cancelDial()
	udpConn, tr, conn, _, err := api.ConnectTunnel(dialCtx, t.tlsCfg,
		&quic.Config{EnableDatagrams: true, KeepAlivePeriod: masqueKeepalive},
		masqueConnectURI, udpAddr)
	if err != nil {
		closeMasqueTransport(udpConn, tr, nil)
		return false
	}

	pumpCtx, cancelPump := context.WithCancel(context.Background())
	go t.pumpIn(pumpCtx, conn)

	t.mu.Lock()
	t.conn = conn
	t.drop = func() {
		cancelPump()
		closeMasqueTransport(udpConn, tr, conn)
	}
	t.mu.Unlock()
	return true
}

func closeMasqueTransport(udpConn *net.UDPConn, tr *http3.Transport, conn *connectip.Conn) {
	if conn != nil {
		conn.Close()
	}
	if tr != nil {
		tr.Close()
	}
	if udpConn != nil {
		udpConn.Close()
	}
}
