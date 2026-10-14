package signal

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

var b64 = base64.RawURLEncoding

// helloTURN says hello and returns what the client signs with.
func helloTURN(t *testing.T, c *websocket.Conn) (helloAt int64, connNonce [32]byte) {
	t.Helper()
	send(t, c, message{"t": "hello", "v": 1})
	m := receive(t, c, "hello_ok")
	n, err := b64.DecodeString(m["connNonce"].(string))
	if err != nil || len(n) != 32 {
		t.Fatalf("connNonce: %v", m)
	}
	copy(connNonce[:], n)
	return int64(m["serverTime"].(float64)), connNonce
}

func turnRequest(sk ed25519.PrivateKey, helloAt int64, connNonce [32]byte) message {
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	sig := ed25519.Sign(sk, turnSigned(nonce, helloAt, connNonce))
	return message{"t": "turn_credentials", "pk": b64.EncodeToString(sk.Public().(ed25519.PublicKey)), "nonce": b64.EncodeToString(nonce), "sig": b64.EncodeToString(sig)}
}

func withTURN(c *Config) {
	c.STUNURLs = []string{"stun:stun.example:3478"}
	c.TURNURLs = []string{"turn:turn-a.example:3478?transport=udp", "turns:turn-a.example:443?transport=tcp"}
	c.TURNSecret = []byte("0123456789abcdef-static-secret")
}

// 04 §4.3: a signed request gets a coturn REST credential with a random
// username, the configured URLs and no invented quota.
func TestTURNCredentialsAreIssuedForASignedRequest(t *testing.T) {
	_, url := fixture(t, withTURN)
	c := dial(t, url)
	at, n := helloTURN(t, c)
	_, sk, _ := ed25519.GenerateKey(nil)
	send(t, c, turnRequest(sk, at, n))
	m := receive(t, c, "turn_credentials_ok")
	user := m["username"].(string)
	exp, opaque, ok := strings.Cut(user, ":")
	expiry, _ := strconv.ParseInt(exp, 10, 64)
	// No device identifier reaches the TURN server (04 §4.3.2).
	if !ok || len(opaque) != 8 || expiry < time.Now().Add(55*time.Minute).Unix() || strings.Contains(user, b64.EncodeToString(sk.Public().(ed25519.PublicKey))[:8]) {
		t.Fatalf("username %q", user)
	}
	mac := hmac.New(sha1.New, []byte("0123456789abcdef-static-secret"))
	mac.Write([]byte(user))
	if m["credential"] != base64.StdEncoding.EncodeToString(mac.Sum(nil)) || m["ttl"] != float64(3600) {
		t.Fatalf("credential %v", m)
	}
	urls := m["urls"].([]any)
	if len(urls) != 3 || urls[0] != "stun:stun.example:3478" || urls[2] != "turns:turn-a.example:443?transport=tcp" {
		t.Fatalf("urls %v", urls)
	}
	if _, has := m["quotaRemainingMB"]; has {
		t.Fatal("no quota is metered yet: none may be reported")
	}
}

// The signature binds this connection: replayed on another one, or forged, it is 8031.
func TestTURNSignatureIsBoundToTheConnection(t *testing.T) {
	_, url := fixture(t, withTURN)
	a, b := dial(t, url), dial(t, url)
	atA, nA := helloTURN(t, a)
	helloTURN(t, b)
	_, sk, _ := ed25519.GenerateKey(nil)
	req := turnRequest(sk, atA, nA)
	send(t, b, req)
	expectError(t, b, 8031)
	_, other, _ := ed25519.GenerateKey(nil)
	req["sig"] = b64.EncodeToString(ed25519.Sign(other, []byte("x")))
	send(t, a, req)
	expectError(t, a, 8031)
}

// Without a relay configured the answer is 8032 (P2P only), not a fake credential.
func TestTURNWithoutRelayConfiguredIs8032(t *testing.T) {
	_, url := fixture(t, nil)
	c := dial(t, url)
	at, n := helloTURN(t, c)
	_, sk, _ := ed25519.GenerateKey(nil)
	send(t, c, turnRequest(sk, at, n))
	expectError(t, c, 8032)
}

func TestTURNConfigurationIsChecked(t *testing.T) {
	for _, urls := range [][]string{
		{"http://turn.example:3478"},
		{"turn:a.example:3478", "turn:b.example:3478", "turn:c.example:3478"},
		{"turn:user@a.example:3478"},
	} {
		cfg := DefaultConfig()
		cfg.TURNURLs, cfg.TURNSecret = urls, []byte("0123456789abcdef")
		if _, err := New(cfg); err == nil {
			t.Fatalf("accepted %v", urls)
		}
	}
	cfg := DefaultConfig()
	cfg.TURNURLs, cfg.TURNSecret = []string{"turn:a.example:3478"}, []byte("short")
	if _, err := New(cfg); err == nil {
		t.Fatal("accepted a short secret")
	}
}

func TestTURNRequestsAreRateLimitedPerConnection(t *testing.T) {
	_, url := fixture(t, withTURN)
	c := dial(t, url)
	at, n := helloTURN(t, c)
	_, sk, _ := ed25519.GenerateKey(nil)
	for i := 0; i < 5; i++ {
		send(t, c, turnRequest(sk, at, n))
		receive(t, c, "turn_credentials_ok")
	}
	send(t, c, turnRequest(sk, at, n))
	expectError(t, c, 8051)
}
