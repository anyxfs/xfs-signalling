package signal

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TURN time-limited credentials (04 §4.3): the client proves an identity key
// bound to this connection, then gets a coturn REST credential
// (draft-uberti-behave-turn-rest-00). Per-device relay quotas need coturn's
// usage reports (04 §5.3, gate G-4) and are not enforced yet, so no
// `quotaRemainingMB` is sent rather than an invented number.

const (
	turnTag      = "XFS-TURNREQ-v1"
	turnTTL      = time.Hour
	turnSkew     = 300 * time.Second
	turnMaxNodes = 2
)

// ParseTURNURLs checks `turn:` / `turns:` URLs naming at most two nodes (04 §4.3.2).
func ParseTURNURLs(urls []string) ([]string, error) {
	hosts := map[string]bool{}
	for _, u := range urls {
		scheme, rest, ok := strings.Cut(u, ":")
		if !ok || (scheme != "turn" && scheme != "turns") || rest == "" || strings.ContainsAny(rest, " @") {
			return nil, fmt.Errorf("not a turn: or turns: URL: %q", u)
		}
		hostport, _, _ := strings.Cut(rest, "?")
		host := hostport
		if i := strings.LastIndex(hostport, ":"); i > 0 {
			host = hostport[:i]
		}
		if host == "" || url.PathEscape(host) != host {
			return nil, fmt.Errorf("bad TURN host in %q", u)
		}
		hosts[host] = true
	}
	if len(hosts) > turnMaxNodes {
		return nil, errors.New("at most two TURN nodes may be offered")
	}
	return append([]string(nil), urls...), nil
}

// turnSigned is what the client signs: tag ‖ nonce ‖ u32(hello time) ‖ SHA-256(connNonce).
func turnSigned(nonce []byte, helloAt int64, connNonce [32]byte) []byte {
	b := make([]byte, 0, len(turnTag)+32+4+32)
	b = append(b, turnTag...)
	b = append(b, nonce...)
	b = binary.BigEndian.AppendUint32(b, uint32(helloAt))
	binding := sha256.Sum256(connNonce[:])
	return append(b, binding[:]...)
}

// turnCredential issues `<expiry>:<opaque>` and its HMAC-SHA1 under the coturn
// static-auth-secret. The opaque part is random: no device identifier reaches
// the TURN server's logs (04 §4.3.2).
func turnCredential(secret []byte, now time.Time) (username, credential string) {
	username = fmt.Sprintf("%d:%s", now.Add(turnTTL).Unix(), randomID(6))
	m := hmac.New(sha1.New, secret)
	_, _ = m.Write([]byte(username))
	return username, base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// verifyTURN checks a `turn_credentials` request against this connection.
func verifyTURN(c *client, r request, now time.Time) bool {
	if now.Sub(time.Unix(c.helloAt, 0)) > turnSkew {
		return false
	}
	pk, _ := base64.RawURLEncoding.DecodeString(r.PK)
	nonce, _ := base64.RawURLEncoding.DecodeString(r.Nonce)
	sig, _ := base64.RawURLEncoding.DecodeString(r.Sig)
	return ed25519.Verify(ed25519.PublicKey(pk), turnSigned(nonce, c.helloAt, c.connNonce), sig)
}
