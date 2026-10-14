package signal

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

// Session-renewal tickets (04 v1.5 §2.6, user ruling 10-02): each side holds its
// own ticket bound to its identity key; the server keeps no per-session state.

const (
	ticketVersion  = 2
	ticketPurpose  = 1 // session renewal
	ticketTTL      = 6 * time.Hour
	ticketTotal    = 24 * time.Hour
	ticketKeyLife  = 24 * time.Hour
	resumeSkew     = 60 * time.Second
	resumeSlotLife = 120 * time.Second
	resumeTag      = "XFS-RESUME-v1"
	ticketBody     = 1 + 1 + 16 + 1 + 16 + 4 + 4 + 1
)

type ticket struct {
	session     [16]byte
	role        uint8 // 1 creator, 2 joiner
	pkHash      [16]byte
	firstIssued int64
	expires     int64
}

// ticketKeys rotate daily; the current and the previous key are accepted.
type ticketKeys struct {
	cur, prev [32]byte
	rotated   time.Time
	path      string // where they are kept (ticketfile.go); empty: memory only
}

func newTicketKeys(now time.Time) ticketKeys {
	var k ticketKeys
	mustRandom(k.cur[:])
	mustRandom(k.prev[:])
	k.rotated = now
	return k
}

// rotate reports whether it did.
func (k *ticketKeys) rotate(now time.Time) bool {
	if now.Sub(k.rotated) < ticketKeyLife {
		return false
	}
	k.prev = k.cur
	mustRandom(k.cur[:])
	k.rotated = now
	return true
}

func mustRandom(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}

func hash16(b []byte) (h [16]byte) {
	sum := sha256.Sum256(b)
	copy(h[:], sum[:16])
	return h
}

func ticketMAC(key [32]byte, body []byte) []byte {
	m := hmac.New(sha256.New, key[:])
	_, _ = m.Write(body)
	return m.Sum(nil)[:16]
}

func (k *ticketKeys) seal(t ticket) string {
	b := make([]byte, 0, ticketBody+16)
	b = append(b, ticketVersion, ticketPurpose)
	b = append(b, t.session[:]...)
	b = append(b, t.role)
	b = append(b, t.pkHash[:]...)
	b = binary.BigEndian.AppendUint32(b, uint32(t.firstIssued))
	b = binary.BigEndian.AppendUint32(b, uint32(t.expires))
	b = append(b, 0) // region: one region for now
	b = append(b, ticketMAC(k.cur, b)...)
	return base64.RawURLEncoding.EncodeToString(b)
}

// open checks the MAC under either key and the expiry; nothing else.
func (k *ticketKeys) open(s string, now time.Time) (ticket, bool) {
	var t ticket
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != ticketBody+16 || b[0] != ticketVersion || b[1] != ticketPurpose {
		return t, false
	}
	body, mac := b[:ticketBody], b[ticketBody:]
	if !hmac.Equal(mac, ticketMAC(k.cur, body)) && !hmac.Equal(mac, ticketMAC(k.prev, body)) {
		return t, false
	}
	copy(t.session[:], body[2:18])
	t.role = body[18]
	copy(t.pkHash[:], body[19:35])
	t.firstIssued = int64(binary.BigEndian.Uint32(body[35:39]))
	t.expires = int64(binary.BigEndian.Uint32(body[39:43]))
	if (t.role != 1 && t.role != 2) || now.Unix() >= t.expires || now.Unix()-t.firstIssued > int64(ticketTotal/time.Second) {
		return t, false
	}
	return t, true
}

// connNonce binds the signature to this one connection (04 §4.3.1's
// turn_credentials does the same; resume previously didn't, so a signed resume
// message captured by a TLS-breaking attacker could be replayed verbatim on a
// second connection within the 60 s skew window to hijack the slot — found in
// the 2026-10-07 penetration test, FINDING-1).
func resumeSigned(tk string, ts uint64, connNonce [32]byte) []byte {
	b := append([]byte(resumeTag), tk...)
	b = binary.BigEndian.AppendUint64(b, ts)
	return append(b, connNonce[:]...)
}

// verifyResume: the request proves the identity its ticket is bound to, now, on
// this connection.
func verifyResume(t ticket, tk string, pk []byte, ts uint64, sig []byte, connNonce [32]byte, now time.Time) bool {
	d := now.Unix() - int64(ts)
	if d > int64(resumeSkew/time.Second) || -d > int64(resumeSkew/time.Second) {
		return false
	}
	return hash16(pk) == t.pkHash && ed25519.Verify(ed25519.PublicKey(pk), resumeSigned(tk, ts, connNonce), sig)
}

// resumeSlot waits up to two minutes for the other side of a session.
type resumeSlot struct {
	members     [2]*client
	sdpNeeded   [2]bool
	firstIssued int64
	expires     time.Time
}
