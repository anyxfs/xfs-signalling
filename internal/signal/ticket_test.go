package signal

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type party struct {
	sk ed25519.PrivateKey
	pk ed25519.PublicKey
}

func newParty() party {
	pk, sk, _ := ed25519.GenerateKey(nil)
	return party{sk, pk}
}

func (p party) hash() string {
	h := hash16(p.pk)
	return b64.EncodeToString(h[:])
}

func (p party) resume(tk string, ts int64, sdp bool, connNonce [32]byte) message {
	sig := ed25519.Sign(p.sk, resumeSigned(tk, uint64(ts), connNonce))
	return message{"t": "resume", "ticket": tk, "pk": b64.EncodeToString(p.pk), "ts": ts, "sig": b64.EncodeToString(sig), "sdpNeeded": sdp}
}

// helloNonce is hello, keeping the connNonce resume signatures must bind to
// (04 §4.3.1's pattern, extended to resume after FINDING-1 of the 2026-10-07
// penetration test: without this binding a captured resume message could be
// replayed verbatim on another connection).
func helloNonce(t *testing.T, c *websocket.Conn) [32]byte {
	t.Helper()
	send(t, c, message{"t": "hello", "v": 1})
	m := receive(t, c, "hello_ok")
	raw, err := b64.DecodeString(m["connNonce"].(string))
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad connNonce: %v", m)
	}
	var nonce [32]byte
	copy(nonce[:], raw)
	return nonce
}

// pairAndReady runs a room to both `ready` and returns each side's ticket.
func pairAndReady(t *testing.T, url string, a, b party) (string, string) {
	t.Helper()
	ca, cb := dial(t, url), dial(t, url)
	hello(t, ca)
	hello(t, cb)
	code := create(t, ca)["code"]
	send(t, cb, message{"t": "join_room", "code": code})
	r := receive(t, cb, "room_joined")
	receive(t, ca, "peer_joined")
	send(t, ca, message{"t": "ready", "room": r["room"], "pkHash": a.hash()})
	send(t, cb, message{"t": "ready", "room": r["room"], "pkHash": b.hash()})
	ta, tb := receive(t, ca, "room_closed"), receive(t, cb, "room_closed")
	return ta["ticket"].(string), tb["ticket"].(string)
}

func resumed(t *testing.T, url string, p party, tk string, sdp bool) *websocket.Conn {
	t.Helper()
	c := dial(t, url)
	nonce := helloNonce(t, c)
	send(t, c, p.resume(tk, time.Now().Unix(), sdp, nonce))
	return c
}

// 04 v1.5 §2.6: each side gets its own ticket; presenting both (with proof of
// the bound identity) meets them again in a negotiating room, and the next
// tickets keep the first issue time.
func TestTicketsResumeBothSidesOfTheSession(t *testing.T) {
	s, url := fixture(t, nil)
	a, b := newParty(), newParty()
	ta, tb := pairAndReady(t, url, a, b)
	if ta == tb {
		t.Fatal("both sides got the same ticket")
	}
	ca := resumed(t, url, a, ta, true)
	cb := resumed(t, url, b, tb, false)
	ra, rb := receive(t, ca, "room_resumed"), receive(t, cb, "room_resumed")
	if ra["room"] != rb["room"] || ra["peerSdpNeeded"] != false || rb["peerSdpNeeded"] != true {
		t.Fatalf("resumed %v / %v", ra, rb)
	}
	send(t, ca, message{"t": "signal", "room": ra["room"], "kind": "offer", "payload": "restart"})
	if m := receive(t, cb, "signal"); m["payload"] != "restart" {
		t.Fatalf("%v", m)
	}
	send(t, ca, message{"t": "ready", "room": ra["room"], "pkHash": a.hash()})
	send(t, cb, message{"t": "ready", "room": ra["room"], "pkHash": b.hash()})
	next := receive(t, ca, "room_closed")["ticket"].(string)
	s.mu.Lock()
	before, _ := s.tickets.open(ta, time.Now())
	after, ok := s.tickets.open(next, time.Now())
	s.mu.Unlock()
	if !ok || after.firstIssued != before.firstIssued || after.session != before.session {
		t.Fatalf("renewal lost the session or its first issue time: %+v / %+v", before, after)
	}
}

// The same side twice is one side reconnecting, never both sides.
func TestTheSameTicketTwiceDoesNotMeetItself(t *testing.T) {
	_, url := fixture(t, nil)
	a, b := newParty(), newParty()
	ta, _ := pairAndReady(t, url, a, b)
	first := resumed(t, url, a, ta, true)
	resumed(t, url, a, ta, true)
	expectError(t, first, 8060) // replaced by the newer connection
}

func TestResumeNeedsTheBoundIdentityAFreshSignatureAndAnIntactTicket(t *testing.T) {
	_, url := fixture(t, nil)
	a, b := newParty(), newParty()
	ta, _ := pairAndReady(t, url, a, b)
	tampered := []byte(ta)
	tampered[10] ^= 1
	for name, build := range map[string]func([32]byte) message{
		"another identity": func(n [32]byte) message { return b.resume(ta, time.Now().Unix(), true, n) },
		"stale signature":  func(n [32]byte) message { return a.resume(ta, time.Now().Add(-2*time.Minute).Unix(), true, n) },
		"tampered ticket":  func(n [32]byte) message { return a.resume(string(tampered), time.Now().Unix(), true, n) },
	} {
		c := dial(t, url)
		nonce := helloNonce(t, c)
		send(t, c, build(nonce))
		m := receive(t, c, "error")
		if m["code"] != float64(8060) {
			t.Fatalf("%s: %v", name, m)
		}
	}
}

func TestTicketsStopAfterTwentyFourHoursInAll(t *testing.T) {
	k := newTicketKeys(time.Now())
	now := time.Now()
	old := k.seal(ticket{role: 1, firstIssued: now.Add(-25 * time.Hour).Unix(), expires: now.Add(time.Hour).Unix()})
	if _, ok := k.open(old, now); ok {
		t.Fatal("a session older than 24 h was renewed")
	}
	fresh := k.seal(ticket{role: 2, firstIssued: now.Unix(), expires: now.Add(time.Hour).Unix()})
	k.rotate(now.Add(25 * time.Hour))
	if _, ok := k.open(fresh, now); !ok {
		t.Fatal("the previous key must still be accepted after a rotation")
	}
}

// FINDING-1 (2026-10-07 penetration test): a resume signature is bound to the
// connection it was sent on. Replaying the exact same signed message on a
// second connection — as an attacker who captured it off the wire would have
// to — must not be accepted as that second connection's own proof.
func TestResumeSignatureDoesNotReplayAcrossConnections(t *testing.T) {
	_, url := fixture(t, nil)
	a, b := newParty(), newParty()
	ta, _ := pairAndReady(t, url, a, b)

	c1 := dial(t, url)
	n1 := helloNonce(t, c1)
	captured := a.resume(ta, time.Now().Unix(), true, n1)

	c2 := dial(t, url)
	helloNonce(t, c2) // a different connNonce than n1
	send(t, c2, captured)
	expectError(t, c2, 8060)
}
