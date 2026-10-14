package signal

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func fixture(t *testing.T, change func(*Config)) (*Server, string) {
	t.Helper()
	cfg := DefaultConfig()
	if change != nil {
		change(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(s)
	t.Cleanup(func() { s.Close(); h.Close() })
	return s, "ws" + strings.TrimPrefix(h.URL, "http") + "/signal"
}
func dial(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	d := websocket.Dialer{Subprotocols: []string{Subprotocol}}
	c, _, err := d.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func send(t *testing.T, c *websocket.Conn, m message) {
	t.Helper()
	if err := c.WriteJSON(m); err != nil {
		t.Fatal(err)
	}
}
func receive(t *testing.T, c *websocket.Conn, typ string) message {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	var m message
	if err := c.ReadJSON(&m); err != nil {
		t.Fatal(err)
	}
	if m["t"] != typ {
		t.Fatalf("want %s, got %v", typ, m)
	}
	return m
}
func hello(t *testing.T, c *websocket.Conn) {
	t.Helper()
	send(t, c, message{"t": "hello", "v": 1, "id": "AAAAAAAAAAA"})
	m := receive(t, c, "hello_ok")
	if m["id"] != "AAAAAAAAAAA" {
		t.Fatal("lost request id")
	}
}
func create(t *testing.T, c *websocket.Conn) message {
	t.Helper()
	send(t, c, message{"t": "create_room"})
	return receive(t, c, "room_created")
}
func expectError(t *testing.T, c *websocket.Conn, code int) {
	t.Helper()
	m := receive(t, c, "error")
	if m["code"] != float64(code) {
		t.Fatalf("want %d, got %v", code, m)
	}
}

func TestRoundTripAndReady(t *testing.T) {
	s, url := fixture(t, nil)
	a, b := dial(t, url), dial(t, url)
	hello(t, a)
	hello(t, b)
	r := create(t, a)
	code := r["code"].(string)
	if len(code) != 8 || code[0] == '0' {
		t.Fatal("bad code")
	}
	send(t, b, message{"t": "join_room", "code": code[:4] + "-" + code[4:]})
	joined := receive(t, b, "room_joined")
	peer := receive(t, a, "peer_joined")
	if joined["peerEphemeralId"] == peer["peerEphemeralId"] {
		t.Fatal("peer identifiers reused")
	}
	for _, pair := range [][2]*websocket.Conn{{a, b}, {b, a}} {
		for _, kind := range []string{"offer", "answer", "candidate", "candidate_end"} {
			payload := "opaque, not SDP: <秘密> \n \"quoted\""
			send(t, pair[0], message{"t": "signal", "room": r["room"], "kind": kind, "payload": payload})
			m := receive(t, pair[1], "signal")
			if m["payload"] != payload || m["kind"] != kind {
				t.Fatal("payload changed")
			}
		}
	}
	send(t, a, message{"t": "ready", "room": r["room"], "pkHash": "AAAAAAAAAAAAAAAAAAAAAA"})
	send(t, b, message{"t": "ready", "room": r["room"], "pkHash": "AAAAAAAAAAAAAAAAAAAAAA"})
	for _, c := range []*websocket.Conn{a, b} {
		if receive(t, c, "room_closed")["reason"] != float64(0) {
			t.Fatal("not established")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rooms) != 0 || len(s.codes) != 0 || len(s.retired) != 1 {
		t.Fatal("lifecycle leak")
	}
}

func TestConcurrentJoinIsSingleUse(t *testing.T) {
	_, url := fixture(t, nil)
	a, b, c := dial(t, url), dial(t, url), dial(t, url)
	for _, x := range []*websocket.Conn{a, b, c} {
		hello(t, x)
	}
	r := create(t, a)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, x := range []*websocket.Conn{b, c} {
		wg.Add(1)
		go func(x *websocket.Conn) {
			defer wg.Done()
			errs <- x.WriteJSON(message{"t": "join_room", "code": r["code"]})
		}(x)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	winners, losers := 0, 0
	for _, x := range []*websocket.Conn{b, c} {
		_ = x.SetReadDeadline(time.Now().Add(3 * time.Second))
		var m message
		if err := x.ReadJSON(&m); err != nil {
			t.Fatal(err)
		}
		if m["t"] == "room_joined" {
			winners++
		} else if m["code"] == float64(8010) {
			losers++
		}
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("winners=%d losers=%d", winners, losers)
	}
	receive(t, a, "peer_joined")
}

func TestRoomMembershipCannotBeForged(t *testing.T) {
	_, url := fixture(t, nil)
	a, b := dial(t, url), dial(t, url)
	hello(t, a)
	hello(t, b)
	r := create(t, a)
	for _, m := range []message{{"t": "signal", "room": r["room"], "kind": "offer", "payload": "secret"}, {"t": "ready", "room": r["room"], "pkHash": "AAAAAAAAAAAAAAAAAAAAAA"}, {"t": "bye", "room": r["room"], "reason": 1}} {
		send(t, b, m)
		expectError(t, b, 8020)
	}
	send(t, a, message{"t": "create_room"})
	expectError(t, a, 8001)
	send(t, b, message{"t": "join_room", "code": r["code"]})
	receive(t, b, "room_joined")
	receive(t, a, "peer_joined")
}

func TestHandshakeAndOrigin(t *testing.T) {
	_, url := fixture(t, nil)
	for _, tc := range []struct {
		m    message
		code int
	}{{message{"t": "ping"}, 8003}, {message{"t": "hello", "v": 2}, 8002}, {message{"t": "hello", "v": 1, "unknown": true}, 8001}} {
		c := dial(t, url)
		send(t, c, tc.m)
		expectError(t, c, tc.code)
		if _, _, err := c.ReadMessage(); err == nil {
			t.Fatal("connection stayed open")
		}
	}
	d := websocket.Dialer{Subprotocols: []string{Subprotocol}}
	if c, _, err := d.Dial(url, http.Header{"Origin": []string{"https://attacker.invalid"}}); err == nil {
		c.Close()
		t.Fatal("cross origin allowed")
	}
	d.Subprotocols = []string{"xfs-signal.v1"}
	if c, _, err := d.Dial(url, nil); err == nil {
		c.Close()
		t.Fatal("advertised unfinished production protocol")
	}
}

func TestDecodeStrict(t *testing.T) {
	for _, input := range []string{`null`, `[]`, `{"t":"ping","t":"hello"}`, `{"t":"ping","\u0074":"ping"}`, `{"t":"ping"} {}`, `{"t":"ping","code":"1"}`, `{"t":"hello","v":null}`, `{"t":"hello","v":-1}`, `{"t":"ping","id":"x"}`, `{"t":"signal","room":"x","kind":"offer"}`, `{"t":"resume","ticket":"secret"}`, string([]byte{0xff})} {
		if _, err := decode([]byte(input)); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

func TestExpiryIgnoresPingsAndQuarantinesCode(t *testing.T) {
	s, url := fixture(t, nil)
	a, b := dial(t, url), dial(t, url)
	hello(t, a)
	hello(t, b)
	r := create(t, a)
	send(t, a, message{"t": "ping"})
	receive(t, a, "pong")
	s.mu.Lock()
	expires := s.rooms[r["room"].(string)].expires
	s.sweep(expires)
	until := s.retired[s.hash(r["code"].(string))]
	s.mu.Unlock()
	if !until.Equal(expires.Add(s.cfg.Wait)) {
		t.Fatal("missing quarantine")
	}
	if receive(t, a, "room_closed")["reason"] != float64(8021) {
		t.Fatal("wrong expiry")
	}
	send(t, b, message{"t": "join_room", "code": r["code"]})
	expectError(t, b, 8010)
	s.mu.Lock()
	s.sweep(until)
	count := len(s.retired)
	s.mu.Unlock()
	if count != 0 {
		t.Fatal("quarantine leak")
	}
}

func TestNegotiationTimeoutAndDisconnect(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(fmt.Sprint(disconnect), func(t *testing.T) {
			s, url := fixture(t, nil)
			a, b := dial(t, url), dial(t, url)
			hello(t, a)
			hello(t, b)
			r := create(t, a)
			send(t, b, message{"t": "join_room", "code": r["code"]})
			receive(t, b, "room_joined")
			receive(t, a, "peer_joined")
			if disconnect {
				_ = b.Close()
				receive(t, a, "peer_left")
			} else {
				s.mu.Lock()
				s.sweep(s.rooms[r["room"].(string)].expires)
				s.mu.Unlock()
			}
			m := receive(t, a, "room_closed")
			want := 8022
			if disconnect {
				want = 8023
			}
			if m["reason"] != float64(want) {
				t.Fatal(m)
			}
		})
	}
}

func TestHelloTimeoutAndMessageLimit(t *testing.T) {
	_, url := fixture(t, func(c *Config) { c.Hello = 40 * time.Millisecond })
	c := dial(t, url)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("hello never expired")
	}
	c = dial(t, url)
	hello(t, c)
	if err := c.WriteMessage(websocket.TextMessage, []byte(strings.Repeat("a", MaxMessage+1))); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("oversized message accepted")
	}
}

func TestLimitsPersistAcrossConnectionsAndIgnoreForwardedIP(t *testing.T) {
	s, url := fixture(t, nil)
	c := dial(t, url)
	hello(t, c)
	s.mu.Lock()
	ip := s.sources["127.0.0.1"]
	ip.join = bucket{tokens: 0, updated: time.Now()}
	s.mu.Unlock()
	d := websocket.Dialer{Subprotocols: []string{Subprotocol}}
	b, _, err := d.Dial(url, http.Header{"X-Forwarded-For": []string{"203.0.113.9"}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	hello(t, b)
	send(t, b, message{"t": "join_room", "code": "12345678"})
	expectError(t, b, 8012)
}

func TestInvalidCodePadding(t *testing.T) {
	_, url := fixture(t, nil)
	c := dial(t, url)
	hello(t, c)
	start := time.Now()
	send(t, c, message{"t": "join_room", "code": "00000000"})
	expectError(t, c, 8010)
	if time.Since(start) < 290*time.Millisecond {
		t.Fatal("missing failure padding")
	}
}

func TestResourceCapsAndShutdown(t *testing.T) {
	s, url := fixture(t, func(c *Config) { c.MaxConnections = 2; c.MaxRooms = 1 })
	a, b := dial(t, url), dial(t, url)
	hello(t, a)
	hello(t, b)
	create(t, a)
	send(t, b, message{"t": "create_room"})
	expectError(t, b, 8014)
	d := websocket.Dialer{Subprotocols: []string{Subprotocol}}
	if c, resp, err := d.Dial(url, nil); err == nil {
		c.Close()
		t.Fatal("connection cap ignored")
	} else if resp.StatusCode != 503 {
		t.Fatal(resp.Status)
	}
	s.Close()
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := a.ReadMessage(); err == nil {
		t.Fatal("shutdown left websocket open")
	}
}

func TestBucketAndSourcePrefixes(t *testing.T) {
	now := time.Now()
	var b bucket
	for i := 0; i < 5; i++ {
		if b.take(now, 5, 30*time.Second) != 0 {
			t.Fatal("early throttle")
		}
	}
	if b.take(now, 5, 30*time.Second) != 30 {
		t.Fatal("wrong retry")
	}
	if b.take(now.Add(30*time.Second), 5, 30*time.Second) != 0 {
		t.Fatal("no refill")
	}
	for _, tc := range []struct{ ip, source, prefix string }{{"::ffff:192.0.2.9", "192.0.2.9", "192.0.2.0/24"}, {"2001:db8:1:2::1", "2001:db8:1:2::/64", "2001:db8:1::/48"}} {
		a, p := sourceKeys(netip.MustParseAddr(tc.ip))
		if a != tc.source || p != tc.prefix {
			t.Fatal(a, p)
		}
	}
}

func TestBackpressureDropsSlowConsumer(t *testing.T) {
	_, url := fixture(t, nil)
	ws := dial(t, url)
	c := &client{ws: ws, send: make(chan outbound, 1), done: make(chan struct{})}
	c.emit(message{"t": "pong"}, false)
	c.emit(message{"t": "pong"}, false)
	select {
	case <-c.done:
	default:
		t.Fatal("queue overflow ignored")
	}
}

func TestOrphanAndCodeCapacity(t *testing.T) {
	s, url := fixture(t, func(c *Config) { c.MaxRooms = 1; c.MaxCodes = 1 })
	a, b := dial(t, url), dial(t, url)
	hello(t, a)
	hello(t, b)
	r := create(t, a)
	s.mu.Lock()
	rm := s.rooms[r["room"].(string)]
	creator := rm.creator
	s.disconnect(creator, time.Now())
	orphanEnd := rm.orphan
	s.mu.Unlock()
	creator.stop()
	send(t, b, message{"t": "join_room", "code": r["code"]})
	expectError(t, b, 8010)
	s.mu.Lock()
	s.sweep(orphanEnd)
	rooms, codes, retired := len(s.rooms), len(s.codes), len(s.retired)
	s.mu.Unlock()
	if rooms != 0 || codes != 0 || retired != 1 {
		t.Fatal("orphan not retired")
	}
	send(t, b, message{"t": "create_room"})
	expectError(t, b, 8014) // quarantine also counts toward memory cap
}

func TestPenaltyScheduleAndCleanup(t *testing.T) {
	now := time.Now()
	var b sourceBudget
	for i := 1; i <= 21; i++ {
		code, duration := b.fail(now)
		switch {
		case i <= 3:
			if code != 8010 || duration != 300*time.Millisecond {
				t.Fatal(i, code, duration)
			}
		case i <= 6:
			if code != 8010 || duration != 2300*time.Millisecond {
				t.Fatal(i, code, duration)
			}
		case i <= 10:
			if code != 8012 || duration != time.Minute {
				t.Fatal(i, code, duration)
			}
		case i <= 20:
			if code != 8013 || duration != 10*time.Minute {
				t.Fatal(i, code, duration)
			}
		default:
			if code != 8013 || duration != time.Hour {
				t.Fatal(i, code, duration)
			}
		}
	}
	s, _ := fixture(t, nil)
	s.mu.Lock()
	b.last = now
	s.sources["test"] = &b
	s.sweep(now.Add(30 * time.Minute))
	if s.sources["test"] == nil {
		t.Fatal("evicted live penalty")
	}
	s.sweep(now.Add(time.Hour + time.Second))
	if len(s.sources) != 0 {
		t.Fatal("leaked source budget")
	}
	s.mu.Unlock()
}

func TestTLSHealthAndNegotiation(t *testing.T) {
	s, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewTLSServer(s)
	defer h.Close()
	defer s.Close()
	d := websocket.Dialer{Subprotocols: []string{Subprotocol}, TLSClientConfig: &tls.Config{RootCAs: h.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}}
	c, _, err := d.Dial("wss"+strings.TrimPrefix(h.URL, "https")+"/signal", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hello(t, c)
	resp, err := h.Client().Get(h.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body message
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || body["status"] != "ok" {
		t.Fatal(body)
	}
}

func TestSTUNConfigurationDeliveredToBothPeers(t *testing.T) {
	urls := []string{"stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302", "stun:stun2.l.google.com:19302", "stun:stun3.l.google.com:19302"}
	_, url := fixture(t, func(c *Config) { c.STUNURLs = urls })
	a, b := dial(t, url), dial(t, url)
	hello(t, a)
	hello(t, b)
	r := create(t, a)
	send(t, b, message{"t": "join_room", "code": r["code"]})
	j := receive(t, b, "room_joined")
	receive(t, a, "peer_joined")
	for _, m := range []message{r, j} {
		servers, ok := m["iceServers"].([]any)
		if !ok || len(servers) != 4 {
			t.Fatal("missing STUN configuration")
		}
		for i, raw := range servers {
			if raw.(map[string]any)["urls"].([]any)[0] != urls[i] {
				t.Fatal("STUN URL changed")
			}
		}
	}
}

func TestRejectInvalidSTUNConfiguration(t *testing.T) {
	for _, uri := range []string{"https://stun.example", "turn:host:3478", "stun:host", "stun:host:0", "stun:host:99999", "stun:user@host:3478", "stun:host/path:3478"} {
		cfg := DefaultConfig()
		cfg.STUNURLs = []string{uri}
		if s, err := New(cfg); err == nil {
			s.Close()
			t.Fatalf("accepted %s", uri)
		}
	}
}

func TestMessageLimitConfiguration(t *testing.T) {
	for _, n := range []int64{0, 1023, 1024*1024 + 1} {
		cfg := DefaultConfig()
		cfg.MaxMessageBytes = n
		if s, err := New(cfg); err == nil {
			s.Close()
			t.Fatalf("accepted message limit %d", n)
		}
	}
	for _, n := range []int64{1024, 32 * 1024, 64 * 1024, 1024 * 1024} {
		cfg := DefaultConfig()
		cfg.MaxMessageBytes = n
		s, err := New(cfg)
		if err != nil {
			t.Fatalf("rejected message limit %d: %v", n, err)
		}
		s.Close()
	}
}

func TestConfiguredMessageLimitIsEnforced(t *testing.T) {
	for _, limit := range []int64{32 * 1024, 128 * 1024} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			_, url := fixture(t, func(c *Config) { c.MaxMessageBytes = limit })
			c := dial(t, url)
			hello(t, c)
			body := message{"t": "hello", "v": 1, "client": strings.Repeat("x", int(limit)-30)}
			data, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(data)) <= limit {
				t.Fatalf("test message is not over limit: %d <= %d", len(data), limit)
			}
			if err := c.WriteMessage(websocket.TextMessage, data); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, _, err = c.ReadMessage()
			if err == nil {
				t.Fatalf("limit %d was ignored", limit)
			}
		})
	}
}

func TestMessageAtLimitAndAboveLimit(t *testing.T) {
	for _, above := range []bool{false, true} {
		t.Run(fmt.Sprint(above), func(t *testing.T) {
			_, url := fixture(t, nil)
			c := dial(t, url)
			hello(t, c)
			base, _ := json.Marshal(message{"t": "hello", "v": 1, "client": ""})
			size := MaxMessage - len(base)
			if above {
				size++
			}
			msg := message{"t": "hello", "v": 1, "client": strings.Repeat("a", size)}
			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatal(err)
			}
			want := MaxMessage
			if above {
				want++
			}
			if len(data) != want {
				t.Fatalf("message length %d; want %d", len(data), want)
			}
			if err := c.WriteMessage(websocket.TextMessage, data); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, raw, err := c.ReadMessage()
			if above {
				if err == nil {
					t.Fatal("accepted over limit")
				}
				if closeErr, ok := err.(*websocket.CloseError); ok && closeErr.Code != websocket.CloseMessageTooBig {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var reply message
			if err := json.Unmarshal(raw, &reply); err != nil {
				t.Fatal(err)
			}
			if reply["t"] != "error" || reply["code"] != float64(8001) {
				t.Fatal(reply)
			}
		})
	}
}

func TestEscapedForwardEnvelopeCanExceedLimit(t *testing.T) {
	_, url := fixture(t, nil)
	a, b := dial(t, url), dial(t, url)
	hello(t, a)
	hello(t, b)
	r := create(t, a)
	send(t, b, message{"t": "join_room", "code": r["code"]})
	receive(t, b, "room_joined")
	receive(t, a, "peer_joined")
	// '<' is valid as a literal inbound but encoding/json escapes it outbound.
	payload := strings.Repeat("<", MaxMessage/4)
	incoming := []byte(fmt.Sprintf(`{"t":"signal","room":%q,"kind":"offer","payload":"%s"}`, r["room"], payload))
	if len(incoming) >= MaxMessage {
		t.Fatalf("input too big: %d", len(incoming))
	}
	if err := a.WriteMessage(websocket.TextMessage, incoming); err != nil {
		t.Fatal(err)
	}
	if code := receive(t, a, "error")["code"]; code != float64(8050) {
		t.Fatalf("want 8050, got %v", code)
	}
	_ = b.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := b.ReadMessage(); err == nil {
		t.Fatal("oversized forwarded payload reached peer")
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{`{"t":"hello","v":1}`, `{"t":"signal","room":"r","kind":"offer","payload":"opaque"}`, `{"t":"ping"}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxMessage {
			return
		}
		r, err := decode(b)
		if err == nil {
			if _, err = json.Marshal(r); err != nil {
				t.Fatal(err)
			}
		}
	})
}
