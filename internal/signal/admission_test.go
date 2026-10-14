package signal

import (
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// refused dials once and wants the upgrade refused with 429 and a Retry-After.
func refused(t *testing.T, url string) string {
	t.Helper()
	d := websocket.Dialer{Subprotocols: []string{Subprotocol}}
	c, resp, err := d.Dial(url, nil)
	if err == nil {
		c.Close()
		t.Fatal("connection admitted")
	}
	if resp == nil || resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatal(resp, err)
	}
	return resp.Header.Get("Retry-After")
}

// 04 §3.3.5: one address cannot hold more than its share of connections, and
// closing one gives the slot back.
func TestOneAddressCannotHoldEveryConnection(t *testing.T) {
	_, url := fixture(t, func(c *Config) { c.IPConnections = 3; c.PrefixConnections = 3 })
	a, b, c := dial(t, url), dial(t, url), dial(t, url)
	hello(t, a)
	hello(t, b)
	hello(t, c)
	if after := refused(t, url); after != "30" {
		t.Fatal(after)
	}
	_ = c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		d := websocket.Dialer{Subprotocols: []string{Subprotocol}}
		ws, _, err := d.Dial(url, nil)
		if err == nil {
			ws.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed connection's slot was not returned:", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The prefix cap is separate from the address cap (a /24 behind one NAT).
func TestPrefixCapCountsEveryAddressInIt(t *testing.T) {
	s, url := fixture(t, func(c *Config) { c.IPConnections = 5; c.PrefixConnections = 5 })
	s.mu.Lock()
	s.sources["127.0.0.0/24"] = &sourceBudget{conns: 4, last: time.Now()} // four from neighbours
	s.mu.Unlock()
	hello(t, dial(t, url))
	refused(t, url)
}

// New connections from one address come in a burst, then at the refill rate,
// whether or not earlier ones are still open.
func TestNewConnectionsAreRateLimitedPerAddress(t *testing.T) {
	_, url := fixture(t, func(c *Config) { c.ConnectCapacity = 3; c.ConnectRefill = time.Hour })
	for i := 0; i < 3; i++ {
		ws := dial(t, url)
		hello(t, ws)
		_ = ws.Close()
	}
	if after := refused(t, url); after != "3600" {
		t.Fatal(after)
	}
}

func TestAdmissionConfigIsValidated(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.IPConnections = 0 },
		func(c *Config) { c.PrefixConnections = c.IPConnections - 1 },
		func(c *Config) { c.ConnectCapacity = 0 },
		func(c *Config) { c.ConnectRefill = 0 },
	} {
		cfg := DefaultConfig()
		change(&cfg)
		if _, err := New(cfg); err == nil {
			t.Fatal("invalid admission configuration accepted")
		}
	}
}

// A source with an open connection is never swept, however old its last
// activity, so its counters cannot be reset under a live connection.
func TestSweepKeepsSourcesWithOpenConnections(t *testing.T) {
	s, _ := fixture(t, nil)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources["192.0.2.1"] = &sourceBudget{conns: 1, last: time.Now().Add(-2 * time.Hour)}
	s.sources["192.0.2.2"] = &sourceBudget{last: time.Now().Add(-2 * time.Hour)}
	s.sweep(time.Now())
	if s.sources["192.0.2.1"] == nil || s.sources["192.0.2.2"] != nil {
		t.Fatal("sweep ignored open connections")
	}
}
