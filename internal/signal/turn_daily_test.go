package signal

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// The daily budget is per address, not per connection: reconnecting does not
// reset it, and the address's record outlives the one-hour idle cleanup until
// the budget has refilled.
func TestTURNDailyBudgetPerAddress(t *testing.T) {
	s, url := fixture(t, func(c *Config) { withTURN(c); c.TURNDailyPerSource = 2 })
	_, sk, _ := ed25519.GenerateKey(nil)
	a := dial(t, url)
	at, nonce := helloTURN(t, a)
	for range 2 {
		send(t, a, turnRequest(sk, at, nonce))
		receive(t, a, "turn_credentials_ok")
	}
	send(t, a, turnRequest(sk, at, nonce))
	m := receive(t, a, "error")
	if m["code"] != float64(8051) || m["retryAfter"].(float64) < 3600 {
		t.Fatalf("third credential of the day: %v", m)
	}
	b := dial(t, url) // a new connection from the same address
	at, nonce = helloTURN(t, b)
	send(t, b, turnRequest(sk, at, nonce))
	if m := receive(t, b, "error"); m["code"] != float64(8051) {
		t.Fatalf("new connection reset the daily budget: %v", m)
	}
	_ = a.Close()
	_ = b.Close()
	time.Sleep(200 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	later := time.Now().Add(2 * time.Hour)
	s.sweep(later)
	if s.sources["127.0.0.1"] == nil {
		t.Fatal("budget dropped before refilling")
	}
	s.sweep(time.Now().Add(25 * time.Hour))
	if s.sources["127.0.0.1"] != nil {
		t.Fatal("refilled budget kept")
	}
}
