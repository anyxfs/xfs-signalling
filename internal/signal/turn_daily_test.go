package signal

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// The daily budget is per address, not per connection: reconnecting does not
// reset it. It counts a Beijing calendar day (design 2026-10-19 §5): the refusal
// is 8030 with resetAt, the next Beijing midnight, so clients can still try a
// direct connection and say when the relay comes back.
func TestDailyLimitAnswers8030WithResetAt(t *testing.T) {
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
	if m["code"] != float64(8030) || int64(m["resetAt"].(float64)) != nextBeijingMidnight(time.Now()).Unix() {
		t.Fatalf("third credential of the day: %v", m)
	}
	b := dial(t, url) // a new connection from the same address
	at, nonce = helloTURN(t, b)
	send(t, b, turnRequest(sk, at, nonce))
	if m := receive(t, b, "error"); m["code"] != float64(8030) {
		t.Fatalf("new connection reset the daily budget: %v", m)
	}
	_ = a.Close()
	_ = b.Close()
	time.Sleep(200 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(nextBeijingMidnight(time.Now()).Add(-time.Minute))
	if s.sources["127.0.0.1"] == nil {
		t.Fatal("budget dropped before its day ended")
	}
	s.sweep(nextBeijingMidnight(time.Now()).Add(2 * time.Hour))
	if s.sources["127.0.0.1"] != nil {
		t.Fatal("spent budget kept after its day")
	}
}

func TestBeijingDayBoundary(t *testing.T) {
	before := time.Date(2026, 10, 20, 15, 59, 59, 0, time.UTC)
	after := time.Date(2026, 10, 20, 16, 0, 0, 0, time.UTC)
	if beijingDay(before) == beijingDay(after) {
		t.Fatal("15:59:59Z and 16:00:00Z are the same Beijing day")
	}
	if got := nextBeijingMidnight(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)); !got.Equal(after) {
		t.Fatalf("next midnight %v", got)
	}
	if got := nextBeijingMidnight(after); !got.Equal(after.Add(24 * time.Hour)) {
		t.Fatalf("at midnight the next one is a day later, got %v", got)
	}
}

func TestDailyBudgetRefillsAtBeijingMidnight(t *testing.T) {
	var b sourceBudget
	day := time.Date(2026, 10, 20, 15, 0, 0, 0, time.UTC)
	for range 2 {
		if ok, _ := b.takeTURN(day, 2); !ok {
			t.Fatal("refused within the budget")
		}
	}
	if ok, reset := b.takeTURN(day, 2); ok || !reset.Equal(nextBeijingMidnight(day)) {
		t.Fatalf("third: ok=%v reset=%v", ok, reset)
	}
	if ok, _ := b.takeTURN(day.Add(time.Hour), 2); !ok {
		t.Fatal("not refilled after Beijing midnight")
	}
}
