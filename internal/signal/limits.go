package signal

import (
	"math"
	"net/netip"
	"time"
)

type bucket struct {
	tokens  float64
	updated time.Time
}

func (b *bucket) take(now time.Time, capacity float64, interval time.Duration) int {
	if b.updated.IsZero() {
		b.tokens = capacity
		b.updated = now
	}
	b.tokens = math.Min(capacity, b.tokens+now.Sub(b.updated).Seconds()/interval.Seconds())
	b.updated = now
	if b.tokens < 1 {
		return int(math.Ceil((1 - b.tokens) * interval.Seconds()))
	}
	b.tokens--
	return 0
}

type sourceBudget struct {
	join     bucket
	create   bucket
	connect  bucket // new connections from this address (04 §3.3.5)
	conns    int    // connections open now, upgrading included
	failures []time.Time
	frozen   time.Time
	last     time.Time
}

func (b *sourceBudget) fail(now time.Time) (int, time.Duration) {
	start := 0
	for start < len(b.failures) && !b.failures[start].After(now.Add(-10*time.Minute)) {
		start++
	}
	b.failures = append(b.failures[start:], now)
	n := len(b.failures)
	freeze := time.Duration(0)
	code := 8010
	switch {
	case n > 20:
		freeze = time.Hour
		code = 8013
	case n >= 11:
		freeze = 10 * time.Minute
		code = 8013
	case n >= 7:
		freeze = time.Minute
		code = 8012
	}
	if freeze > 0 {
		b.frozen = now.Add(freeze)
		return code, freeze
	}
	if n >= 4 {
		return code, 2300 * time.Millisecond
	}
	return code, 300 * time.Millisecond
}

func sourceKeys(addr netip.Addr) (string, string) {
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String(), netip.PrefixFrom(addr, 24).Masked().String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String(), netip.PrefixFrom(addr, 48).Masked().String()
}
