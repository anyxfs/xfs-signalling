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

// full: the bucket has refilled to capacity (or was never used).
func (b *bucket) full(now time.Time, capacity float64, interval time.Duration) bool {
	return b.updated.IsZero() || b.tokens+now.Sub(b.updated).Seconds()/interval.Seconds() >= capacity
}

type sourceBudget struct {
	turnDay  int64 // beijingDay of turnUsed
	turnUsed int   // TURN credentials issued to this address on turnDay
	join     bucket
	create   bucket
	connect  bucket // new connections from this address (04 §3.3.5)
	conns    int    // connections open now, upgrading included
	failures []time.Time
	frozen   time.Time
	last     time.Time
}

// beijingDay numbers calendar days in Beijing time (UTC+8): the daily relay
// budget resets at Beijing midnight for everyone (design 2026-10-19 §5).
func beijingDay(t time.Time) int64 { return (t.Unix() + 8*3600) / 86400 }

// nextBeijingMidnight is the start of the Beijing day after t's.
func nextBeijingMidnight(t time.Time) time.Time {
	return time.Unix((beijingDay(t)+1)*86400-8*3600, 0).UTC()
}

// takeTURN counts one relay credential against today's budget; when it is spent
// it reports when the budget comes back.
func (b *sourceBudget) takeTURN(now time.Time, limit int) (bool, time.Time) {
	if day := beijingDay(now); day != b.turnDay {
		b.turnDay, b.turnUsed = day, 0
	}
	if b.turnUsed >= limit {
		return false, nextBeijingMidnight(now)
	}
	b.turnUsed++
	return true, time.Time{}
}

// turnSpentToday: the address drew relay credentials today, so its record has to
// outlive the idle cleanup or the limit would reset early.
func (b *sourceBudget) turnSpentToday(now time.Time) bool {
	return b.turnUsed > 0 && b.turnDay == beijingDay(now)
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
