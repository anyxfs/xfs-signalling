package signal

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func keyFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "ticket-keys")
}

func sealNow(k ticketKeys, now time.Time) string {
	return k.seal(ticket{role: 1, firstIssued: now.Unix(), expires: now.Add(ticketTTL).Unix()})
}

// 04 §2.6: the reason for the file — a restart keeps outstanding tickets.
func TestTicketsOutliveARestartWithAKeyFile(t *testing.T) {
	path, now := keyFile(t), time.Now()
	before, err := loadTicketKeys(path, now)
	if err != nil {
		t.Fatal(err)
	}
	tk := sealNow(before, now)
	after, err := loadTicketKeys(path, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.open(tk, now.Add(time.Minute)); !ok {
		t.Fatal("a ticket from before the restart was refused")
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatal(info.Mode())
		}
	}
}

// The server end to end: tickets issued before a restart meet again after it.
func TestServerResumesTicketsIssuedBeforeItRestarted(t *testing.T) {
	path := keyFile(t)
	_, url := fixture(t, func(c *Config) { c.TicketKeyFile = path })
	a, b := newParty(), newParty()
	ta, tb := pairAndReady(t, url, a, b)
	_, url2 := fixture(t, func(c *Config) { c.TicketKeyFile = path })
	ca, cb := resumed(t, url2, a, ta, true), resumed(t, url2, b, tb, false)
	receive(t, ca, "room_resumed")
	receive(t, cb, "room_resumed")
}

// Without the file (the development default) a restart still ends them.
func TestWithoutAKeyFileARestartEndsTickets(t *testing.T) {
	_, url := fixture(t, nil)
	a, b := newParty(), newParty()
	ta, _ := pairAndReady(t, url, a, b)
	_, url2 := fixture(t, nil)
	expectError(t, resumed(t, url2, a, ta, true), 8060)
}

// A rotation is saved, and the previous key still opens what it signed after a
// restart (the 48-hour window survives restarts too).
func TestARotationIsKeptAcrossARestart(t *testing.T) {
	path, now := keyFile(t), time.Now()
	k, _ := loadTicketKeys(path, now)
	later := now.Add(ticketKeyLife + time.Minute)
	tk := k.seal(ticket{role: 1, firstIssued: later.Unix(), expires: later.Add(ticketTTL).Unix()}) // signed by the key that becomes prev
	if !k.rotate(later) {
		t.Fatal("no rotation after a day")
	}
	if err := saveTicketKeys(k); err != nil {
		t.Fatal(err)
	}
	again, err := loadTicketKeys(path, later)
	if err != nil {
		t.Fatal(err)
	}
	if again.cur != k.cur || again.prev != k.prev || !again.rotated.Equal(k.rotated.Truncate(time.Second)) {
		t.Fatal("rotation not kept")
	}
	if _, ok := again.open(tk, later); !ok {
		t.Fatal("the previous key no longer opens its tickets")
	}
}

// Down for more than a day: rotate once on start, keeping the old current key
// as previous. More than two days: nothing on disk is worth keeping.
func TestStartingAfterADayRotatesAfterTwoReplacesBoth(t *testing.T) {
	path, now := keyFile(t), time.Now()
	k, _ := loadTicketKeys(path, now)
	day, err := loadTicketKeys(path, now.Add(30*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if day.prev != k.cur || day.cur == k.cur {
		t.Fatal("one day down did not rotate once")
	}
	saved, _ := loadTicketKeys(path, now.Add(30*time.Hour))
	if saved.cur != day.cur {
		t.Fatal("the start-up rotation was not saved")
	}
	gone, err := loadTicketKeys(path, now.Add(30*time.Hour+2*ticketKeyLife))
	if err != nil {
		t.Fatal(err)
	}
	if gone.cur == day.cur || gone.prev == day.cur || gone.prev == day.prev {
		t.Fatal("keys older than two days were kept")
	}
}

// A damaged file stops the start instead of being quietly replaced.
func TestADamagedKeyFileStopsTheStart(t *testing.T) {
	path, now := keyFile(t), time.Now()
	if _, err := loadTicketKeys(path, now); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(path)
	for name, b := range map[string][]byte{
		"flipped bit": func() []byte { b := append([]byte(nil), good...); b[20] ^= 1; return b }(),
		"truncated":   good[:len(good)-1],
		"other file":  []byte("hello"),
	} {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTicketKeys(path, now); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		cfg := DefaultConfig()
		cfg.TicketKeyFile = path
		if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("%s: server started: %v", name, err)
		}
		if now, _ := os.ReadFile(path); string(now) != string(b) {
			t.Fatalf("%s: the damaged file was overwritten", name)
		}
	}
}

func TestAKeyFileOthersCanReadIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := keyFile(t)
	if _, err := loadTicketKeys(path, time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0o644)
	if _, err := loadTicketKeys(path, time.Now()); err == nil {
		t.Fatal("a world-readable key file was used")
	}
}

// A rotation that cannot be written still rotates in memory and keeps serving.
func TestAFailedSaveKeepsTheNewKeyInMemory(t *testing.T) {
	s, _ := fixture(t, func(c *Config) { c.TicketKeyFile = keyFile(t) })
	blocker := filepath.Join(t.TempDir(), "a-file")
	_ = os.WriteFile(blocker, nil, 0o600)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickets.path = filepath.Join(blocker, "keys") // its directory is a file
	old := s.tickets.cur
	first := time.Now().Add(ticketKeyLife + time.Minute)
	s.sweep(first)
	if s.tickets.cur == old || s.tickets.prev != old {
		t.Fatal("rotation lost when the save failed")
	}

	// Review R2: once the disk works again the rotation is written, without
	// waiting a day for the next one.
	good := keyFile(t)
	s.tickets.path = good
	later := first.Add(30 * time.Second)
	s.sweep(later)
	if _, err := os.Stat(good); err == nil {
		t.Fatal("retried before its backoff")
	}
	s.sweep(first.Add(time.Minute))
	saved, err := loadTicketKeys(good, first.Add(time.Minute))
	if err != nil || saved.cur != s.tickets.cur || s.keysUnsaved {
		t.Fatalf("rotation not written after the disk recovered: %v", err)
	}
}

// Review R6: the temporary file is exclusively created; a stale one with a loose
// mode next to the key file is never reused, and nothing is left behind.
func TestSavingIgnoresAStaleTemporaryFile(t *testing.T) {
	path := keyFile(t)
	_ = os.WriteFile(path+".tmp", []byte("stale"), 0o644)
	k := newTicketKeys(time.Now())
	k.path = path
	if err := saveTicketKeys(k); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatal(info.Mode())
		}
	}
	left, _ := filepath.Glob(path + ".*.tmp")
	if len(left) != 0 {
		t.Fatal("temporary files left:", left)
	}
}
