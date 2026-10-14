package signal

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func codesFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "retired-codes")
}

// 04 §3.2 across a clean restart: a code open or just ended when the server
// stopped is not handed out again by the next one, and a late join with it finds
// nothing.
func TestCodesStayRetiredAcrossACleanRestart(t *testing.T) {
	path := codesFile(t)
	first, url := fixture(t, func(c *Config) { c.RetiredCodesFile = path })
	creator := dial(t, url)
	hello(t, creator)
	code := create(t, creator)["code"].(string)
	first.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("nothing left for the next run:", err)
	}

	second, url2 := fixture(t, func(c *Config) { c.RetiredCodesFile = path })
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the file outlived the start that read it")
	}
	second.mu.Lock()
	until, kept := second.retired[second.hash(code)]
	second.mu.Unlock()
	if !kept || time.Until(until) < second.cfg.Wait-time.Minute {
		t.Fatalf("code %s not quarantined for T_wait after the restart (%v)", code, until)
	}
	late := dial(t, url2)
	hello(t, late)
	send(t, late, message{"t": "join_room", "code": code})
	expectError(t, late, 8010)
}

// Without the setting the quarantine is per process, as before.
func TestWithoutTheFileARestartForgetsRetiredCodes(t *testing.T) {
	first, url := fixture(t, nil)
	c := dial(t, url)
	hello(t, c)
	code := create(t, c)["code"].(string)
	first.Close()
	second, _ := fixture(t, nil)
	second.mu.Lock()
	defer second.mu.Unlock()
	if _, kept := second.retired[second.hash(code)]; kept {
		t.Fatal("quarantine carried over without a file")
	}
}

func TestExpiredEntriesAreDroppedOnLoad(t *testing.T) {
	now := time.Now()
	var pepper [32]byte
	pepper[0] = 7
	b := encodeRetired(pepper, map[[32]byte]time.Time{{1}: now.Add(-time.Second), {2}: now.Add(time.Minute)})
	got, retired, err := decodeRetired(b, now)
	if err != nil || got != pepper || len(retired) != 1 {
		t.Fatal(err, len(retired))
	}
	if _, ok := retired[[32]byte{2}]; !ok {
		t.Fatal("the live entry was dropped")
	}
}

// A damaged file costs this one restart its quarantine, never the start itself,
// and is not left to be read again.
func TestADamagedCodesFileIsLoggedAndRemoved(t *testing.T) {
	path := codesFile(t)
	var pepper [32]byte
	good := encodeRetired(pepper, map[[32]byte]time.Time{{1}: time.Now().Add(time.Minute)})
	for name, b := range map[string][]byte{
		"flipped bit": func() []byte { b := append([]byte(nil), good...); b[50] ^= 1; return b }(),
		"truncated":   good[:len(good)-3],
		"other file":  []byte("hello"),
	} {
		_ = os.WriteFile(path, b, 0o600)
		cfg := DefaultConfig()
		cfg.RetiredCodesFile = path
		s, err := New(cfg)
		if err != nil {
			t.Fatalf("%s: did not start: %v", name, err)
		}
		n := len(s.retired)
		s.cfg.RetiredCodesFile = "" // nothing to save from this one
		s.Close()
		if n != 0 {
			t.Fatalf("%s: damaged entries used", name)
		}
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s: damaged file left in place", name)
		}
	}
}

func TestAStopWithNoCodesWritesNothing(t *testing.T) {
	path := codesFile(t)
	s, _ := fixture(t, func(c *Config) { c.RetiredCodesFile = path })
	s.Close()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("an empty quarantine was written")
	}
}
