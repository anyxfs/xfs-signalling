package signal

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// noticeFixture: a server reading a signed notices file in a temp dir.
func noticeFixture(t *testing.T, set NoticeSet, change func(*Config)) (*Server, string, string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := testKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "notices.json")
	if err := os.WriteFile(path, seal(t, priv, "n1", set), 0o644); err != nil {
		t.Fatal(err)
	}
	s, url := fixture(t, func(c *Config) {
		c.NoticesFile, c.NoticesCache = path, filepath.Join(dir, "notices.last.json")
		c.NoticesKeys = map[string]ed25519.PublicKey{"n1": pub}
		if change != nil {
			change(c)
		}
	})
	return s, url, path, priv
}

func liveSet(issued time.Time, paused bool) NoticeSet {
	now := time.Now()
	n := sampleNotice("maint-1", now.Add(-time.Hour), now.Add(time.Hour))
	n.Link = map[string]string{"en": "https://www.anyxfs.com/en/download/"}
	return NoticeSet{V: 1, IssuedAt: issued, RelayPaused: paused, Notices: []Notice{n, sampleNotice("later", now.Add(time.Hour), now.Add(2*time.Hour))}}
}

func helloAs(t *testing.T, c *websocket.Conn, client string) message {
	t.Helper()
	send(t, c, message{"t": "hello", "v": 1, "client": client})
	return receive(t, c, "hello_ok")
}

func TestHelloCarriesActiveNotices(t *testing.T) {
	_, url, _, _ := noticeFixture(t, liveSet(time.Now(), false), nil)
	m := helloAs(t, dial(t, url), "anyxfs/1.0.1 (android)")
	list, _ := m["notices"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["id"] != "maint-1" {
		t.Fatalf("notices %v", m["notices"])
	}
	if _, ok := list[0].(map[string]any)["link"]; !ok {
		t.Fatal("android lost the link")
	}
}

func TestHelloStripsLinksForApple(t *testing.T) {
	_, url, _, _ := noticeFixture(t, liveSet(time.Now(), false), nil)
	list := helloAs(t, dial(t, url), "anyxfs/1.0.0 (ios)")["notices"].([]any)
	if _, ok := list[0].(map[string]any)["link"]; ok {
		t.Fatal("ios got a link")
	}
}

func TestUnknownClientTagStillServed(t *testing.T) {
	_, url, _, _ := noticeFixture(t, liveSet(time.Now(), false), nil)
	list := helloAs(t, dial(t, url), "xfs-rust-dev")["notices"].([]any)
	if len(list) != 1 {
		t.Fatalf("notices %v", list)
	}
}

func TestHelloWithoutNoticesFileHasEmptyList(t *testing.T) {
	_, url := fixture(t, nil)
	m := helloAs(t, dial(t, url), "anyxfs/1.0.1 (windows)")
	if list, ok := m["notices"].([]any); !ok || len(list) != 0 {
		t.Fatalf("notices %v", m["notices"])
	}
}

func TestPausedRelayAnswers8032WithReason(t *testing.T) {
	_, url, _, _ := noticeFixture(t, liveSet(time.Now(), true), withTURN)
	_, sk, _ := ed25519.GenerateKey(nil)
	c := dial(t, url)
	at, nonce := helloTURN(t, c)
	send(t, c, turnRequest(sk, at, nonce))
	m := receive(t, c, "error")
	if m["code"] != float64(8032) || m["reason"] != "paused" {
		t.Fatalf("paused relay answered %v", m)
	}
}

func TestNoRelayConfiguredHasNoReason(t *testing.T) {
	_, url := fixture(t, nil)
	_, sk, _ := ed25519.GenerateKey(nil)
	c := dial(t, url)
	at, nonce := helloTURN(t, c)
	send(t, c, turnRequest(sk, at, nonce))
	m := receive(t, c, "error")
	if _, ok := m["reason"]; m["code"] != float64(8032) || ok {
		t.Fatalf("no relay answered %v", m)
	}
}

func TestNoticesReloadWithoutRestart(t *testing.T) {
	s, url, path, priv := noticeFixture(t, liveSet(time.Now().Add(-time.Hour), false), nil)
	next := liveSet(time.Now(), false)
	next.Notices[0].ID = "maint-2"
	if err := os.WriteFile(path, seal(t, priv, "n1", next), 0o644); err != nil {
		t.Fatal(err)
	}
	s.pollNotices()
	list := helloAs(t, dial(t, url), "anyxfs/1.0.1 (windows)")["notices"].([]any)
	if list[0].(map[string]any)["id"] != "maint-2" {
		t.Fatalf("still %v", list)
	}
}

func TestBadNoticesFileCounted(t *testing.T) {
	s, _, path, _ := noticeFixture(t, liveSet(time.Now(), false), nil)
	if err := os.WriteFile(path, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.pollNotices()
	if s.metrics.noticesRejected.Load() != 1 {
		t.Fatalf("rejected %d", s.metrics.noticesRejected.Load())
	}
}
