package signal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var langs4 = map[string]string{"zh-CN": "x", "zh-TW": "x", "en": "x", "ja": "x"}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sampleNotice(id string, starts, ends time.Time) Notice {
	return Notice{ID: id, Level: "info", StartsAt: starts, EndsAt: ends, Title: copyLangs(), Body: copyLangs()}
}

func copyLangs() map[string]string {
	m := map[string]string{}
	for k, v := range langs4 {
		m[k] = v
	}
	return m
}

// seal signs an inner set the way xfs-notice does.
func seal(t *testing.T, priv ed25519.PrivateKey, key string, set any) []byte {
	t.Helper()
	inner, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(map[string]string{
		"payload": base64.StdEncoding.EncodeToString(inner),
		"sig":     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, inner)),
		"key":     key,
	})
	return env
}

func validSet(issued time.Time) NoticeSet {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	return NoticeSet{V: 1, IssuedAt: issued, RelayPaused: true, Notices: []Notice{sampleNotice("maint-1", now, now.Add(time.Hour))}}
}

func TestOpenNoticesValid(t *testing.T) {
	pub, priv := testKey(t)
	set := validSet(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC))
	got, err := OpenNotices(seal(t, priv, "n1", set), map[string]ed25519.PublicKey{"n1": pub})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RelayPaused || len(got.Notices) != 1 || got.Notices[0].ID != "maint-1" {
		t.Fatalf("got %+v", got)
	}
}

func TestWatcherRetriesFailedCacheWrite(t *testing.T) {
	testWatcherRetriesFailedCache(t, false)
}

func TestWatcherRetriesFailedCacheRename(t *testing.T) {
	testWatcherRetriesFailedCache(t, true)
}

func testWatcherRetriesFailedCache(t *testing.T, rename bool) {
	t.Helper()
	pub, priv := testKey(t)
	_, path, cache := watcherFiles(t)
	t1 := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	old := seal(t, priv, "n1", validSet(t1))
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	w := newNoticeWatcher(path, cache, map[string]ed25519.PublicKey{"n1": pub})
	// Directories deterministically prevent either writing or replacing the cache.
	blocked := cache + ".tmp"
	if rename {
		blocked = cache
		if err := os.Remove(cache); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	newest := seal(t, priv, "n1", validSet(t1.Add(time.Hour)))
	if err := os.WriteFile(path, newest, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.poll(); changed || err == nil {
		t.Fatalf("cache failure: changed=%v err=%v", changed, err)
	}
	if !w.current().IssuedAt.Equal(t1) {
		t.Fatal("cache failure replaced current version")
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.poll(); !changed || err != nil {
		t.Fatalf("retry: changed=%v err=%v", changed, err)
	}
	if got, err := os.ReadFile(cache); err != nil || string(got) != string(newest) {
		t.Fatalf("cache retry: %v", err)
	}
}

func TestOpenNoticesRequiresTimes(t *testing.T) {
	pub, priv := testKey(t)
	for _, field := range []string{"issuedAt", "startsAt", "endsAt"} {
		for _, value := range []any{nil, "null", "0001-01-01T00:00:00Z"} {
			t.Run(fmt.Sprintf("%s/%v", field, value), func(t *testing.T) {
				var inner map[string]any
				raw, _ := json.Marshal(validSet(time.Now()))
				if err := json.Unmarshal(raw, &inner); err != nil {
					t.Fatal(err)
				}
				target := inner
				if field != "issuedAt" {
					target = inner["notices"].([]any)[0].(map[string]any)
				}
				if value == nil {
					delete(target, field)
				} else if value == "null" {
					target[field] = nil
				} else {
					target[field] = value
				}
				if _, err := OpenNotices(seal(t, priv, "n1", inner), map[string]ed25519.PublicKey{"n1": pub}); err == nil {
					t.Fatal("accepted missing or zero time")
				}
			})
		}
	}
}

func TestOpenNoticesRejects(t *testing.T) {
	pub, priv := testKey(t)
	_, other := testKey(t)
	keys := map[string]ed25519.PublicKey{"n1": pub}
	issued := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	mutate := func(f func(*NoticeSet)) NoticeSet { s := validSet(issued); f(&s); return s }
	cases := map[string][]byte{
		"bad signature":  seal(t, other, "n1", validSet(issued)),
		"unknown key":    seal(t, priv, "n9", validSet(issued)),
		"version 2":      seal(t, priv, "n1", mutate(func(s *NoticeSet) { s.V = 2 })),
		"missing ja":     seal(t, priv, "n1", mutate(func(s *NoticeSet) { delete(s.Notices[0].Title, "ja") })),
		"ends <= starts": seal(t, priv, "n1", mutate(func(s *NoticeSet) { s.Notices[0].EndsAt = s.Notices[0].StartsAt })),
		"bad level":      seal(t, priv, "n1", mutate(func(s *NoticeSet) { s.Notices[0].Level = "critical" })),
		"http link":      seal(t, priv, "n1", mutate(func(s *NoticeSet) { s.Notices[0].Link = map[string]string{"en": "http://x"} })),
		"duplicate id":   seal(t, priv, "n1", mutate(func(s *NoticeSet) { s.Notices = append(s.Notices, s.Notices[0]) })),
		"bad id":         seal(t, priv, "n1", mutate(func(s *NoticeSet) { s.Notices[0].ID = "Maint 1" })),
		"too many": seal(t, priv, "n1", mutate(func(s *NoticeSet) {
			for i := 0; i < 20; i++ {
				n := s.Notices[0]
				n.ID = "n-" + string(rune('a'+i))
				s.Notices = append(s.Notices, n)
			}
		})),
		"not json": []byte("{"),
	}
	for name, env := range cases {
		if _, err := OpenNotices(env, keys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLintNoticeRejectsURLAndCallToAction(t *testing.T) {
	n := sampleNotice("a", time.Now(), time.Now().Add(time.Hour))
	if err := LintNotice(n); err != nil {
		t.Fatalf("plain notice rejected: %v", err)
	}
	for _, text := range []string{"see https://a.cn now", "请点击下方按钮", "visit www.anyxfs.com", "Click below"} {
		bad := sampleNotice("a", time.Now(), time.Now().Add(time.Hour))
		bad.Body["zh-CN"] = text
		if err := LintNotice(bad); err == nil {
			t.Errorf("%q accepted", text)
		}
	}
}

func watcherFiles(t *testing.T) (dir, path, cache string) {
	dir = t.TempDir()
	return dir, filepath.Join(dir, "notices.json"), filepath.Join(dir, "notices.last.json")
}

func TestWatcherReplacesOnlyNewer(t *testing.T) {
	pub, priv := testKey(t)
	_, path, cache := watcherFiles(t)
	t0 := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	t1, t2 := t0.Add(time.Hour), t0.Add(2*time.Hour)
	write := func(issued time.Time) []byte {
		env := seal(t, priv, "n1", validSet(issued))
		if err := os.WriteFile(path, env, 0o644); err != nil {
			t.Fatal(err)
		}
		return env
	}
	write(t1)
	w := newNoticeWatcher(path, cache, map[string]ed25519.PublicKey{"n1": pub})
	if !w.current().IssuedAt.Equal(t1) {
		t.Fatalf("start: %v", w.current().IssuedAt)
	}
	write(t0)
	if changed, err := w.poll(); changed || err == nil {
		t.Fatalf("older accepted: changed=%v err=%v", changed, err)
	}
	newest := write(t2)
	if changed, err := w.poll(); !changed || err != nil {
		t.Fatalf("newer refused: changed=%v err=%v", changed, err)
	}
	if !w.current().IssuedAt.Equal(t2) {
		t.Fatalf("now %v", w.current().IssuedAt)
	}
	if got, _ := os.ReadFile(cache); string(got) != string(newest) {
		t.Fatalf("cache not updated")
	}
}

func TestWatcherKeepsOldOnTruncatedFile(t *testing.T) {
	pub, priv := testKey(t)
	_, path, cache := watcherFiles(t)
	t1 := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	_ = os.WriteFile(path, seal(t, priv, "n1", validSet(t1)), 0o644)
	w := newNoticeWatcher(path, cache, map[string]ed25519.PublicKey{"n1": pub})
	full := seal(t, priv, "n1", validSet(t1.Add(time.Hour)))
	_ = os.WriteFile(path, full[:len(full)/2], 0o644)
	if changed, err := w.poll(); changed || err == nil {
		t.Fatalf("half file accepted")
	}
	if !w.current().IssuedAt.Equal(t1) {
		t.Fatalf("old version lost")
	}
	_ = os.WriteFile(path, full, 0o644)
	if changed, err := w.poll(); !changed || err != nil {
		t.Fatalf("complete file refused: %v", err)
	}
}

func TestWatcherUnchangedFileIsNotReparsed(t *testing.T) {
	pub, priv := testKey(t)
	_, path, cache := watcherFiles(t)
	_ = os.WriteFile(path, seal(t, priv, "n1", validSet(time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC))), 0o644)
	w := newNoticeWatcher(path, cache, map[string]ed25519.PublicKey{"n1": pub})
	// Dropping the key would make any re-parse fail: an unchanged file must not be parsed again.
	w.keys = map[string]ed25519.PublicKey{}
	if changed, err := w.poll(); changed || err != nil {
		t.Fatalf("unchanged file re-read: changed=%v err=%v", changed, err)
	}
}

func TestWatcherStartsFromCacheWhenFileMissing(t *testing.T) {
	pub, priv := testKey(t)
	_, path, cache := watcherFiles(t)
	t1 := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	_ = os.WriteFile(cache, seal(t, priv, "n1", validSet(t1)), 0o644)
	w := newNoticeWatcher(path, cache, map[string]ed25519.PublicKey{"n1": pub})
	if !w.current().IssuedAt.Equal(t1) {
		t.Fatalf("cache not loaded")
	}
}

func TestActiveFiltersAndStripsLinks(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	live := sampleNotice("live", now.Add(-time.Hour), now.Add(time.Hour))
	live.Link = map[string]string{"en": "https://www.anyxfs.com/en/download/"}
	set := NoticeSet{V: 1, Notices: []Notice{
		live,
		sampleNotice("later", now.Add(time.Hour), now.Add(2*time.Hour)),
		sampleNotice("gone", now.Add(-2*time.Hour), now),
	}}
	android := set.active(now, "android")
	if len(android) != 1 || android[0]["id"] != "live" {
		t.Fatalf("android: %v", android)
	}
	if _, ok := android[0]["link"]; !ok {
		t.Fatal("android lost the link")
	}
	if s, ok := android[0]["startsAt"].(int64); !ok || s != now.Add(-time.Hour).Unix() {
		t.Fatalf("startsAt %v", android[0]["startsAt"])
	}
	for _, p := range []string{"ios", "macos"} {
		if _, ok := set.active(now, p)[0]["link"]; ok {
			t.Errorf("%s got a link", p)
		}
	}
}

func TestOpenNoticesErrorNamesTheNotice(t *testing.T) {
	pub, priv := testKey(t)
	s := validSet(time.Now())
	delete(s.Notices[0].Body, "en")
	_, err := OpenNotices(seal(t, priv, "n1", s), map[string]ed25519.PublicKey{"n1": pub})
	if err == nil || !strings.Contains(err.Error(), "maint-1") {
		t.Fatalf("error %v does not name the notice", err)
	}
}
