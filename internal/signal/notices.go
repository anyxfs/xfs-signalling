package signal

// Signed service notices (design 2026-10-19-signalling-notices-design.md): the
// operator signs notices.json on their own machine and uploads it to the host;
// the server checks it every few seconds, keeps the last good version (in memory
// and in a cache file for restarts) and hands the live entries to every client in
// hello_ok. A file that fails any check leaves the current version in place.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// NoticeLanguages: every notice carries its title and body in all of them.
var NoticeLanguages = []string{"zh-CN", "zh-TW", "en", "ja"}

const maxNotices = 20

type Notice struct {
	ID       string            `json:"id"`
	Level    string            `json:"level"` // info | warning
	StartsAt time.Time         `json:"startsAt"`
	EndsAt   time.Time         `json:"endsAt"` // the display window, not the event's
	Title    map[string]string `json:"title"`
	Body     map[string]string `json:"body"`
	Link     map[string]string `json:"link,omitempty"`
}

type NoticeSet struct {
	V           int       `json:"v"`
	IssuedAt    time.Time `json:"issuedAt"`
	RelayPaused bool      `json:"relayPaused"`
	Notices     []Notice  `json:"notices"`
}

type noticeEnvelope struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
	Key     string `json:"key"`
}

var noticeID = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// OpenNotices verifies the envelope's signature over the payload's exact bytes,
// then the notices themselves.
func OpenNotices(envelope []byte, keys map[string]ed25519.PublicKey) (NoticeSet, error) {
	var env noticeEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return NoticeSet{}, fmt.Errorf("envelope: %w", err)
	}
	pub, ok := keys[env.Key]
	if !ok {
		return NoticeSet{}, fmt.Errorf("unknown key %q", env.Key)
	}
	payload, err1 := base64.StdEncoding.DecodeString(env.Payload)
	sig, err2 := base64.StdEncoding.DecodeString(env.Sig)
	if err1 != nil || err2 != nil || !ed25519.Verify(pub, payload, sig) {
		return NoticeSet{}, errors.New("bad signature")
	}
	var set NoticeSet
	if err := json.Unmarshal(payload, &set); err != nil {
		return NoticeSet{}, fmt.Errorf("payload: %w", err)
	}
	return set, set.check()
}

func (s NoticeSet) check() error {
	if s.V != 1 {
		return fmt.Errorf("version %d", s.V)
	}
	if s.IssuedAt.IsZero() {
		return errors.New("issuedAt is required and must be nonzero")
	}
	if len(s.Notices) > maxNotices {
		return fmt.Errorf("%d notices, at most %d", len(s.Notices), maxNotices)
	}
	seen := map[string]bool{}
	for _, n := range s.Notices {
		if !noticeID.MatchString(n.ID) {
			return fmt.Errorf("notice id %q: lower-case letters, digits and '-' only", n.ID)
		}
		if seen[n.ID] {
			return fmt.Errorf("notice %s: id used twice", n.ID)
		}
		seen[n.ID] = true
		if n.StartsAt.IsZero() || n.EndsAt.IsZero() {
			return fmt.Errorf("notice %s: startsAt and endsAt are required and must be nonzero", n.ID)
		}
		if n.Level != "info" && n.Level != "warning" {
			return fmt.Errorf("notice %s: level %q", n.ID, n.Level)
		}
		if !n.EndsAt.After(n.StartsAt) {
			return fmt.Errorf("notice %s: endsAt must be after startsAt", n.ID)
		}
		for _, l := range NoticeLanguages {
			if strings.TrimSpace(n.Title[l]) == "" || strings.TrimSpace(n.Body[l]) == "" {
				return fmt.Errorf("notice %s: title and body need %s", n.ID, l)
			}
		}
		for l, u := range n.Link {
			if !strings.HasPrefix(u, "https://") {
				return fmt.Errorf("notice %s: %s link must be https", n.ID, l)
			}
		}
	}
	return nil
}

var noticeLint = []string{"http://", "https://", "www.", "点击", "點擊", "click", "クリック"}

// LintNotice refuses text that reads like a link or a call to action: links belong
// in Link, which Apple platforms never show (App Store rules on donations).
func LintNotice(n Notice) error {
	for _, field := range []map[string]string{n.Title, n.Body} {
		for l, text := range field {
			low := strings.ToLower(text)
			for _, bad := range noticeLint {
				if strings.Contains(low, bad) {
					return fmt.Errorf("notice %s (%s): %q does not belong in the text; use link", n.ID, l, bad)
				}
			}
		}
	}
	return nil
}

// active: the entries to show at now, times as Unix seconds; Apple platforms get no links.
func (s NoticeSet) active(now time.Time, platform string) []message {
	out := []message{}
	for _, n := range s.Notices {
		if now.Before(n.StartsAt) || !now.Before(n.EndsAt) {
			continue
		}
		m := message{"id": n.ID, "level": n.Level, "startsAt": n.StartsAt.Unix(), "endsAt": n.EndsAt.Unix(), "title": n.Title, "body": n.Body}
		if len(n.Link) > 0 && platform != "ios" && platform != "macos" {
			m["link"] = n.Link
		}
		out = append(out, m)
	}
	return out
}

type noticeWatcher struct {
	path, cache string
	keys        map[string]ed25519.PublicKey
	mu          sync.Mutex
	set         NoticeSet
	sum         [32]byte
}

// newNoticeWatcher starts from the cache (last good version), then the file.
func newNoticeWatcher(path, cache string, keys map[string]ed25519.PublicKey) *noticeWatcher {
	w := &noticeWatcher{path: path, cache: cache, keys: keys}
	if data, err := os.ReadFile(cache); err == nil {
		if set, err := OpenNotices(data, keys); err == nil {
			w.set = set
		}
	}
	_, _ = w.poll()
	return w
}

// poll reads the file again when its content changed. A file that does not
// verify, or is not newer than the current version, changes nothing.
func (w *noticeWatcher) poll() (bool, error) {
	data, err := os.ReadFile(w.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	sum := sha256.Sum256(data)
	w.mu.Lock()
	defer w.mu.Unlock()
	if sum == w.sum {
		return false, nil
	}
	w.sum = sum // a bad file is reported once, not every few seconds
	set, err := OpenNotices(data, w.keys)
	if err != nil {
		return false, err
	}
	if !w.set.IssuedAt.IsZero() && !set.IssuedAt.After(w.set.IssuedAt) {
		return false, fmt.Errorf("issuedAt %s is not after the current %s", set.IssuedAt.Format(time.RFC3339), w.set.IssuedAt.Format(time.RFC3339))
	}
	if w.cache != "" {
		tmp := w.cache + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			w.sum = [32]byte{} // retry this version once storage is available
			return false, fmt.Errorf("write notices cache: %w", err)
		}
		if err := os.Rename(tmp, w.cache); err != nil {
			_ = os.Remove(tmp)
			w.sum = [32]byte{}
			return false, fmt.Errorf("replace notices cache: %w", err)
		}
	}
	w.set = set
	return true, nil
}

func (w *noticeWatcher) current() NoticeSet {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.set
}
