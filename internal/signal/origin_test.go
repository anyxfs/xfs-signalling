package signal

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestOriginHandshakePolicy(t *testing.T) {
	for _, configured := range []bool{false, true} {
		_, endpoint := fixture(t, func(c *Config) {
			c.ConnectCapacity = 100
			if configured {
				c.AllowedOrigins = []string{"https://Web.Example:443", "http://localhost:9000"}
			}
		})
		host := strings.TrimSuffix(strings.TrimPrefix(endpoint, "ws://"), "/signal")
		for _, tc := range []struct {
			origin  string
			allowed bool
		}{
			{"", true}, {"http://" + host, true}, {"https://" + host, true},
			{"https://web.example", configured}, {"http://localhost:9000", configured},
			{"http://web.example", false}, {"https://web.example:444", false},
			{"https://web.example.evil", false}, {"null", false},
			{"https://web.example/path", false}, {"https://web.example?x=1", false},
			{"https://web.example@evil.example", false},
		} {
			h := http.Header{}
			if tc.origin != "" {
				h.Set("Origin", tc.origin)
			}
			d := websocket.Dialer{Subprotocols: []string{Subprotocol}}
			c, resp, err := d.Dial(endpoint, h)
			if c != nil {
				c.Close()
			}
			if tc.allowed && err != nil {
				t.Fatalf("configured=%v origin=%q: %v", configured, tc.origin, err)
			}
			if !tc.allowed && (err == nil || resp == nil || resp.StatusCode != 403) {
				t.Fatalf("configured=%v origin=%q was not refused with 403", configured, tc.origin)
			}
		}
	}
}

func TestOriginConfigValidationAndCopy(t *testing.T) {
	for _, raw := range []string{"*", "null", "https://*.example", "https://web.example/", "https://u:p@web.example", "https://web.example?", "https://web.example#", "ws://web.example", "https://web.example:", "https://web.example:0", "https://web.example:65536", ""} {
		cfg := DefaultConfig()
		cfg.AllowedOrigins = []string{raw}
		if s, err := New(cfg); err == nil {
			s.Close()
			t.Fatalf("accepted %q", raw)
		}
	}
	origins := []string{"https://web.example"}
	policy, err := originPolicy(origins)
	if err != nil {
		t.Fatal(err)
	}
	origins[0] = "https://evil.example"
	r, _ := http.NewRequest("GET", "https://signal.example/signal", nil)
	r.Header.Set("Origin", "https://evil.example")
	if policy(r) {
		t.Fatal("configuration mutated after validation")
	}
	r.Header["Origin"] = []string{"https://web.example", "https://evil.example"}
	if policy(r) {
		t.Fatal("multiple origins accepted")
	}
}
