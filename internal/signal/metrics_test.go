package signal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func scrape(s *Server) string {
	w := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	return w.Body.String()
}

func wantMetric(t *testing.T, body, line string) {
	t.Helper()
	if !strings.Contains(body, "\n"+line+"\n") {
		t.Fatalf("missing %s in\n%s", line, body)
	}
}

func TestMetricsPairResumeTURNAndPrivacy(t *testing.T) {
	s, url := fixture(t, withTURN)
	a, b := newParty(), newParty()
	ta, tb := pairAndReady(t, url, a, b)
	ca, cb := resumed(t, url, a, ta, true), resumed(t, url, b, tb, false)
	receive(t, ca, "room_resumed")
	receive(t, cb, "room_resumed")
	bad := resumed(t, url, newParty(), ta, true)
	expectError(t, bad, 8060)
	c := dial(t, url)
	at, nonce := helloTURN(t, c)
	send(t, c, turnRequest(a.sk, at, nonce))
	receive(t, c, "turn_credentials_ok")
	send(t, c, turnRequest(a.sk, at, [32]byte{}))
	expectError(t, c, 8031)
	send(t, c, message{"t": "join_room", "code": "99999999"})
	expectError(t, c, 8010)
	body := scrape(s)
	for _, line := range []string{
		"sig_ws_active 6", "sig_room_created_total 1", "sig_room_paired_total 1",
		`sig_resume_total{result="success"} 2`, `sig_resume_total{result="failure"} 1`,
		`sig_turn_credentials_total{result="issued"} 1`, `sig_turn_credentials_total{result="rejected"} 1`,
		`sig_join_fail_total{code="8010"} 1`,
	} {
		wantMetric(t, body, line)
	}
	for _, secret := range []string{"127.0.0.1", "99999999", ta, tb, b64.EncodeToString(a.pk), string(s.cfg.TURNSecret)} {
		if strings.Contains(body, secret) {
			t.Fatal("metrics leaked an identifier")
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 404 {
		t.Fatal("public metrics exposed")
	}
	s.Close()
	wantMetric(t, scrape(s), "sig_ws_active 0")
}

func TestMetricsRejectionReasons(t *testing.T) {
	for _, tc := range []struct {
		reason string
		status int
		setup  func(*Server)
	}{
		{"stopped", 503, func(s *Server) { s.closed = true }},
		{"global_capacity", 503, func(s *Server) { s.connections = s.cfg.MaxConnections }},
		{"source_capacity", 503, func(s *Server) { s.cfg.MaxSources = 2; s.sources["other"] = &sourceBudget{} }},
		{"connect_rate", 429, func(s *Server) {
			s.sources["192.0.2.1"] = &sourceBudget{connect: bucket{updated: time.Now().Add(time.Hour)}}
		}},
		{"ip_connections", 429, func(s *Server) { s.sources["192.0.2.1"] = &sourceBudget{conns: s.cfg.IPConnections} }},
		{"prefix_connections", 429, func(s *Server) { s.sources["192.0.2.0/24"] = &sourceBudget{conns: s.cfg.PrefixConnections} }},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			s, _ := fixture(t, nil)
			s.mu.Lock()
			tc.setup(s)
			s.mu.Unlock()
			r := httptest.NewRequest("GET", "/signal", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			r.Header.Set("Sec-WebSocket-Protocol", Subprotocol)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatal(w.Code)
			}
			status := "429"
			if tc.status == 503 {
				status = "503"
			}
			wantMetric(t, scrape(s), `sig_connection_rejected_total{status="`+status+`",reason="`+tc.reason+`"} 1`)
			s.mu.Lock()
			s.closed = false
			s.mu.Unlock()
		})
	}
}

func TestMetricsRotationAndConcurrentScrapes(t *testing.T) {
	s, _ := fixture(t, func(c *Config) { c.TicketKeyFile = keyFile(t) })
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.tickets.path = filepath.Join(blocker, "keys")
	s.sweep(time.Now().Add(ticketKeyLife + time.Minute))
	s.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = scrape(s)
			}
		}()
	}
	wg.Wait()
	body := scrape(s)
	wantMetric(t, body, "sig_ticket_key_rotations_total 1")
	wantMetric(t, body, "sig_ticket_key_write_failures_total 1")
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		w := httptest.NewRecorder()
		s.MetricsHandler().ServeHTTP(w, httptest.NewRequest(method, "/metrics", nil))
		if w.Code != 405 {
			t.Fatal(w.Code)
		}
	}
}

func TestMetricsFrozenAndThrottledErrors(t *testing.T) {
	s, _ := fixture(t, nil)
	now := time.Now()
	c := &client{metrics: &s.metrics, send: make(chan outbound, 16), done: make(chan struct{}), source: "ip", prefix: "prefix"}
	s.mu.Lock()
	s.sources[c.source] = &sourceBudget{last: now, failures: make([]time.Time, 10)}
	for i := range s.sources[c.source].failures {
		s.sources[c.source].failures[i] = now
	}
	s.sources[c.prefix] = &sourceBudget{last: now}
	s.mu.Unlock()
	s.dispatch(c, request{Type: "join_room", Code: "99999999"}, now)
	respond(c, request{Type: "join_room"}, c.pending)
	s.dispatch(c, request{Type: "join_room", Code: "99999999"}, now)
	wantMetric(t, scrape(s), `sig_join_fail_total{code="8013"} 1`)
	wantMetric(t, scrape(s), `sig_join_fail_total{code="8012"} 1`)
}

func TestMetricsResumeWaitFailures(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		s, url := fixture(t, nil)
		a, b := newParty(), newParty()
		ta, _ := pairAndReady(t, url, a, b)
		c := resumed(t, url, a, ta, true)
		// A pong orders the preceding resume without a scheduling-dependent sleep.
		send(t, c, message{"t": "ping"})
		receive(t, c, "pong")
		if timeout {
			s.mu.Lock()
			s.sweep(time.Now().Add(resumeSlotLife + time.Second))
			s.mu.Unlock()
			expectError(t, c, 8021)
		} else {
			c.Close()
			s.Close() // waits for handler cleanup
		}
		wantMetric(t, scrape(s), `sig_resume_total{result="failure"} 1`)
		wantMetric(t, scrape(s), `sig_resume_total{result="success"} 0`)
	}
}
