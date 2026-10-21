package signal

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Fixed fields and labels only: never accept client-controlled metric names or
// labels (04 section 6.2). Counters live for this process, not on disk.
type metrics struct {
	rejected                       [6]atomic.Uint64
	created, paired                atomic.Uint64
	joinFail                       [3]atomic.Uint64
	resumeOK, resumeFail           atomic.Uint64
	turnOK, turnFail               atomic.Uint64
	keyRotations, keyWriteFailures atomic.Uint64
	noticesRejected                atomic.Uint64
}

const (
	rejectStopped = iota
	rejectGlobal
	rejectSources
	rejectRate
	rejectIP
	rejectPrefix
)

func (m *metrics) response(req request, msg message) {
	if m == nil {
		return
	}
	if msg["t"] == "error" {
		if req.Type == "resume" {
			m.resumeFail.Add(1)
		}
		if req.Type == "turn_credentials" {
			m.turnFail.Add(1)
		}
	}
}

func (m *metrics) emitted(msg message) {
	if m == nil {
		return
	}
	if msg["t"] == "turn_credentials_ok" {
		m.turnOK.Add(1)
	}
	if msg["t"] == "error" {
		switch msg["code"] {
		case 8010:
			m.joinFail[0].Add(1)
		case 8012:
			m.joinFail[1].Add(1)
		case 8013:
			m.joinFail[2].Add(1)
		}
	}
}

// MetricsHandler is deliberately separate from ServeHTTP: the public signal
// listener never exposes /metrics. The command binds this handler to loopback.
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		s.mu.Lock()
		active := len(s.clients)
		s.mu.Unlock()
		fmt.Fprintln(w, "# HELP sig_ws_active Current upgraded WebSocket connections.\n# TYPE sig_ws_active gauge")
		fmt.Fprintf(w, "sig_ws_active %d\n", active)
		family := func(name, help string) { fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name) }
		family("sig_connection_rejected_total", "Rejected signal upgrades by fixed HTTP status and reason.")
		for i, entry := range []struct{ status, reason string }{
			{"503", "stopped"}, {"503", "global_capacity"}, {"503", "source_capacity"},
			{"429", "connect_rate"}, {"429", "ip_connections"}, {"429", "prefix_connections"},
		} {
			fmt.Fprintf(w, "sig_connection_rejected_total{status=\"%s\",reason=\"%s\"} %d\n", entry.status, entry.reason, s.metrics.rejected[i].Load())
		}
		for _, entry := range []struct {
			name, help string
			value      uint64
		}{
			{"sig_room_created_total", "Rooms created by pairing code.", s.metrics.created.Load()},
			{"sig_room_paired_total", "Rooms paired by pairing code.", s.metrics.paired.Load()},
			{"sig_ticket_key_rotations_total", "In-process ticket key rotations after startup.", s.metrics.keyRotations.Load()},
			{"sig_ticket_key_write_failures_total", "Failed in-process ticket key writes after startup.", s.metrics.keyWriteFailures.Load()},
			{"sig_notices_rejected_total", "Notices files refused (signature, format or not newer); the current version stays.", s.metrics.noticesRejected.Load()},
		} {
			family(entry.name, entry.help)
			fmt.Fprintf(w, "%s %d\n", entry.name, entry.value)
		}
		family("sig_join_fail_total", "Error responses generated with code 8010, 8012 or 8013, including create and resume throttling.")
		for i, code := range []int{8010, 8012, 8013} {
			fmt.Fprintf(w, "sig_join_fail_total{code=\"%d\"} %d\n", code, s.metrics.joinFail[i].Load())
		}
		family("sig_resume_total", "Resume requests: success on rendezvous (two per room); failure on rejection or abandoned wait.")
		fmt.Fprintf(w, "sig_resume_total{result=\"success\"} %d\nsig_resume_total{result=\"failure\"} %d\n", s.metrics.resumeOK.Load(), s.metrics.resumeFail.Load())
		family("sig_turn_credentials_total", "TURN credential requests issued or rejected after protocol decoding.")
		fmt.Fprintf(w, "sig_turn_credentials_total{result=\"issued\"} %d\nsig_turn_credentials_total{result=\"rejected\"} %d\n", s.metrics.turnOK.Load(), s.metrics.turnFail.Load())
	})
}
