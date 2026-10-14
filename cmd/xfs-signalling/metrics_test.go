package main

import (
	"net/http"
	"testing"
)

func TestMetricsLoopbackOnly(t *testing.T) {
	for _, addr := range []string{":9000", "0.0.0.0:9000", "[::]:9000", "192.0.2.1:9000", "localhost:9000", "invalid"} {
		if err := validateMetricsListen(addr); err == nil {
			t.Fatalf("accepted %q", addr)
		}
	}
	for _, addr := range []string{"", "127.0.0.1:0", "[::1]:9000"} {
		if err := validateMetricsListen(addr); err != nil {
			t.Fatal(err)
		}
	}
	s, l, err := metricsServer("", http.NotFoundHandler())
	if err != nil || s != nil || l != nil {
		t.Fatal("metrics enabled by default")
	}
	s, l, err = metricsServer("127.0.0.1:0", http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer s.Close()
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	resp, err := http.Get("http://" + l.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	s.Close()
	if err := <-done; err != http.ErrServerClosed {
		t.Fatal(err)
	}
}
