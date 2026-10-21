package main

import (
	"strings"
	"testing"
)

func TestRejectUnsafeListeners(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8787", ":8787", "[::]:8787", "localhost:8787", "invalid"} {
		if err := run(addr, "", "", 64*1024, 10, 10, 60); err == nil {
			t.Fatalf("accepted plaintext listener %s", addr)
		}
	}
	if err := run("127.0.0.1:8787", "cert.pem", "", 64*1024, 10, 10, 60); err == nil {
		t.Fatal("accepted missing TLS key")
	}
}

func TestParseNoticeKeys(t *testing.T) {
	keys, err := parseNoticeKeys("n1:" + strings.Repeat("A", 43) + "=,n2:" + strings.Repeat("B", 43) + "=")
	if err != nil || len(keys) != 2 || len(keys["n1"]) != 32 {
		t.Fatalf("keys %v err %v", keys, err)
	}
	for _, bad := range []string{"", "n1", "n1:short", ":" + strings.Repeat("A", 43) + "=", "n1:" + strings.Repeat("A", 43) + "=,n1:" + strings.Repeat("A", 43) + "="} {
		if _, err := parseNoticeKeys(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
