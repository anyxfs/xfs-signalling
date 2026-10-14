package main

import "testing"

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
