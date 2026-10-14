package main

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeUnauth(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typ   uint16
		attrs []byte
		code  int
		text  string
	}{
		{"challenge", 0x0113, []byte{0, 9, 0, 4, 0, 0, 4, 1, 0, 20, 0, 1, 'r', 0, 0, 0, 0, 21, 0, 1, 'n', 0, 0, 0}, 0, "OK"},
		{"open relay", 0x0103, nil, 1, "开放中继！"},
		{"timeout", 0, nil, 2, "TIMEOUT"},
		{"missing nonce", 0x0113, []byte{0, 9, 0, 4, 0, 0, 4, 1, 0, 20, 0, 1, 'r', 0, 0, 0}, 1, "FAIL"},
		{"truncated attr", 0x0113, []byte{0, 20, 0, 8}, 1, "FAIL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 100)
				n, addr, err := server.ReadFrom(buf)
				if err != nil {
					t.Error(err)
					return
				}
				if n != 28 || binary.BigEndian.Uint16(buf[:2]) != 3 || binary.BigEndian.Uint32(buf[4:8]) != stunCookie || string(buf[20:28]) != string([]byte{0, 25, 0, 4, 17, 0, 0, 0}) {
					t.Error("not an unauthenticated UDP Allocate")
					return
				}
				if tc.typ == 0 {
					return
				}
				reply := append([]byte(nil), buf[:20]...)
				binary.BigEndian.PutUint16(reply[:2], tc.typ)
				binary.BigEndian.PutUint16(reply[2:4], uint16(len(tc.attrs)))
				reply = append(reply, tc.attrs...)
				if _, err := server.WriteTo(reply, addr); err != nil {
					t.Error(err)
				}
			}()
			code, message := probeUnauth(server.LocalAddr().String(), 150*time.Millisecond)
			<-done
			if code != tc.code || !strings.Contains(message, tc.text) {
				t.Fatalf("got %d %q", code, message)
			}
		})
	}
}
