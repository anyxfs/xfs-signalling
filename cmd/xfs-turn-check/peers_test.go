package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestCheckPeersRequiresPublicPermission(t *testing.T) {
	for _, family := range []byte{1, 2} {
		t.Run(map[byte]string{1: "ipv4", 2: "ipv6"}[family], func(t *testing.T) {
			public := map[byte]string{1: "1.1.1.1", 2: "2606:4700:4700::1111"}[family]
			for _, allowPublic := range []bool{false, true} {
				seenPublic, released := false, false
				call := func(method uint16, extra ...stunAttr) (stunReply, error) {
					if method == stunRefresh {
						released = true
						return stunReply{class: 0x0100}, nil
					}
					if method != stunCreatePermission {
						t.Fatalf("unexpected method %d", method)
					}
					if bytes.Equal(extra[0].value, xorPeer(netip.MustParseAddr(public))) {
						seenPublic = true
						if allowPublic {
							return stunReply{class: 0x0100}, nil
						}
					}
					return stunReply{class: 0x0110, code: 403}, nil
				}
				granted, _, err := checkPeers(call, family)
				if !seenPublic || !released {
					t.Fatalf("public probed=%v allocation released=%v", seenPublic, released)
				}
				if allowPublic && (err != nil || len(granted) != 0) {
					t.Fatalf("valid filters: %v %v", granted, err)
				}
				if !allowPublic && (err == nil || !strings.Contains(err.Error(), public)) {
					t.Fatalf("deny-all must fail: %v", err)
				}
			}
		})
	}
}
