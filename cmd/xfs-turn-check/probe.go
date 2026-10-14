package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const stunCookie = 0x2112a442

// RFC 5766 sections 6.1, 6.2, 14.7: Allocate with REQUESTED-TRANSPORT UDP,
// deliberately without USERNAME or MESSAGE-INTEGRITY. This is a bounded
// deployment probe, not a complete TURN client.
func probeUnauth(endpoint string, timeout time.Duration) (int, string) {
	conn, err := net.DialTimeout("udp", endpoint, timeout)
	if err != nil {
		return probeFailure(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return probeFailure(err)
	}
	request := make([]byte, 28)
	binary.BigEndian.PutUint16(request[0:2], 0x0003)
	binary.BigEndian.PutUint16(request[2:4], 8)
	binary.BigEndian.PutUint32(request[4:8], stunCookie)
	if _, err := rand.Read(request[8:20]); err != nil {
		return probeFailure(err)
	}
	copy(request[20:], []byte{0, 0x19, 0, 4, 17, 0, 0, 0})
	if _, err := conn.Write(request); err != nil {
		return probeFailure(err)
	}
	response := make([]byte, 65535)
	for {
		n, err := conn.Read(response)
		if err != nil {
			return probeFailure(err)
		}
		b := response[:n]
		// Unrelated transactions cannot satisfy this probe or extend its deadline.
		if len(b) < 20 || !bytes.Equal(b[8:20], request[8:20]) {
			continue
		}
		return checkAllocate(b)
	}
}

func probeFailure(err error) (int, string) {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return 2, "TIMEOUT: no Allocate response"
	}
	return 1, fmt.Sprintf("FAIL: %v", err)
}

func checkAllocate(b []byte) (int, string) {
	if len(b) < 20 || binary.BigEndian.Uint32(b[4:8]) != stunCookie || int(binary.BigEndian.Uint16(b[2:4])) != len(b)-20 || len(b)%4 != 0 {
		return 1, "FAIL: malformed STUN response"
	}
	typ := binary.BigEndian.Uint16(b[:2])
	if typ != 0x0103 && typ != 0x0113 {
		return 1, "FAIL: unexpected STUN response type"
	}
	code, realm, nonce := 0, false, false
	for offset := 20; offset < len(b); {
		if len(b)-offset < 4 {
			return 1, "FAIL: truncated STUN attribute"
		}
		attr := binary.BigEndian.Uint16(b[offset:])
		size := int(binary.BigEndian.Uint16(b[offset+2:]))
		next := offset + 4 + (size+3)&^3
		if next > len(b) {
			return 1, "FAIL: truncated STUN attribute"
		}
		value := b[offset+4 : offset+4+size]
		switch attr {
		case 0x0009: // ERROR-CODE
			if size < 4 || value[2] > 6 || value[2] < 3 || value[3] > 99 {
				return 1, "FAIL: malformed ERROR-CODE"
			}
			code = int(value[2])*100 + int(value[3])
		case 0x0014:
			realm = realm || size > 0
		case 0x0015:
			nonce = nonce || size > 0
		}
		offset = next
	}
	if typ == 0x0103 {
		return 1, "开放中继！无凭据 Allocate 成功"
	}
	if code == 401 && realm && nonce {
		return 0, "OK: 401 with REALM/NONCE"
	}
	return 1, fmt.Sprintf("FAIL: expected 401 with REALM/NONCE (got %d)", code)
}
