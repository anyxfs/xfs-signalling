package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Peers a correctly configured relay must refuse (denied-peer-ip in
// deploy/turnserver.conf). ::ffff:127.0.0.1 is CVE-2026-27624: coturn before
// 4.9 mapped v4-mapped addresses to IPv4 after the deny check. Those forms only
// reach that path on an IPv6 allocation (RFC 6156), so IPv6 peers are tried on
// a second, IPv6 allocation.
var forbiddenPeers = map[byte][]string{
	1: {"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "100.64.0.1", "169.254.0.23"},
	2: {"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.0.23", "::1", "fd00::1", "fe80::1"},
}

const (
	stunAllocate         = 0x0003
	stunRefresh          = 0x0004
	stunCreatePermission = 0x0008
	attrUsername         = 0x0006
	attrIntegrity        = 0x0008
	attrErrorCode        = 0x0009
	attrLifetime         = 0x000d
	attrXorPeer          = 0x0012
	attrRealm            = 0x0014
	attrNonce            = 0x0015
	attrFamily           = 0x0017
	attrTransport        = 0x0019
)

type stunAttr struct {
	typ   uint16
	value []byte
}

type stunReply struct {
	class uint16 // 0x0100 success, 0x0110 error
	code  int
	attrs map[uint16][]byte
}

type stunCaller func(method uint16, extra ...stunAttr) (stunReply, error)

// probePeers authenticates Allocates with the given (time-limited) credentials,
// then asks for a permission to each forbidden peer. Exit 0 only if every one is
// refused; 1 if any is granted or the exchange fails; 2 on timeout. Each address
// family gets its own socket: one 5-tuple holds one allocation (437 otherwise).
func probePeers(endpoint, user, pass string, timeout time.Duration) (int, string) {
	var granted []string
	report := ""
	for _, family := range []byte{1, 2} {
		code, g, rep := probeFamily(endpoint, user, pass, family, timeout)
		if code != 0 {
			return code, rep
		}
		granted, report = append(granted, g...), report+rep
	}
	if len(granted) > 0 {
		return 1, fmt.Sprintf("FAIL: relay to forbidden peers allowed: %v (%s)", granted, report[1:])
	}
	return 0, "OK: forbidden peers refused (" + report[1:] + ")"
}

func probeFamily(endpoint, user, pass string, family byte, timeout time.Duration) (int, []string, string) {
	fail := func(err error) (int, []string, string) {
		code, message := probeFailure(err)
		return code, nil, message
	}
	conn, err := net.DialTimeout("udp", endpoint, timeout)
	if err != nil {
		return fail(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fail(err)
	}
	transport := stunAttr{attrTransport, []byte{17, 0, 0, 0}}
	r, err := stunCall(conn, stunAllocate, []stunAttr{transport}, nil)
	if err != nil {
		return fail(err)
	}
	if r.class == 0x0100 {
		return 1, nil, "开放中继！无凭据 Allocate 成功"
	}
	realm, nonce := r.attrs[attrRealm], r.attrs[attrNonce]
	if r.code != 401 || len(realm) == 0 || len(nonce) == 0 {
		return 1, nil, fmt.Sprintf("FAIL: expected 401 with REALM/NONCE (got %d)", r.code)
	}
	key := md5.Sum([]byte(user + ":" + string(realm) + ":" + pass))
	call := func(method uint16, extra ...stunAttr) (stunReply, error) {
		auth := func() []stunAttr {
			return append(append([]stunAttr(nil), extra...), stunAttr{attrUsername, []byte(user)}, stunAttr{attrRealm, realm}, stunAttr{attrNonce, nonce})
		}
		r, err := stunCall(conn, method, auth(), key[:])
		if err == nil && r.code == 438 && len(r.attrs[attrNonce]) > 0 { // stale nonce: retry once
			nonce = r.attrs[attrNonce]
			r, err = stunCall(conn, method, auth(), key[:])
		}
		return r, err
	}
	r, err = call(stunAllocate, transport, stunAttr{attrFamily, []byte{family, 0, 0, 0}})
	if err != nil {
		return fail(err)
	}
	if r.class != 0x0100 && family == 1 {
		return 1, nil, fmt.Sprintf("FAIL: authenticated Allocate refused (%d); wrong credentials or secret?", r.code)
	}
	if r.class != 0x0100 {
		return 0, nil, fmt.Sprintf(" ipv6-allocation=%d", r.code) // no IPv6 relay: nothing to reach
	}
	granted, report, err := checkPeers(call, family)
	if err != nil {
		return fail(err)
	}
	return 0, granted, report
}

// checkPeers asks for a permission to each forbidden peer of one family on the
// current allocation, then releases the allocation.
func checkPeers(call stunCaller, family byte) ([]string, string, error) {
	defer call(stunRefresh, stunAttr{attrLifetime, []byte{0, 0, 0, 0}})
	var granted []string
	report := ""
	for _, peer := range forbiddenPeers[family] {
		r, err := call(stunCreatePermission, stunAttr{attrXorPeer, xorPeer(netip.MustParseAddr(peer))})
		if err != nil {
			return nil, "", err
		}
		if r.class == 0x0100 {
			granted = append(granted, peer)
		}
		report += fmt.Sprintf(" %s=%d", peer, r.code)
	}
	return granted, report, nil
}

// xorPeer encodes XOR-PEER-ADDRESS with port 0. IPv6 addresses (v4-mapped ones
// included, sent as such on purpose) are XORed with cookie || transaction ID by
// stunCall once the transaction ID is known.
func xorPeer(addr netip.Addr) []byte {
	if addr.Is4() {
		ip, cookie := addr.As4(), binary.BigEndian.AppendUint32(nil, stunCookie)
		v := []byte{0, 1, 0x21, 0x12, 0, 0, 0, 0}
		for i := range ip {
			v[4+i] = ip[i] ^ cookie[i]
		}
		return v
	}
	ip := addr.As16()
	return append([]byte{0, 2, 0x21, 0x12}, ip[:]...)
}

// stunCall sends one request and waits for its response. With key, it appends
// MESSAGE-INTEGRITY (RFC 5389 §15.4).
func stunCall(conn net.Conn, method uint16, attrs []stunAttr, key []byte) (stunReply, error) {
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg, method)
	binary.BigEndian.PutUint32(msg[4:], stunCookie)
	if _, err := rand.Read(msg[8:20]); err != nil {
		return stunReply{}, err
	}
	for _, a := range attrs {
		value := a.value
		if a.typ == attrXorPeer && value[1] == 2 {
			value = append([]byte(nil), value...)
			for i, m := range msg[4:20] {
				value[4+i] ^= m
			}
		}
		msg = appendAttr(msg, a.typ, value)
	}
	if key != nil {
		binary.BigEndian.PutUint16(msg[2:], uint16(len(msg)-20+24))
		mac := hmac.New(sha1.New, key)
		mac.Write(msg)
		msg = appendAttr(msg, attrIntegrity, mac.Sum(nil))
	}
	binary.BigEndian.PutUint16(msg[2:], uint16(len(msg)-20))
	if _, err := conn.Write(msg); err != nil {
		return stunReply{}, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return stunReply{}, err
		}
		b := buf[:n]
		if len(b) < 20 || !bytes.Equal(b[8:20], msg[8:20]) {
			continue
		}
		return parseReply(b, method)
	}
}

func appendAttr(msg []byte, typ uint16, value []byte) []byte {
	msg = binary.BigEndian.AppendUint16(msg, typ)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(value)))
	msg = append(msg, value...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}
	return msg
}

func parseReply(b []byte, method uint16) (stunReply, error) {
	if binary.BigEndian.Uint32(b[4:8]) != stunCookie || int(binary.BigEndian.Uint16(b[2:4])) != len(b)-20 {
		return stunReply{}, fmt.Errorf("malformed STUN response")
	}
	typ := binary.BigEndian.Uint16(b[:2])
	r := stunReply{class: typ &^ 0x3eef, attrs: map[uint16][]byte{}}
	if typ&0x3eef != method || (r.class != 0x0100 && r.class != 0x0110) {
		return stunReply{}, fmt.Errorf("unexpected STUN response type %#04x", typ)
	}
	for offset := 20; offset < len(b); {
		if len(b)-offset < 4 {
			return stunReply{}, fmt.Errorf("truncated STUN attribute")
		}
		attr := binary.BigEndian.Uint16(b[offset:])
		size := int(binary.BigEndian.Uint16(b[offset+2:]))
		next := offset + 4 + (size+3)&^3
		if next > len(b) {
			return stunReply{}, fmt.Errorf("truncated STUN attribute")
		}
		value := b[offset+4 : offset+4+size]
		if _, seen := r.attrs[attr]; !seen {
			r.attrs[attr] = value
		}
		if attr == attrErrorCode && size >= 4 {
			r.code = int(value[2])*100 + int(value[3])
		}
		offset = next
	}
	if r.class == 0x0110 && r.code == 0 {
		return stunReply{}, fmt.Errorf("error response without ERROR-CODE")
	}
	return r, nil
}
