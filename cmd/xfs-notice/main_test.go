package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sig "xfs/signaling/internal/signal"
)

const sample = `{"v":1,"issuedAt":"2026-10-20T21:00:00+08:00","relayPaused":false,"notices":[
 {"id":"maint-1","level":"warning","startsAt":"2026-10-23T09:00:00+08:00","endsAt":"2026-10-25T04:00:00+08:00",
  "title":{"zh-CN":"计划维护","zh-TW":"計畫維護","en":"Planned maintenance","ja":"メンテナンス"},
  "body":{"zh-CN":"10 月 25 日凌晨维护。","zh-TW":"10 月 25 日凌晨維護。","en":"Maintenance early on 25 October.","ja":"10月25日未明にメンテナンスします。"}}]}`

func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func makeKey(t *testing.T, dir string) (keyFile, pubArg string) {
	t.Helper()
	keyFile = filepath.Join(dir, "notices-key")
	code, out, errOut := cli(t, "keygen", "-out", keyFile)
	if code != 0 {
		t.Fatalf("keygen: %s", errOut)
	}
	return keyFile, strings.TrimSpace(out)
}

func TestSignThenVerify(t *testing.T) {
	dir := t.TempDir()
	keyFile, pubArg := makeKey(t, dir)
	if !strings.HasPrefix(pubArg, "n1:") {
		t.Fatalf("keygen printed %q", pubArg)
	}
	inner := filepath.Join(dir, "inner.json")
	_ = os.WriteFile(inner, []byte(sample), 0o644)
	code, signed, errOut := cli(t, "sign", "-key", keyFile, "-id", "n1", inner)
	if code != 0 {
		t.Fatalf("sign: %s", errOut)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(pubArg, "n1:"))
	set, err := sig.OpenNotices([]byte(signed), map[string]ed25519.PublicKey{"n1": raw})
	if err != nil || len(set.Notices) != 1 {
		t.Fatalf("server would refuse it: %v", err)
	}
	signedFile := filepath.Join(dir, "notices.json")
	_ = os.WriteFile(signedFile, []byte(signed), 0o644)
	code, out, errOut := cli(t, "verify", "-pub", pubArg, signedFile)
	if code != 0 || !strings.Contains(out, "maint-1") {
		t.Fatalf("verify: %d %s %s", code, out, errOut)
	}
}

func TestSignRefusesURLInBody(t *testing.T) {
	dir := t.TempDir()
	keyFile, _ := makeKey(t, dir)
	var m map[string]any
	_ = json.Unmarshal([]byte(sample), &m)
	m["notices"].([]any)[0].(map[string]any)["body"].(map[string]any)["en"] = "Donate at https://www.anyxfs.com"
	data, _ := json.Marshal(m)
	inner := filepath.Join(dir, "inner.json")
	_ = os.WriteFile(inner, data, 0o644)
	code, _, errOut := cli(t, "sign", "-key", keyFile, "-id", "n1", inner)
	if code != 1 || !strings.Contains(errOut, "maint-1") {
		t.Fatalf("code %d, %s", code, errOut)
	}
}

func TestSignRefusesMissingLanguage(t *testing.T) {
	dir := t.TempDir()
	keyFile, _ := makeKey(t, dir)
	inner := filepath.Join(dir, "inner.json")
	_ = os.WriteFile(inner, []byte(strings.Replace(sample, `"ja":"メンテナンス"`, `"ja":""`, 1)), 0o644)
	if code, _, _ := cli(t, "sign", "-key", keyFile, "-id", "n1", inner); code != 1 {
		t.Fatalf("missing ja signed, code %d", code)
	}
}

func TestKeygenRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	keyFile, _ := makeKey(t, dir)
	if code, _, _ := cli(t, "keygen", "-out", keyFile); code == 0 {
		t.Fatal("overwrote an existing key")
	}
}
