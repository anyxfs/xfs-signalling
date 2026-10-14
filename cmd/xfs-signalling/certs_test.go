package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a fresh self-signed pair named cn, stamped at when.
func writePair(t *testing.T, certFile, keyFile, cn string, when time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
	_ = os.Chtimes(certFile, when, when)
	_ = os.Chtimes(keyFile, when, when)
}

func served(t *testing.T, r *certReloader) string {
	t.Helper()
	c, err := r.get(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

// A renewed certificate is served without a restart; a broken renewal keeps the
// one in use.
func TestARenewedCertificateIsPickedUpWithoutARestart(t *testing.T) {
	dir, start := t.TempDir(), time.Now().Add(-time.Hour)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePair(t, certFile, keyFile, "first.test", start)
	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	writePair(t, certFile, keyFile, "renewed.test", start.Add(time.Minute))
	if served(t, r) != "first.test" {
		t.Fatal("reloaded before the check interval")
	}
	r.checked = time.Time{}
	if served(t, r) != "renewed.test" {
		t.Fatal("renewal not picked up")
	}
	_ = os.WriteFile(certFile, []byte("half written"), 0o600)
	_ = os.Chtimes(certFile, start.Add(2*time.Minute), start.Add(2*time.Minute))
	r.checked = time.Time{}
	if served(t, r) != "renewed.test" {
		t.Fatal("a broken renewal replaced the working certificate")
	}
}

func TestAMissingOrBrokenCertificateStopsTheStart(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := newCertReloader(certFile, keyFile); err == nil {
		t.Fatal("started without certificate files")
	}
	_ = os.WriteFile(certFile, []byte("x"), 0o600)
	_ = os.WriteFile(keyFile, []byte("x"), 0o600)
	if _, err := newCertReloader(certFile, keyFile); err == nil {
		t.Fatal("started with a broken certificate")
	}
}
