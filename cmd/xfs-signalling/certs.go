package main

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"
)

// certReloader serves the certificate in certFile/keyFile and picks up a renewed
// pair (Let's Encrypt renews every 60–90 days) without a restart: at most once a
// minute a handshake looks at the files' times and loads them again if either
// changed. A pair that fails to load keeps the one in use and is logged, so a
// half-written renewal never takes the service down.
type certReloader struct {
	certFile, keyFile string
	every             time.Duration

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   [2]time.Time
	checked time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, every: time.Minute}
	stamp, err := r.times()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	r.cert, r.stamp, r.checked = &cert, stamp, time.Now()
	return r, nil
}

func (r *certReloader) times() ([2]time.Time, error) {
	var t [2]time.Time
	for i, name := range []string{r.certFile, r.keyFile} {
		info, err := os.Stat(name)
		if err != nil {
			return t, err
		}
		t[i] = info.ModTime()
	}
	return t, nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := time.Now(); now.Sub(r.checked) >= r.every {
		r.checked = now
		stamp, err := r.times()
		if err != nil {
			// Moved, unlinked or unreadable: keep serving, but say so every check,
			// before the certificate in use expires unnoticed.
			log.Printf("TLS certificate files not checked, keeping the current one: %v", err)
		} else if stamp != r.stamp {
			if cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile); err == nil {
				r.cert, r.stamp = &cert, stamp
				log.Print("TLS certificate reloaded")
			} else {
				log.Printf("TLS certificate not reloaded, keeping the current one: %v", err)
			}
		}
	}
	return r.cert, nil
}
