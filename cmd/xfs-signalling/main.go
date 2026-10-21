package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	sig "xfs/signaling/internal/signal"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8787", "listen address (plaintext is restricted to loopback)")
	flag.StringVar(&metricsListen, "metrics-listen", "", "Prometheus /metrics listen address (explicit loopback IP only; empty disables)")
	flag.StringVar(&allowedOrigins, "allowed-origins", "", "comma-separated http(s)://host[:port] origins allowed in addition to same-Host and native clients")
	cert := flag.String("tls-cert", "", "TLS certificate PEM")
	key := flag.String("tls-key", "", "TLS key PEM")
	stun := flag.String("stun", "", "comma-separated stun:host:port URLs; empty means no external STUN")
	maxMessageBytes := flag.Int64("max-message-bytes", 64*1024, "maximum complete WebSocket message size (1024..1048576 bytes)")
	createCapacity := flag.Int("create-capacity", 10, "per-source create_room burst capacity (refill 1/minute)")
	ipJoinCapacity := flag.Int("ip-join-capacity", 10, "per-IP join_room burst capacity (refill 1/minute)")
	prefixJoinCapacity := flag.Int("prefix-join-capacity", 60, "per-prefix join_room burst capacity (refill 6/minute)")
	turnURLs := flag.String("turn-urls", "", "comma-separated turn:/turns: URLs of at most two nodes (04 §4.3); needs -turn-secret-file")
	turnSecretFile := flag.String("turn-secret-file", "", "file holding the coturn static-auth-secret (never pass the secret itself on the command line)")
	flag.StringVar(&ticketKeyFile, "ticket-key-file", "", "file keeping the resume-ticket keys across restarts (04 §2.6), created if missing; empty: a restart ends every ticket")
	flag.StringVar(&regionsFile, "regions-file", "", "JSON: offline country database and per-region STUN / TURN lists (internal/signal/geo.go); empty: one list for every client")
	flag.StringVar(&eventsDB, "events-db", "", "SQLite file for anonymous events (hour, region, event, client platform and version; internal/signal/events.go); empty: none recorded")
	flag.StringVar(&retiredCodesFile, "retired-codes-file", "", "file carrying recently ended pairing codes over a clean restart so none is reused within 10 minutes (04 §3.2); empty: not carried")
	flag.StringVar(&notices.file, "notices-file", "", "signed service notices (internal/signal/notices.go), checked every 5 s; empty: no notices, relay never paused by notice")
	flag.StringVar(&notices.cache, "notices-cache", "", "last good notices file, kept over a restart")
	noticeKeys := flag.String("notices-pubkey", "", "operator public keys for notices: id:base64[,id:base64]")
	defaults := sig.DefaultConfig()
	flag.IntVar(&admission.total, "max-connections", defaults.MaxConnections, "concurrent connections in all")
	flag.IntVar(&admission.ip, "ip-connections", defaults.IPConnections, "concurrent connections per IPv4 address or IPv6 /64 (04 §3.3.5)")
	flag.IntVar(&admission.prefix, "prefix-connections", defaults.PrefixConnections, "concurrent connections per IPv4 /24 or IPv6 /48")
	flag.IntVar(&admission.turnDaily, "turn-daily-per-source", defaults.TURNDailyPerSource, "TURN credentials per IPv4 address or IPv6 /64 a day (generous: carrier NAT puts many users behind one address)")
	flag.IntVar(&admission.burst, "connect-capacity", defaults.ConnectCapacity, "per-address burst of new connections (refill 1 per 3 s)")
	flag.Parse()
	if notices.file != "" {
		keys, err := parseNoticeKeys(*noticeKeys)
		if err != nil {
			log.Print(err)
			os.Exit(1)
		}
		notices.keys = keys
	}
	if (*turnURLs == "") != (*turnSecretFile == "") {
		log.Print("-turn-urls and -turn-secret-file go together")
		os.Exit(1)
	}
	if *turnURLs != "" {
		secret, err := os.ReadFile(*turnSecretFile)
		if err != nil {
			log.Print(err)
			os.Exit(1)
		}
		turn.secret = []byte(strings.TrimSpace(string(secret)))
		for _, uri := range strings.Split(*turnURLs, ",") {
			turn.urls = append(turn.urls, strings.TrimSpace(uri))
		}
	}
	var urls []string
	if *stun != "" {
		for _, uri := range strings.Split(*stun, ",") {
			urls = append(urls, strings.TrimSpace(uri))
		}
	}
	if err := run(*addr, *cert, *key, *maxMessageBytes, *createCapacity, *ipJoinCapacity, *prefixJoinCapacity, urls...); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

// turn is the relay configuration main read; run applies it.
var turn struct {
	urls   []string
	secret []byte
}

// regionsFile and eventsDB: per-region ICE lists and anonymous events; run applies them.
var regionsFile, eventsDB string

// retiredCodesFile is where a stopping server leaves its code quarantine.
var retiredCodesFile string

// notices: the signed notices file, its cache and the keys; run applies them.
var notices struct {
	file, cache string
	keys        map[string]ed25519.PublicKey
}

// parseNoticeKeys reads "-notices-pubkey": id:base64[,id:base64], each a 32-byte
// Ed25519 public key, ids distinct.
func parseNoticeKeys(s string) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	for _, part := range strings.Split(s, ",") {
		id, b64, ok := strings.Cut(strings.TrimSpace(part), ":")
		raw, err := base64.StdEncoding.DecodeString(b64)
		if !ok || id == "" || err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("-notices-pubkey: %q is not id:base64-ed25519-key", part)
		}
		if keys[id] != nil {
			return nil, fmt.Errorf("-notices-pubkey: id %q twice", id)
		}
		keys[id] = ed25519.PublicKey(raw)
	}
	return keys, nil
}

// ticketKeyFile is where the resume-ticket keys live; run applies it.
var ticketKeyFile string

var metricsListen string

var allowedOrigins string

// admission holds the connection limits main read; zero keeps the defaults.
var admission struct{ total, ip, prefix, burst, turnDaily int }

func run(addr, cert, key string, maxMessageBytes int64, createCapacity, ipJoinCapacity, prefixJoinCapacity int, stunURLs ...string) error {
	if err := validateMetricsListen(metricsListen); err != nil {
		return err
	}
	if (cert == "") != (key == "") {
		return fmt.Errorf("both TLS certificate and key are required")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if cert == "" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("plaintext requires an explicit loopback IP; supply TLS for other interfaces")
		}
	}
	cfg := sig.DefaultConfig()
	cfg.NoticesFile, cfg.NoticesCache, cfg.NoticesKeys = notices.file, notices.cache, notices.keys
	if allowedOrigins != "" {
		cfg.AllowedOrigins = strings.Split(allowedOrigins, ",")
	}
	cfg.STUNURLs = stunURLs
	cfg.TURNURLs, cfg.TURNSecret = turn.urls, turn.secret
	cfg.MaxMessageBytes = maxMessageBytes
	cfg.SourceCreateCapacity = createCapacity
	cfg.IPJoinCapacity = ipJoinCapacity
	cfg.PrefixJoinCapacity = prefixJoinCapacity
	for _, v := range []struct {
		from int
		to   *int
	}{{admission.total, &cfg.MaxConnections}, {admission.ip, &cfg.IPConnections}, {admission.prefix, &cfg.PrefixConnections}, {admission.burst, &cfg.ConnectCapacity}, {admission.turnDaily, &cfg.TURNDailyPerSource}} {
		if v.from != 0 {
			*v.to = v.from
		}
	}
	cfg.TicketKeyFile = ticketKeyFile
	cfg.RetiredCodesFile = retiredCodesFile
	cfg.EventsDB = eventsDB
	if regionsFile != "" {
		f, err := sig.LoadRegionsFile(regionsFile)
		if err != nil {
			return err
		}
		cfg.Regions, cfg.GeoFile = f.Regions, f.GeoFile
	}
	if ticketKeyFile == "" {
		log.Print("no -ticket-key-file: resume tickets end when this process restarts")
	}
	s, err := sig.New(cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	mh, ml, err := metricsServer(metricsListen, s.MetricsHandler())
	if err != nil {
		return err
	}
	if mh != nil {
		defer mh.Close()
		defer ml.Close()
	}
	h := &http.Server{Addr: addr, Handler: s, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer h.Close()
	if cert != "" {
		certs, err := newCertReloader(cert, key)
		if err != nil {
			return err
		}
		h.TLSConfig.GetCertificate = certs.get
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	finished := make(chan error, 2)
	if mh != nil {
		go func() { finished <- mh.Serve(ml) }()
	}
	go func() {
		if cert != "" {
			finished <- h.ListenAndServeTLS("", "")
		} else {
			finished <- h.ListenAndServe()
		}
	}()
	log.Printf("XFS development signaling: %s, subprotocol=%s (not production-ready)", addr, sig.Subprotocol)
	select {
	case err := <-finished:
		if err != http.ErrServerClosed {
			return err
		}
	case <-ctx.Done():
		stop, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		return sig.Shutdown(stop, h, s)
	}
	return nil
}
