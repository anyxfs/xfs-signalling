// xfs-turn-check asks a signalling server for TURN credentials the way a client
// does (04 §4.3: hello, then a turn_credentials request signed with a throwaway
// identity key bound to the connection) and prints the answer, so a deployment
// can be checked against its coturn, e.g. with turnutils_uclient.
package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	url := flag.String("url", "ws://127.0.0.1:8787/signal", "signalling WebSocket URL")
	insecure := flag.Bool("insecure", false, "skip TLS certificate checks (test certificates only)")
	probe := flag.String("probe-unauth", "", "check UDP TURN authentication at host:port without credentials (exit 0: 401 challenge, 1: unsafe/error, 2: timeout)")
	peers := flag.String("probe-peers", "", "check that the relay at host:port refuses private/loopback peers incl. ::ffff:127.0.0.1 (credentials from -turn-user/-turn-pass, else from -url; exit codes as -probe-unauth)")
	turnUser := flag.String("turn-user", "", "TURN username for -probe-peers")
	turnPass := flag.String("turn-pass", "", "TURN credential for -probe-peers")
	secretFile := flag.String("turn-secret-file", "", "for -probe-peers on the TURN host: sign short-lived credentials with this static-auth-secret file instead of asking -url")
	flag.Parse()
	if *probe != "" {
		code, message := probeUnauth(*probe, 3*time.Second)
		fmt.Println(message)
		os.Exit(code)
	}
	if *peers != "" {
		user, pass := *turnUser, *turnPass
		if user == "" && *secretFile != "" {
			secret, err := os.ReadFile(*secretFile)
			must(err)
			user = fmt.Sprintf("%d:xfs-turn-check", time.Now().Add(10*time.Minute).Unix())
			m := hmac.New(sha1.New, []byte(strings.TrimSpace(string(secret))))
			m.Write([]byte(user))
			pass = base64.StdEncoding.EncodeToString(m.Sum(nil))
		}
		if user == "" {
			user, pass, _ = fetchCredentials(*url, *insecure)
		}
		code, message := probePeers(*peers, user, pass, 5*time.Second)
		fmt.Println(message)
		os.Exit(code)
	}
	user, pass, urls := fetchCredentials(*url, *insecure)
	// One line each: easy to read into a shell.
	fmt.Println(user)
	fmt.Println(pass)
	fmt.Println(strings.Join(urls, ","))
}

// fetchCredentials asks the signalling server for TURN credentials as a client does.
func fetchCredentials(url string, insecure bool) (string, string, []string) {
	d := websocket.Dialer{Subprotocols: []string{"xfs-signal.dev.v1"}, TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}
	c, _, err := d.Dial(url, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	must(c.WriteJSON(map[string]any{"t": "hello", "v": 1, "client": "xfs-turn-check"}))
	var hello map[string]any
	must(c.ReadJSON(&hello))
	if hello["t"] != "hello_ok" {
		log.Fatalf("hello: %v", hello)
	}
	connNonce, err := base64.RawURLEncoding.DecodeString(fmt.Sprint(hello["connNonce"]))
	if err != nil || len(connNonce) != 32 {
		log.Fatalf("no connNonce: %v", hello)
	}
	pk, sk, _ := ed25519.GenerateKey(nil)
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	signed := append([]byte("XFS-TURNREQ-v1"), nonce...)
	signed = binary.BigEndian.AppendUint32(signed, uint32(hello["serverTime"].(float64)))
	binding := sha256.Sum256(connNonce)
	signed = append(signed, binding[:]...)
	b64 := base64.RawURLEncoding.EncodeToString
	must(c.WriteJSON(map[string]any{"t": "turn_credentials", "pk": b64(pk), "nonce": b64(nonce), "sig": b64(ed25519.Sign(sk, signed))}))
	var got map[string]any
	must(c.ReadJSON(&got))
	if got["t"] != "turn_credentials_ok" {
		log.Fatalf("turn_credentials: %v", got)
	}
	urls := []string{}
	for _, u := range got["urls"].([]any) {
		urls = append(urls, fmt.Sprint(u))
	}
	return fmt.Sprint(got["username"]), fmt.Sprint(got["credential"]), urls
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
