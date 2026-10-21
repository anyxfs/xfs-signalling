// xfs-notice signs the signalling server's service notices on the operator's own
// machine (design 2026-10-19-signalling-notices-design.md §4.3). The private key
// never leaves that machine; the server only has the public key (-notices-pubkey).
//
//	xfs-notice keygen -out <key file>              prints the public key as n1:<base64>
//	xfs-notice sign -key <key file> -id n1 <inner.json> > notices.json
//	xfs-notice verify -pub n1:<base64> <notices.json>
//
// sign checks everything the server checks, and refuses links or calls to action
// in the text (links go in "link", which Apple platforms never show).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	sig "xfs/signaling/internal/signal"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: xfs-notice keygen|sign|verify …")
		return 2
	}
	var err error
	switch args[0] {
	case "keygen":
		err = keygen(args[1:], out)
	case "sign":
		err = sign(args[1:], out)
	case "verify":
		err = verify(args[1:], out)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintln(errOut, "xfs-notice:", err)
		return 1
	}
	return 0
}

func keygen(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	path := fs.String("out", "", "private key file to create")
	id := fs.String("id", "n1", "key id the server knows this key by")
	if err := fs.Parse(args); err != nil || *path == "" {
		return errors.New("keygen -out <file> [-id n1]")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err // an existing key is never overwritten
	}
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s:%s\n", *id, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func sign(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "private key file")
	id := fs.String("id", "n1", "key id")
	if err := fs.Parse(args); err != nil || *keyFile == "" || fs.NArg() != 1 {
		return errors.New("sign -key <file> -id n1 <inner.json>")
	}
	seedText, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedText)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("not a key file made by keygen")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	inner, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var set sig.NoticeSet
	if err := json.Unmarshal(inner, &set); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	for _, n := range set.Notices {
		if err := sig.LintNotice(n); err != nil {
			return err
		}
	}
	envelope, _ := json.Marshal(map[string]string{
		"payload": base64.StdEncoding.EncodeToString(inner),
		"sig":     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, inner)),
		"key":     *id,
	})
	// The server's own checks, run here so a refused file never gets uploaded.
	if _, err := sig.OpenNotices(envelope, map[string]ed25519.PublicKey{*id: priv.Public().(ed25519.PublicKey)}); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(envelope))
	return err
}

func verify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubArg := fs.String("pub", "", "id:base64 public key")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return errors.New("verify -pub n1:<base64> <notices.json>")
	}
	id, b64, _ := strings.Cut(*pubArg, ":")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("-pub must be id:base64-ed25519-key")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	set, err := sig.OpenNotices(data, map[string]ed25519.PublicKey{id: ed25519.PublicKey(raw)})
	if err != nil {
		return err
	}
	beijing := time.FixedZone("CST", 8*3600)
	fmt.Fprintf(out, "issued %s, relay paused: %v, %d notice(s)\n", set.IssuedAt.In(beijing).Format("2006-01-02 15:04"), set.RelayPaused, len(set.Notices))
	for _, n := range set.Notices {
		fmt.Fprintf(out, "  %s  %-7s  %s – %s (Beijing)  %s\n", n.ID, n.Level,
			n.StartsAt.In(beijing).Format("2006-01-02 15:04"), n.EndsAt.In(beijing).Format("2006-01-02 15:04"), n.Title["zh-CN"])
	}
	return nil
}
