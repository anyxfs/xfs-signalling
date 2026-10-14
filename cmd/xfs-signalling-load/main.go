// xfs-signalling-load is a bounded development load generator. It opens one
// room per pair, measures setup time, then sends small bidirectional signals.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type msg map[string]any

type pair struct {
	a, b  *websocket.Conn
	room  string
	setup time.Duration
}

func main() {
	url := flag.String("url", "ws://127.0.0.1:8787/signal", "signaling websocket URL")
	levels := flag.String("pairs", "10,50,100,250,500", "comma-separated simultaneous paired rooms")
	cycles := flag.Int("cycles", 10, "bidirectional forwarded messages per pair")
	hold := flag.Duration("hold", 5*time.Second, "how long to hold paired rooms after message round trips")
	timeout := flag.Duration("timeout", 15*time.Second, "per-operation websocket timeout")
	flag.Parse()
	counts, err := parseLevels(*levels)
	if err != nil {
		log.Fatal(err)
	}
	if *cycles < 1 || *cycles > 1000 || *hold < 0 || *timeout <= 0 {
		log.Fatal("invalid cycles, hold, or timeout")
	}
	fmt.Println("pairs,connections,setup_p50_ms,setup_p95_ms,signal_rtt_p50_ms,signal_rtt_p95_ms,forwarded_messages_per_sec,failures")
	failed := false
	for _, count := range counts {
		result, err := runLevel(*url, count, *cycles, *hold, *timeout)
		if err != nil {
			log.Printf("level %d failed: %v", count, err)
			failed = true
			continue
		}
		fmt.Printf("%d,%d,%.2f,%.2f,%.2f,%.2f,%.1f,%d\n", count, count*2, millis(percentile(result.setup, .50)), millis(percentile(result.setup, .95)), millis(percentile(result.rtt, .50)), millis(percentile(result.rtt, .95)), float64(result.messages)/result.signalSeconds, result.failures)
	}
	if failed {
		log.Fatal("one or more load levels failed")
	}
}

type measurements struct {
	setup, rtt    []time.Duration
	messages      int64
	signalSeconds float64
	failures      int64
}

func runLevel(url string, n, cycles int, hold, timeout time.Duration) (measurements, error) {
	startGate := make(chan struct{})
	pairs := make(chan pair, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate
			p, err := establish(url, timeout)
			if err != nil {
				errs <- err
				return
			}
			pairs <- p
		}()
	}
	close(startGate)
	wg.Wait()
	close(pairs)
	close(errs)
	var result measurements
	active := make([]pair, 0, n)
	for p := range pairs {
		active = append(active, p)
		result.setup = append(result.setup, p.setup)
	}
	setupErrs := make([]error, 0)
	for err := range errs {
		setupErrs = append(setupErrs, err)
	}
	if len(setupErrs) > 0 {
		closePairs(active)
		return result, fmt.Errorf("paired %d/%d rooms; sample error: %w", len(active), n, setupErrs[0])
	}
	phase := time.Now()
	var messageCount atomic.Int64
	var roundTrips sync.Mutex
	var rtts []time.Duration
	errCh := make(chan error, n)
	var senders sync.WaitGroup
	for _, p := range active {
		senders.Add(1)
		go func(p pair) {
			defer senders.Done()
			for cycle := 0; cycle < cycles; cycle++ {
				for _, direction := range [][2]*websocket.Conn{{p.a, p.b}, {p.b, p.a}} {
					started := time.Now()
					payload := strings.Repeat("x", 256)
					data, _ := json.Marshal(msg{"t": "signal", "room": p.room, "kind": "candidate", "payload": payload})
					if err := direction[0].SetWriteDeadline(time.Now().Add(timeout)); err != nil {
						errCh <- err
						return
					}
					if err := direction[0].WriteMessage(websocket.TextMessage, data); err != nil {
						errCh <- err
						return
					}
					if err := direction[1].SetReadDeadline(time.Now().Add(timeout)); err != nil {
						errCh <- err
						return
					}
					var response msg
					if err := direction[1].ReadJSON(&response); err != nil {
						errCh <- err
						return
					}
					if response["t"] != "signal" || response["payload"] != payload || response["room"] != p.room {
						errCh <- fmt.Errorf("unexpected forwarded signal")
						return
					}
					roundTrips.Lock()
					rtts = append(rtts, time.Since(started))
					roundTrips.Unlock()
					messageCount.Add(1)
				}
			}
		}(p)
	}
	senders.Wait()
	close(errCh)
	for err := range errCh {
		result.failures++
		if result.failures == 1 {
			closePairs(active)
			return result, fmt.Errorf("signal forwarding failed: %w", err)
		}
	}
	result.signalSeconds = time.Since(phase).Seconds()
	if result.signalSeconds <= 0 {
		result.signalSeconds = float64(time.Nanosecond) / float64(time.Second)
	}
	result.rtt = rtts
	result.messages = messageCount.Load()
	time.Sleep(hold)
	closePairs(active)
	return result, nil
}

func establish(url string, timeout time.Duration) (pair, error) {
	started := time.Now()
	dialer := websocket.Dialer{Subprotocols: []string{"xfs-signal.dev.v1"}, HandshakeTimeout: timeout}
	a, _, err := dialer.Dial(url, nil)
	if err != nil {
		return pair{}, err
	}
	b, _, err := dialer.Dial(url, nil)
	if err != nil {
		a.Close()
		return pair{}, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			a.Close()
			b.Close()
		}
	}()
	for _, c := range []*websocket.Conn{a, b} {
		if err := setDeadline(c, time.Now().Add(timeout)); err != nil {
			return pair{}, err
		}
		if err := c.WriteJSON(msg{"t": "hello", "v": 1, "client": "xfs-load/1"}); err != nil {
			return pair{}, err
		}
		var r msg
		if err := c.ReadJSON(&r); err != nil || r["t"] != "hello_ok" {
			return pair{}, fmt.Errorf("hello rejected: %v (%v)", r, err)
		}
	}
	if err := a.WriteJSON(msg{"t": "create_room"}); err != nil {
		return pair{}, err
	}
	var created msg
	if err := a.ReadJSON(&created); err != nil || created["t"] != "room_created" {
		return pair{}, fmt.Errorf("create failed: %v (%v)", created, err)
	}
	room, ok := created["room"].(string)
	code, codeOK := created["code"].(string)
	if !ok || !codeOK {
		return pair{}, fmt.Errorf("invalid room response")
	}
	if err := b.WriteJSON(msg{"t": "join_room", "code": code}); err != nil {
		return pair{}, err
	}
	var joined msg
	if err := b.ReadJSON(&joined); err != nil || joined["t"] != "room_joined" {
		return pair{}, fmt.Errorf("join failed: %v (%v)", joined, err)
	}
	var peer msg
	if err := a.ReadJSON(&peer); err != nil || peer["t"] != "peer_joined" {
		return pair{}, fmt.Errorf("peer notification failed: %v (%v)", peer, err)
	}
	for _, c := range []*websocket.Conn{a, b} {
		_ = setDeadline(c, time.Time{})
	}
	closeOnError = false
	return pair{a: a, b: b, room: room, setup: time.Since(started)}, nil
}

func setDeadline(c *websocket.Conn, deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}

func closePairs(pairs []pair) {
	for _, p := range pairs {
		_ = p.a.Close()
		_ = p.b.Close()
	}
}
func millis(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
func percentile(values []time.Duration, p float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	idx := int(float64(len(values)-1) * p)
	return values[idx]
}
func parseLevels(raw string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(raw, ",") {
		var n int
		if _, err := fmt.Sscan(strings.TrimSpace(part), &n); err != nil || n < 1 || n > 513 {
			return nil, fmt.Errorf("pair count must be 1..513: %q", part)
		}
		out = append(out, n)
	}
	sort.Ints(out)
	return out, nil
}
