package signal

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Config struct {
	AllowedOrigins []string
	STUNURLs       []string
	// TURNURLs and TURNSecret (coturn static-auth-secret) enable
	// turn_credentials (04 §4.3); without them it answers 8032.
	TURNURLs                                                 []string
	TURNSecret                                               []byte
	MaxMessageBytes                                          int64
	SourceCreateCapacity, IPJoinCapacity, PrefixJoinCapacity int
	Region                                                   string
	MaxConnections, MaxRooms, MaxCodes, MaxSources           int
	// Connection admission (04 §3.3.5): concurrent connections per address and
	// per prefix, and a per-address burst of new connections refilled one per
	// ConnectRefill. Without them one machine could hold every connection slot.
	IPConnections, PrefixConnections, ConnectCapacity int
	// TURNDailyPerSource: relay credentials per address (IPv4 / IPv6 /64) a day.
	TURNDailyPerSource int
	ConnectRefill      time.Duration
	// TicketKeyFile keeps the resume-ticket keys across restarts (04 §2.6);
	// empty keeps them in memory only, so a restart ends every ticket.
	TicketKeyFile string
	// RetiredCodesFile carries the code quarantine over a restart (04 §3.2,
	// codesfile.go); empty: a restart forgets which codes just ended.
	RetiredCodesFile string
	// Regions give clients per-region STUN / TURN lists and are recorded with
	// each anonymous event (geo.go, events.go). GeoFile is the offline country
	// database; without it every client is in DefaultRegion. EventsDB empty:
	// no events are recorded.
	Regions           []Region
	GeoFile, EventsDB string
	// Signed service notices (notices.go): NoticesFile is checked every few
	// seconds, NoticesCache keeps the last good version over a restart, and
	// NoticesKeys are the operator's public keys by envelope key id. Without a
	// file there are no notices and the relay is never paused by notice.
	NoticesFile, NoticesCache                                    string
	NoticesKeys                                                  map[string]ed25519.PublicKey
	Wait, Negotiate, Orphan, Hard, Hello, Heartbeat, Ping, Write time.Duration
}

func DefaultConfig() Config {
	return Config{Region: "local", MaxMessageBytes: MaxMessage, SourceCreateCapacity: 10, IPJoinCapacity: 10, PrefixJoinCapacity: 60, MaxConnections: 1024, MaxRooms: 512, MaxCodes: 8192, MaxSources: 8192,
		IPConnections: 16, PrefixConnections: 128, ConnectCapacity: 20, ConnectRefill: 3 * time.Second, TURNDailyPerSource: 300,
		Wait: 10 * time.Minute, Negotiate: 2 * time.Minute, Orphan: time.Minute, Hard: 15 * time.Minute,
		Hello: 5 * time.Second, Heartbeat: time.Minute, Ping: 20 * time.Second, Write: 5 * time.Second}
}

type room struct {
	id                    string
	code                  [32]byte
	creator, joiner       *client
	expires, hard, orphan time.Time
	paired                bool
	ready                 [2]bool
	eids                  [2]string
	session               [16]byte    // 04 §2.6: random at creation, kept across resumes
	pkHash                [2][16]byte // from each side's ready
	firstIssued           int64       // a resumed session's first ticket; 0 for a new one
	// For the room_closed event: the creator's region and client, and when the
	// room paired (or resumed).
	region            int
	platform, version string
	pairedAt          time.Time
}

type outbound struct {
	m     message
	close bool
}
type client struct {
	metrics           *metrics
	ws                *websocket.Conn
	send              chan outbound
	done              chan struct{}
	once              sync.Once
	room              *room     // guarded by Server.mu
	hello             bool      // reader goroutine only
	helloAt           int64     // hello_ok serverTime; reader goroutine only
	connNonce         [32]byte  // 04 §4.3.1 connection binding; reader goroutine only
	turn              bucket    // guarded by Server.mu
	slot              *[16]byte // waiting in a resume slot; guarded by Server.mu
	source, prefix    string
	region            int    // index into Config.Regions, -1 for DefaultRegion
	platform, version string // from hello's client tag (events.go); reader goroutine sets them before any request
	join, create, all bucket
	pending           message // delayed invalid-code response, owned by reader
}

func (c *client) stop() { c.once.Do(func() { close(c.done); _ = c.ws.Close() }) }
func (c *client) emit(m message, closeAfter bool) {
	c.metrics.emitted(m)
	select {
	case <-c.done:
		return
	default:
	}
	select {
	case c.send <- outbound{m, closeAfter}:
	default:
		c.stop()
	}
}

type Server struct {
	checkOrigin func(*http.Request) bool
	metrics     metrics
	cfg         Config
	tickets     ticketKeys // guarded by mu
	// A rotation not yet on disk is written again, backing off from one minute to
	// an hour, until it is: a restart meanwhile would end its tickets.
	keysUnsaved bool                     // guarded by mu
	keysRetry   time.Time                // guarded by mu
	keysBackoff time.Duration            // guarded by mu
	slots       map[[16]byte]*resumeSlot // guarded by mu
	regions     *regionTable
	events      *eventLog
	notices     *noticeWatcher // nil without Config.NoticesFile
	noticesAt   time.Time      // last check; guarded by mu (sweep goroutine)
	mu          sync.Mutex
	rooms       map[string]*room
	codes       map[[32]byte]*room
	retired     map[[32]byte]time.Time
	sources     map[string]*sourceBudget
	clients     map[*client]bool
	connections int
	pepper      [32]byte
	closed      bool
	done        chan struct{}
	wg          sync.WaitGroup
}

func New(cfg Config) (*Server, error) {
	checkOrigin, err := originPolicy(cfg.AllowedOrigins)
	if err != nil {
		return nil, err
	}
	if len(cfg.STUNURLs) > 8 {
		return nil, errors.New("at most eight STUN URLs")
	}
	for _, uri := range cfg.STUNURLs {
		if err := checkSTUN(uri); err != nil {
			return nil, err
		}
	}
	cfg.STUNURLs = append([]string(nil), cfg.STUNURLs...)
	if len(cfg.TURNURLs) > 0 {
		urls, err := ParseTURNURLs(cfg.TURNURLs)
		if err != nil {
			return nil, err
		}
		cfg.TURNURLs = urls
		if len(cfg.TURNSecret) < 16 {
			return nil, errors.New("TURN needs a static-auth-secret of at least 16 bytes")
		}
	}
	cfg.TURNSecret = append([]byte(nil), cfg.TURNSecret...)
	if cfg.MaxMessageBytes < 1024 || cfg.MaxMessageBytes > 1024*1024 || cfg.SourceCreateCapacity < 1 || cfg.SourceCreateCapacity > 100000 || cfg.IPJoinCapacity < 1 || cfg.IPJoinCapacity > 100000 || cfg.PrefixJoinCapacity < 1 || cfg.PrefixJoinCapacity > 100000 || cfg.MaxConnections < 1 || cfg.IPConnections < 1 || cfg.PrefixConnections < cfg.IPConnections || cfg.ConnectCapacity < 1 || cfg.TURNDailyPerSource < 1 || cfg.TURNDailyPerSource > 1000000 || cfg.ConnectRefill <= 0 || cfg.MaxRooms < 1 || cfg.MaxCodes < cfg.MaxRooms || cfg.MaxSources < 2 || cfg.Wait <= 0 || cfg.Negotiate <= 0 || cfg.Orphan <= 0 || cfg.Hard <= 0 || cfg.Hello <= 0 || cfg.Ping <= 0 || cfg.Heartbeat <= cfg.Ping || cfg.Write <= 0 {
		return nil, errors.New("invalid signaling configuration")
	}
	s := &Server{cfg: cfg, rooms: map[string]*room{}, codes: map[[32]byte]*room{}, retired: map[[32]byte]time.Time{}, sources: map[string]*sourceBudget{}, clients: map[*client]bool{}, done: make(chan struct{}), tickets: newTicketKeys(time.Now()), slots: map[[16]byte]*resumeSlot{}}
	s.checkOrigin = checkOrigin
	if len(cfg.Regions) > 0 {
		if cfg.GeoFile == "" {
			return nil, errors.New("regions need a geo database")
		}
		geo, err := loadGeo(cfg.GeoFile)
		if err != nil {
			return nil, err
		}
		s.cfg.Regions = append([]Region(nil), cfg.Regions...)
		if s.regions, err = newRegionTable(geo, s.cfg.Regions); err != nil {
			return nil, err
		}
	}
	if s.events, err = openEventLog(cfg.EventsDB); err != nil {
		return nil, err
	}
	if cfg.TicketKeyFile != "" {
		k, err := loadTicketKeys(cfg.TicketKeyFile, time.Now())
		if err != nil {
			return nil, err
		}
		s.tickets = k
	}
	if _, err := rand.Read(s.pepper[:]); err != nil {
		return nil, err
	}
	if cfg.RetiredCodesFile != "" {
		s.loadRetired(cfg.RetiredCodesFile, time.Now())
	}
	if cfg.NoticesFile != "" {
		if len(cfg.NoticesKeys) == 0 {
			return nil, errors.New("notices need at least one public key")
		}
		s.notices = newNoticeWatcher(cfg.NoticesFile, cfg.NoticesCache, cfg.NoticesKeys)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case now := <-t.C:
				s.mu.Lock()
				s.sweep(now)
				due := s.notices != nil && now.Sub(s.noticesAt) >= noticesEvery
				if due {
					s.noticesAt = now
				}
				s.mu.Unlock()
				if due {
					s.pollNotices()
				}
			case <-s.done:
				return
			}
		}
	}()
	return s, nil
}

func (s *Server) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		if s.cfg.RetiredCodesFile != "" {
			s.saveRetired(s.cfg.RetiredCodesFile, time.Now())
		}
		close(s.done)
		for c := range s.clients {
			c.stop()
		}
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.events.close()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/healthz" {
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			http.Error(w, "stopped", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","profile":"development"}`)
		return
	}
	if r.URL.Path != "/signal" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	found := false
	for _, p := range websocket.Subprotocols(r) {
		if p == Subprotocol {
			found = true
		}
	}
	if !found {
		http.Error(w, "development subprotocol required", 400)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid remote address", 400)
		return
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		http.Error(w, "invalid remote address", 400)
		return
	}
	source, prefix := sourceKeys(ip)
	region := s.regions.lookup(ip) // the address itself is not kept for this
	s.mu.Lock()
	if s.closed || s.connections >= s.cfg.MaxConnections {
		if s.closed {
			s.metrics.rejected[rejectStopped].Add(1)
		} else {
			s.metrics.rejected[rejectGlobal].Add(1)
		}
		s.mu.Unlock()
		s.refused(region, 503, time.Now())
		http.Error(w, "unavailable", 503)
		return
	}
	// Never trust forwarded IP headers. A reverse proxy currently shares a budget.
	if len(s.sources)+2 > s.cfg.MaxSources && (s.sources[source] == nil || s.sources[prefix] == nil) {
		s.metrics.rejected[rejectSources].Add(1)
		s.mu.Unlock()
		s.refused(region, 503, time.Now())
		http.Error(w, "unavailable", 503)
		return
	}
	now := time.Now()
	for _, key := range []string{source, prefix} {
		if s.sources[key] == nil {
			s.sources[key] = &sourceBudget{}
		}
		s.sources[key].last = now
	}
	// 04 §3.3.5: refused before the WebSocket upgrade, so a refused connection
	// costs no more than its HTTP request.
	src, pfx := s.sources[source], s.sources[prefix]
	if wait := src.connect.take(now, float64(s.cfg.ConnectCapacity), s.cfg.ConnectRefill); wait > 0 {
		s.metrics.rejected[rejectRate].Add(1)
		s.mu.Unlock()
		s.refused(region, 429, now)
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		http.Error(w, "too many new connections", http.StatusTooManyRequests)
		return
	}
	if src.conns >= s.cfg.IPConnections || pfx.conns >= s.cfg.PrefixConnections {
		if src.conns >= s.cfg.IPConnections {
			s.metrics.rejected[rejectIP].Add(1)
		} else {
			s.metrics.rejected[rejectPrefix].Add(1)
		}
		s.mu.Unlock()
		s.refused(region, 429, now)
		w.Header().Set("Retry-After", "30")
		http.Error(w, "too many connections", http.StatusTooManyRequests)
		return
	}
	src.conns++
	pfx.conns++
	s.connections++
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()
	defer func() { s.mu.Lock(); s.connections--; src.conns--; pfx.conns--; s.mu.Unlock() }()
	u := websocket.Upgrader{Subprotocols: []string{Subprotocol}, HandshakeTimeout: s.cfg.Hello, ReadBufferSize: 1024, WriteBufferSize: 1024, CheckOrigin: s.checkOrigin}
	ws, err := u.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &client{metrics: &s.metrics, ws: ws, send: make(chan outbound, 16), done: make(chan struct{}), source: source, prefix: prefix, region: region, platform: "unknown"}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.stop()
		return
	}
	s.clients[c] = true
	s.mu.Unlock()
	writerDone := make(chan struct{})
	go func() { defer close(writerDone); c.writeLoop(s.cfg) }()
	defer func() {
		c.stop()
		<-writerDone
		s.mu.Lock()
		delete(s.clients, c)
		s.disconnect(c, time.Now())
		s.mu.Unlock()
	}()
	ws.SetReadLimit(s.cfg.MaxMessageBytes)
	_ = ws.SetReadDeadline(time.Now().Add(s.cfg.Hello))
	ws.SetPongHandler(func(string) error {
		if c.hello {
			return ws.SetReadDeadline(time.Now().Add(s.cfg.Heartbeat))
		}
		return nil
	})
	for {
		kind, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if kind != websocket.TextMessage {
			c.emit(failure(8001, 0), true)
			<-c.done
			return
		}
		req, err := decode(data)
		if err != nil {
			c.emit(failure(8001, 0), true)
			<-c.done
			return
		}
		if !c.hello {
			if req.Type != "hello" {
				c.emit(failure(8003, 0), true)
				<-c.done
				return
			}
			if *req.Version != 1 {
				c.emit(failure(8002, 0), true)
				<-c.done
				return
			}
			c.hello = true
			c.helloAt = time.Now().Unix()
			c.platform, c.version = clientPlatform(req.Client)
			s.record(c, evConnect, 0, time.Now())
			if _, err := rand.Read(c.connNonce[:]); err != nil {
				panic(err)
			}
			m := message{"t": "hello_ok", "v": 1, "minClientProto": 1, "serverTime": c.helloAt, "region": s.cfg.Region, "draining": false,
				"connNonce": base64.RawURLEncoding.EncodeToString(c.connNonce[:]), "notices": s.activeNotices(time.Now(), c.platform)}
			respond(c, req, m)
			_ = ws.SetReadDeadline(time.Now().Add(s.cfg.Heartbeat))
			continue
		}
		_ = ws.SetReadDeadline(time.Now().Add(s.cfg.Heartbeat))
		if req.Type == "hello" {
			c.emit(failure(8001, 0), true)
			<-c.done
			return
		}
		delay := s.dispatch(c, req, time.Now())
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-c.done:
				timer.Stop()
				return
			case <-s.done:
				timer.Stop()
				return
			}
		}
		if c.pending != nil {
			respond(c, req, c.pending)
			c.pending = nil
		}
	}
}

func (c *client) writeLoop(cfg Config) {
	defer c.stop()
	t := time.NewTicker(cfg.Ping)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if err := c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(cfg.Write)); err != nil {
				return
			}
		case out := <-c.send:
			_ = c.ws.SetWriteDeadline(time.Now().Add(cfg.Write))
			if err := c.ws.WriteJSON(out.m); err != nil {
				return
			}
			if out.close {
				_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "invalid request"), time.Now().Add(cfg.Write))
				return
			}
		}
	}
}

func respond(c *client, r request, m message) {
	c.metrics.response(r, m)
	if r.ID != "" {
		m["id"] = r.ID
	}
	c.emit(m, false)
}
func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func (s *Server) hash(code string) [32]byte {
	h := hmac.New(sha256.New, s.pepper[:])
	_, _ = h.Write([]byte(code))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (s *Server) dispatch(c *client, req request, now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	if wait := c.all.take(now, 60, time.Second/20); wait > 0 {
		respond(c, req, failure(8051, wait))
		return 0
	}
	switch req.Type {
	case "ping":
		respond(c, req, message{"t": "pong"})
	case "turn_credentials":
		if len(s.cfg.TURNSecret) == 0 || len(s.cfg.TURNURLs) == 0 {
			respond(c, req, failure(8032, 0)) // no relay here: P2P only
			break
		}
		if s.notices != nil && s.notices.current().RelayPaused {
			// The operator paused the relay; clients still try a direct connection.
			s.record(c, evTURNPaused, 0, now)
			m := failure(8032, 0)
			m["reason"] = "paused"
			respond(c, req, m)
			break
		}
		if wait := c.turn.take(now, 5, 12*time.Second); wait > 0 {
			respond(c, req, failure(8051, wait))
			break
		}
		if !verifyTURN(c, req, now) {
			respond(c, req, failure(8031, 0))
			break
		}
		// A daily budget per address (IPv4 / IPv6 /64), not per connection: a
		// script reconnecting cannot keep drawing relay credentials. Generous,
		// because many users can share one address behind carrier NAT. It counts a
		// Beijing calendar day; 8030 tells the client when it comes back.
		b := s.sources[c.source]
		b.last = now
		if ok, reset := b.takeTURN(now, s.cfg.TURNDailyPerSource); !ok {
			s.record(c, evTURNLimited, 0, now)
			m := failure(8030, 0)
			m["resetAt"] = reset.Unix()
			respond(c, req, m)
			break
		}
		{
			user, cred := turnCredential(s.cfg.TURNSecret, now)
			stun, turn := s.iceURLs(c)
			urls := append(append([]string(nil), stun...), turn...)
			s.record(c, evTURNIssued, 0, now)
			respond(c, req, message{"t": "turn_credentials_ok", "username": user, "credential": cred, "ttl": int(turnTTL / time.Second), "urls": urls})
		}
	case "hello":
		c.emit(failure(8001, 0), true)
	case "create_room":
		if c.room != nil {
			respond(c, req, failure(8001, 0))
			break
		}
		wait := c.create.take(now, 3, 20*time.Second)
		b := s.sources[c.source]
		b.last = now
		wait = max(wait, b.create.take(now, float64(s.cfg.SourceCreateCapacity), time.Minute))
		if wait > 0 {
			respond(c, req, failure(8012, wait))
			break
		}
		if len(s.rooms) >= s.cfg.MaxRooms || len(s.codes)+len(s.retired) >= s.cfg.MaxCodes {
			respond(c, req, failure(8014, 10))
			break
		}
		var code string
		var hash [32]byte
		for {
			n, err := rand.Int(rand.Reader, big.NewInt(90000000))
			if err != nil {
				respond(c, req, failure(8040, 1))
				return 0
			}
			code = new(big.Int).Add(n, big.NewInt(10000000)).String()
			hash = s.hash(code)
			if s.codes[hash] == nil {
				if _, used := s.retired[hash]; !used {
					break
				}
			}
		}
		r := &room{id: randomID(16), code: hash, creator: c, expires: now.Add(s.cfg.Wait), hard: now.Add(s.cfg.Hard), eids: [2]string{randomID(8), randomID(8)},
			region: c.region, platform: c.platform, version: c.version}
		mustRandom(r.session[:])
		s.rooms[r.id] = r
		s.codes[hash] = r
		c.room = r
		s.metrics.created.Add(1)
		s.record(c, evRoomCreated, 0, now)
		respond(c, req, message{"t": "room_created", "room": r.id, "code": code, "expiresAt": r.expires.Unix(), "iceServers": s.iceServers(c)})
	case "resume":
		s.resume(c, req, now)
	case "join_room":
		if c.room != nil {
			respond(c, req, failure(8001, 0))
			break
		}
		ip, prefix := s.sources[c.source], s.sources[c.prefix]
		ip.last = now
		prefix.last = now
		wait := c.join.take(now, 5, 30*time.Second)
		wait = max(wait, ip.join.take(now, float64(s.cfg.IPJoinCapacity), time.Minute), prefix.join.take(now, float64(s.cfg.PrefixJoinCapacity), 10*time.Second))
		for _, b := range []*sourceBudget{ip, prefix} {
			if now.Before(b.frozen) {
				wait = max(wait, int(b.frozen.Sub(now).Seconds())+1)
			}
		}
		if wait > 0 {
			s.record(c, evJoinFailed, 8012, now)
			respond(c, req, failure(8012, wait))
			break
		}
		code := strings.NewReplacer(" ", "", "-", "").Replace(req.Code)
		r := s.codes[s.hash(code)]
		if r == nil || r.creator == nil || r.paired {
			code, delay := ip.fail(now)
			prefixCode, prefixDelay := prefix.fail(now)
			code = max(code, prefixCode)
			delay = max(delay, prefixDelay)
			s.record(c, evJoinFailed, int64(code), now)
			if code != 8010 {
				c.pending = failure(code, int(delay.Seconds()))
				delay = 300 * time.Millisecond
			} else {
				c.pending = failure(8010, 0)
			}
			// Padding is performed by the reader, outside the room lock.
			return delay
		}
		r.paired = true
		s.metrics.paired.Add(1)
		s.record(c, evRoomPaired, 0, now)
		r.pairedAt = now
		r.joiner = c
		c.room = r
		r.expires = now.Add(s.cfg.Negotiate)
		delete(s.codes, r.code)
		s.retired[r.code] = now.Add(s.cfg.Wait)
		respond(c, req, message{"t": "room_joined", "room": r.id, "peerEphemeralId": r.eids[0], "iceServers": s.iceServers(c)})
		r.creator.emit(message{"t": "peer_joined", "room": r.id, "peerEphemeralId": r.eids[1]}, false)
	case "signal", "ready", "bye":
		r := c.room
		if r == nil || r.id != req.Room {
			respond(c, req, failure(8020, 0))
			break
		}
		if req.Type == "bye" {
			s.closeRoom(r, *req.Reason, now)
			break
		}
		if !r.paired {
			respond(c, req, failure(8001, 0))
			break
		}
		peer := r.joiner
		side := 0
		if c == r.joiner {
			peer = r.creator
			side = 1
		}
		if peer == nil {
			respond(c, req, failure(8023, 0))
			break
		}
		if req.Type == "signal" {
			m := message{"t": "signal", "room": r.id, "kind": req.Kind, "payload": *req.Payload}
			// JSON escaping may expand the outbound envelope beyond the input.
			data, _ := json.Marshal(m)
			if int64(len(data)) > s.cfg.MaxMessageBytes {
				respond(c, req, failure(8050, 0))
				break
			}
			peer.emit(m, false)
		} else {
			r.ready[side] = true
			pk, _ := base64.RawURLEncoding.DecodeString(req.PKHash)
			copy(r.pkHash[side][:], pk)
			if r.ready[0] && r.ready[1] {
				s.closeRoom(r, 0, now)
			}
		}
	}
	return 0
}

func (s *Server) closeRoom(r *room, reason uint, now time.Time) {
	if r.paired {
		s.events.add(event{at: now, region: s.regions.name(r.region), name: evRoomClosed, platform: r.platform, version: r.version,
			detail: int64(reason), hasDetail: true, seconds: int64(now.Sub(r.pairedAt).Seconds()), hasDuration: true})
	}
	delete(s.rooms, r.id)
	if s.codes[r.code] != nil {
		delete(s.codes, r.code)
		s.retired[r.code] = now.Add(s.cfg.Wait)
	}
	first := r.firstIssued
	if first == 0 {
		first = now.Unix()
	}
	for side, c := range []*client{r.creator, r.joiner} {
		if c != nil {
			c.room = nil
			m := message{"t": "room_closed", "room": r.id, "reason": reason}
			if reason == 0 && r.ready[0] && r.ready[1] {
				// 04 v1.5 §2.6: each side its own ticket, bound to its identity.
				m["ticket"] = s.tickets.seal(ticket{session: r.session, role: uint8(side + 1), pkHash: r.pkHash[side], firstIssued: first, expires: now.Add(ticketTTL).Unix()})
			}
			c.emit(m, false)
		}
	}
}
func (s *Server) disconnect(c *client, now time.Time) {
	s.leaveSlot(c)
	r := c.room
	if r == nil {
		return
	}
	c.room = nil
	if !r.paired {
		r.creator = nil
		r.orphan = now.Add(s.cfg.Orphan)
		return
	}
	peer := r.creator
	if c == r.creator {
		r.creator = nil
		peer = r.joiner
	} else {
		r.joiner = nil
	}
	if peer != nil {
		peer.emit(message{"t": "peer_left", "room": r.id, "reason": 8023}, false)
	}
	s.closeRoom(r, 8023, now)
}
func (s *Server) sweep(now time.Time) {
	if s.tickets.rotate(now) {
		s.metrics.keyRotations.Add(1)
		if s.tickets.path != "" {
			s.keysUnsaved, s.keysRetry, s.keysBackoff = true, now, 0
		}
	}
	// The new key is used either way; until it is saved, a restart ends the
	// tickets it signed.
	if s.keysUnsaved && !now.Before(s.keysRetry) {
		if err := saveTicketKeys(s.tickets); err != nil {
			s.metrics.keyWriteFailures.Add(1)
			s.keysBackoff = min(max(2*s.keysBackoff, time.Minute), time.Hour)
			s.keysRetry = now.Add(s.keysBackoff)
			log.Printf("ticket keys not saved, retrying in %v: %v", s.keysBackoff, err)
		} else {
			if s.keysBackoff > 0 {
				log.Print("ticket keys saved after earlier failures")
			}
			s.keysUnsaved = false
		}
	}
	for id, slot := range s.slots {
		if !now.Before(slot.expires) {
			for _, m := range slot.members {
				if m != nil {
					m.slot = nil
					s.metrics.resumeFail.Add(1)
					s.record(m, evResumeFailed, 8021, now)
					m.emit(failure(8021, 0), false)
				}
			}
			delete(s.slots, id)
		}
	}
	for _, r := range s.rooms {
		if !now.Before(r.expires) || !now.Before(r.hard) || (!r.orphan.IsZero() && !now.Before(r.orphan)) {
			reason := uint(8021)
			if r.paired {
				reason = 8022
			}
			s.closeRoom(r, reason, now)
		}
	}
	for code, until := range s.retired {
		if !now.Before(until) {
			delete(s.retired, code)
		}
	}
	// Budgets remain for an hour even after disconnect. Bound total keys rather
	// than evicting active rate limits to make room for attacker-controlled IPs.
	active := map[string]bool{}
	for c := range s.clients {
		active[c.source] = true
		active[c.prefix] = true
	}
	for key, b := range s.sources {
		// An address that drew relay credentials is kept until its daily budget
		// has refilled (at most a day), or the limit would reset after an hour.
		if !active[key] && b.conns == 0 && now.Sub(b.last) > time.Hour && !now.Before(b.frozen) && !b.turnSpentToday(now) {
			delete(s.sources, key)
		}
	}
}

// Shutdown stops websocket handlers too (net/http Shutdown does not own them).
func Shutdown(ctx context.Context, httpServer *http.Server, signaling *Server) error {
	signaling.Close()
	return httpServer.Shutdown(ctx)
}

// iceURLs: the client's region's STUN and TURN lists; an empty list in a
// region falls back to the default one (Config.STUNURLs / TURNURLs).
func (s *Server) iceURLs(c *client) (stun, turn []string) {
	stun, turn = s.cfg.STUNURLs, s.cfg.TURNURLs
	if c.region >= 0 {
		r := s.cfg.Regions[c.region]
		if len(r.STUNURLs) > 0 {
			stun = r.STUNURLs
		}
		if len(r.TURNURLs) > 0 {
			turn = r.TURNURLs
		}
	}
	return stun, turn
}

func (s *Server) iceServers(c *client) []message {
	stun, _ := s.iceURLs(c)
	servers := make([]message, 0, len(stun))
	for _, uri := range stun {
		servers = append(servers, message{"urls": []string{uri}})
	}
	return servers
}

// noticesEvery: how often the notices file is checked (only its hash when unchanged).
const noticesEvery = 5 * time.Second

// pollNotices reads a changed notices file; a bad one is logged and counted and
// the current version stays.
func (s *Server) pollNotices() {
	if s.notices == nil {
		return
	}
	if changed, err := s.notices.poll(); err != nil {
		s.metrics.noticesRejected.Add(1)
		log.Printf("notices file rejected, keeping the current version: %v", err)
	} else if changed {
		log.Printf("notices updated (issued %s)", s.notices.current().IssuedAt.Format(time.RFC3339))
	}
}

func (s *Server) activeNotices(now time.Time, platform string) []message {
	if s.notices == nil {
		return []message{}
	}
	return s.notices.current().active(now, platform)
}

// record adds an anonymous event for a client; detail 0 means none.
func (s *Server) record(c *client, name string, detail int64, now time.Time) {
	s.events.add(event{at: now, region: s.regions.name(c.region), name: name, platform: c.platform, version: c.version, detail: detail, hasDetail: detail != 0})
}

// refused records a connection turned away before its upgrade (no hello yet).
func (s *Server) refused(region int, status int64, now time.Time) {
	s.events.add(event{at: now, region: s.regions.name(region), name: evRejected, platform: "unknown", detail: status, hasDetail: true})
}

func checkSTUN(uri string) error {
	if !strings.HasPrefix(uri, "stun:") || len(uri) > 256 {
		return errors.New("STUN URL must be stun:host:port")
	}
	host, port, err := net.SplitHostPort(strings.TrimPrefix(uri, "stun:"))
	n, portErr := strconv.Atoi(port)
	if err != nil || host == "" || strings.ContainsAny(host, "/@?# \\ \t\r\n") || portErr != nil || n < 1 || n > 65535 {
		return errors.New("invalid STUN host or port")
	}
	return nil
}

// resume (04 v1.5 §2.6): a ticket holder proves its identity, waits up to two
// minutes for the other side of the session, then both get a fresh room in
// the negotiating state.
func (s *Server) resume(c *client, req request, now time.Time) {
	if c.room != nil || c.slot != nil {
		respond(c, req, failure(8001, 0))
		return
	}
	if wait := c.join.take(now, 5, 30*time.Second); wait > 0 {
		s.record(c, evResumeFailed, 8012, now)
		respond(c, req, failure(8012, wait))
		return
	}
	t, ok := s.tickets.open(req.Ticket, now)
	pk, _ := base64.RawURLEncoding.DecodeString(req.PK)
	sig, _ := base64.RawURLEncoding.DecodeString(req.Sig)
	if !ok || !verifyResume(t, req.Ticket, pk, *req.TS, sig, c.connNonce, now) {
		s.record(c, evResumeFailed, 8060, now)
		respond(c, req, failure(8060, 0))
		return
	}
	slot := s.slots[t.session]
	if slot == nil {
		if len(s.slots)+len(s.rooms) >= s.cfg.MaxRooms {
			s.record(c, evResumeFailed, 8040, now)
			respond(c, req, failure(8040, 0))
			return
		}
		slot = &resumeSlot{firstIssued: t.firstIssued, expires: now.Add(resumeSlotLife)}
		s.slots[t.session] = slot
	}
	side := int(t.role - 1)
	if old := slot.members[side]; old != nil && old != c {
		// The same side again: the newer connection replaces the older one.
		old.slot = nil
		s.metrics.resumeFail.Add(1)
		s.record(old, evResumeFailed, 8060, now)
		old.emit(failure(8060, 0), false)
	}
	slot.members[side], slot.sdpNeeded[side] = c, *req.SDP
	session := t.session
	c.slot = &session
	if slot.members[0] == nil || slot.members[1] == nil {
		return
	}
	delete(s.slots, t.session)
	s.metrics.resumeOK.Add(2)
	for _, m := range slot.members {
		s.record(m, evResumed, 0, now)
	}
	r := &room{id: randomID(16), creator: slot.members[0], joiner: slot.members[1], paired: true, session: t.session, firstIssued: slot.firstIssued,
		expires: now.Add(s.cfg.Negotiate), hard: now.Add(s.cfg.Hard), eids: [2]string{randomID(8), randomID(8)},
		region: slot.members[0].region, platform: slot.members[0].platform, version: slot.members[0].version, pairedAt: now}
	s.rooms[r.id] = r
	for i, m := range slot.members {
		m.slot = nil
		m.room = r
		m.emit(message{"t": "room_resumed", "room": r.id, "peerEphemeralId": r.eids[1-i], "peerSdpNeeded": slot.sdpNeeded[1-i], "iceServers": s.iceServers(m)}, false)
	}
}

func (s *Server) leaveSlot(c *client) {
	if c.slot == nil {
		return
	}
	if slot := s.slots[*c.slot]; slot != nil {
		for i, m := range slot.members {
			if m == c {
				s.metrics.resumeFail.Add(1)
				s.record(c, evResumeFailed, 0, time.Now()) // left while waiting for the other side
				slot.members[i] = nil
			}
		}
		if slot.members[0] == nil && slot.members[1] == nil {
			delete(s.slots, *c.slot)
		}
	}
	c.slot = nil
}
