package signal

import (
	"database/sql"
	"log"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// Anonymous events for operations analysis, one row each, in a SQLite file
// (EventsDB). A row has the hour (China Standard Time), the client's region,
// the event, an optional numeric detail (an error or close code), the client's
// platform and version from hello, and for a closed room how long it lasted.
// Never an address, pairing code, room, ticket, key or any identifier: rows
// cannot be tied to a person or a device, nor to each other. Rows older than
// eventRetention are deleted.
const (
	evConnect      = "connect"
	evRejected     = "rejected"      // detail: 429 / 503
	evRoomCreated  = "room_created"  //
	evRoomPaired   = "room_paired"   //
	evJoinFailed   = "join_failed"   // detail: 8010 / 8012 / 8013
	evRoomClosed   = "room_closed"   // detail: close reason; seconds since paired
	evResumed      = "resumed"       //
	evResumeFailed = "resume_failed" // detail: error code
	evTURNIssued   = "turn_issued"   //
	evTURNLimited  = "turn_limited"  // daily per-address budget spent
	evTURNPaused   = "turn_paused"   // the operator paused the relay (notices.json)
)

const eventRetention = 400 * 24 * time.Hour

type event struct {
	at                     time.Time
	region, name           string
	detail, seconds        int64
	platform, version      string
	hasDetail, hasDuration bool
}

// clientTag is what hello's "client" field must look like to be recorded;
// anything else is recorded as platform "unknown" with no version.
var clientTag = regexp.MustCompile(`^anyxfs/(\d{1,3}\.\d{1,3}\.\d{1,4}) \((windows|macos|linux|android|ios)\)$`)

func clientPlatform(tag string) (platform, version string) {
	if m := clientTag.FindStringSubmatch(tag); m != nil {
		return m[2], m[1]
	}
	return "unknown", ""
}

// eventLog queues events without blocking the server; a writer goroutine
// stores them in batches. When the queue is full events are dropped and counted.
type eventLog struct {
	db      *sql.DB
	queue   chan event
	stop    chan struct{}
	done    chan struct{}
	dropped atomic.Uint64
	closing sync.Once
}

func openEventLog(path string) (*eventLog, error) {
	if path == "" {
		return nil, nil
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS events (
		hour     TEXT    NOT NULL, -- 2026-10-14T18, China Standard Time
		region   TEXT    NOT NULL,
		event    TEXT    NOT NULL,
		detail   INTEGER,
		platform TEXT    NOT NULL,
		version  TEXT    NOT NULL,
		seconds  INTEGER
	);
	CREATE INDEX IF NOT EXISTS events_hour ON events(hour);`); err != nil {
		db.Close()
		return nil, err
	}
	l := &eventLog{db: db, queue: make(chan event, 4096), stop: make(chan struct{}), done: make(chan struct{})}
	go l.run()
	return l, nil
}

func (l *eventLog) add(e event) {
	if l == nil {
		return
	}
	select {
	case l.queue <- e:
	default:
		l.dropped.Add(1)
	}
}

func (l *eventLog) run() {
	defer close(l.done)
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	var batch []event
	pruned := time.Time{}
	for {
		select {
		case <-l.stop:
			for {
				select {
				case e := <-l.queue:
					batch = append(batch, e)
				default:
					l.write(batch)
					return
				}
			}
		case e := <-l.queue:
			batch = append(batch, e)
			if len(batch) < 512 {
				continue
			}
		case now := <-t.C:
			if now.Sub(pruned) > time.Hour {
				pruned = now
				cut := now.Add(-eventRetention).In(statsZone).Format("2006-01-02T15")
				if _, err := l.db.Exec(`DELETE FROM events WHERE hour < ?`, cut); err != nil {
					log.Printf("events not pruned: %v", err)
				}
			}
		}
		l.write(batch)
		batch = batch[:0]
	}
}

func (l *eventLog) write(batch []event) {
	if len(batch) == 0 {
		return
	}
	tx, err := l.db.Begin()
	if err == nil {
		var st *sql.Stmt
		if st, err = tx.Prepare(`INSERT INTO events(hour, region, event, detail, platform, version, seconds) VALUES (?, ?, ?, ?, ?, ?, ?)`); err == nil {
			for _, e := range batch {
				var detail, seconds any
				if e.hasDetail {
					detail = e.detail
				}
				if e.hasDuration {
					seconds = e.seconds
				}
				if _, err = st.Exec(e.at.In(statsZone).Format("2006-01-02T15"), e.region, e.name, detail, e.platform, e.version, seconds); err != nil {
					break
				}
			}
			st.Close()
		}
		if err == nil {
			err = tx.Commit()
		} else {
			tx.Rollback()
		}
	}
	if err != nil {
		l.dropped.Add(uint64(len(batch)))
		log.Printf("%d events not stored: %v", len(batch), err)
	}
}

// close stores what is queued and closes the database. Events added later are
// dropped, never a panic: the queue itself is not closed.
func (l *eventLog) close() {
	if l == nil {
		return
	}
	l.closing.Do(func() {
		close(l.stop)
		<-l.done
		l.db.Close()
	})
}

var statsZone = time.FixedZone("CST", 8*3600)
