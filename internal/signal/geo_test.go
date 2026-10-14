package signal

import (
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const geoCSV = `1.0.0.0,1.0.0.255,AU
"1.0.1.0","1.0.3.255","CN"
1.0.4.0,1.0.7.255,CN
8.8.8.0,8.8.8.255,US
127.0.0.0,127.255.255.255,CN
2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP
2a00:1450::,2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff,DE
`

func TestGeoLookup(t *testing.T) {
	db, err := parseGeo(strings.NewReader(geoCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(db.v4) != 4 { // 1.0.1.0–1.0.7.255 merged into one CN range
		t.Fatalf("v4 ranges %d", len(db.v4))
	}
	for ip, want := range map[string]string{
		"1.0.0.7": "AU", "1.0.2.1": "CN", "1.0.7.255": "CN", "1.0.8.0": "", "8.8.8.8": "US", "0.0.0.1": "",
		"::ffff:8.8.8.8": "US", "2001:200::1": "JP", "2a00:1450:4001::1": "DE", "2a00:1451::": "", "::1": "",
	} {
		if got := db.country(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	for _, bad := range []string{"1.0.0.0,1.0.0.255", "1.0.0.9,1.0.0.1,AU", "1.0.0.0,::1,AU", "x,y,AU", "1.0.0.0,1.0.0.1,AUS"} {
		if _, err := parseGeo(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRegionTableRejectsBadConfig(t *testing.T) {
	db, _ := parseGeo(strings.NewReader(geoCSV))
	for _, regions := range [][]Region{
		{{Name: "", Countries: []string{"CN"}}},
		{{Name: DefaultRegion, Countries: []string{"CN"}}},
		{{Name: "a", Countries: []string{"CN"}}, {Name: "b", Countries: []string{"cn"}}},
		{{Name: "a", Countries: []string{"CHN"}}},
		{{Name: "a", STUNURLs: []string{"turn:x:3478"}}},
		{{Name: "a", TURNURLs: []string{"stun:x:3478"}}},
	} {
		if _, err := newRegionTable(db, regions); err == nil {
			t.Errorf("accepted %+v", regions)
		}
	}
}

// The test client connects from 127.0.0.1, which the fixture database puts in CN.
func TestRegionIceServersAndEvents(t *testing.T) {
	dir := t.TempDir()
	geo := filepath.Join(dir, "geo.csv")
	if err := os.WriteFile(geo, []byte(geoCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		name, region, stun string
		turn               []string
	}{
		{"in a region", "cn", "stun:stun1.example.cn:3478", []string{"turn:relay.example.cn:3478?transport=udp"}},
		{"region without TURN falls back", "cn", "stun:stun1.example.cn:3478", []string{"turn:default.example:3478?transport=udp"}},
		{"country in no region", DefaultRegion, "stun:default.example:3478", []string{"turn:default.example:3478?transport=udp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := filepath.Join(dir, fmt.Sprintf("events-%d.db", i))
			s, url := fixture(t, func(c *Config) {
				c.GeoFile, c.EventsDB = geo, db
				c.STUNURLs, c.TURNURLs, c.TURNSecret = []string{"stun:default.example:3478"}, []string{"turn:default.example:3478?transport=udp"}, []byte("0123456789abcdef-static-secret")
				region := Region{Name: "cn", Countries: []string{"CN"}, STUNURLs: []string{"stun:stun1.example.cn:3478"}}
				if tc.name == "in a region" {
					region.TURNURLs = tc.turn
				}
				if tc.region == DefaultRegion {
					region.Countries = []string{"US"}
				}
				c.Regions = []Region{region}
			})
			ws := dial(t, url)
			helloAt, connNonce := helloTURN(t, ws)
			m := create(t, ws)
			servers := m["iceServers"].([]any)
			if len(servers) != 1 || servers[0].(map[string]any)["urls"].([]any)[0] != tc.stun {
				t.Fatalf("iceServers %v", m["iceServers"])
			}
			_, sk, _ := ed25519.GenerateKey(nil)
			send(t, ws, turnRequest(sk, helloAt, connNonce))
			got := receive(t, ws, "turn_credentials_ok")
			urls := got["urls"].([]any)
			if len(urls) != 2 || urls[0] != tc.stun || urls[1] != tc.turn[0] {
				t.Fatalf("turn urls %v", urls)
			}
			s.Close()
			rows := queryEvents(t, db)
			for _, want := range []string{"connect", "room_created", "turn_issued"} {
				if rows[tc.region+" "+want] == 0 {
					t.Fatalf("no %s %s event: %v", tc.region, want, rows)
				}
			}
		})
	}
}

// A paired room's close is one event with the creator's platform, the close
// reason and how long it lasted; no column can hold an address or identifier.
func TestEventsForAPairedRoom(t *testing.T) {
	db := filepath.Join(t.TempDir(), "events.db")
	s, url := fixture(t, func(c *Config) { c.EventsDB = db })
	a, b := dial(t, url), dial(t, url)
	send(t, a, message{"t": "hello", "v": 1, "client": "anyxfs/1.0.3 (android)"})
	receive(t, a, "hello_ok")
	send(t, b, message{"t": "hello", "v": 1, "client": "anyxfs/1.0.3 (android) extra"})
	receive(t, b, "hello_ok")
	code := create(t, a)["code"].(string)
	send(t, b, message{"t": "join_room", "code": "00000000"})
	receive(t, b, "error")
	send(t, b, message{"t": "join_room", "code": code})
	room := receive(t, b, "room_joined")["room"].(string)
	receive(t, a, "peer_joined")
	send(t, a, message{"t": "bye", "room": room, "reason": 0})
	receive(t, a, "room_closed")
	s.Close()
	conn, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var platform, version string
	var detail, seconds sql.NullInt64
	if err := conn.QueryRow(`SELECT platform, version, detail, seconds FROM events WHERE event = 'room_closed'`).Scan(&platform, &version, &detail, &seconds); err != nil {
		t.Fatal(err)
	}
	if platform != "android" || version != "1.0.3" || !detail.Valid || detail.Int64 != 0 || !seconds.Valid {
		t.Fatalf("room_closed %s %s %v %v", platform, version, detail, seconds)
	}
	rows := queryEvents(t, db)
	if rows["other join_failed"] != 1 || rows["other room_paired"] != 1 || rows["other connect"] != 2 {
		t.Fatalf("events %v", rows)
	}
	var unknown int
	_ = conn.QueryRow(`SELECT count(*) FROM events WHERE event = 'connect' AND platform = 'unknown' AND version = ''`).Scan(&unknown)
	if unknown != 1 {
		t.Fatal("a malformed client tag must be recorded as unknown")
	}
}

func queryEvents(t *testing.T, path string) map[string]int {
	t.Helper()
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rs, err := conn.Query(`SELECT region || ' ' || event, count(*) FROM events GROUP BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	out := map[string]int{}
	for rs.Next() {
		var k string
		var n int
		if err := rs.Scan(&k, &n); err != nil {
			t.Fatal(err)
		}
		out[k] = n
	}
	return out
}

func TestClientPlatform(t *testing.T) {
	for tag, want := range map[string]string{
		"anyxfs/1.0.3 (ios)": "ios 1.0.3", "anyxfs/10.20.300 (windows)": "windows 10.20.300",
		"xfs-rust-dev": "unknown ", "anyxfs/1.0 (ios)": "unknown ", "anyxfs/1.0.3 (beos)": "unknown ", "": "unknown ",
	} {
		p, v := clientPlatform(tag)
		if p+" "+v != want {
			t.Errorf("%q: %s %s", tag, p, v)
		}
	}
}
