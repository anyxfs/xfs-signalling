package signal

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// Region is a group of countries whose clients get their own STUN / TURN
// lists, and the unit daily statistics are counted in. A client's address is
// looked up once when it connects; only the region name is kept.
type Region struct {
	Name      string   `json:"name"`
	Countries []string `json:"countries"`
	STUNURLs  []string `json:"stun"`
	// Empty: the default TURN list (Config.TURNURLs). All nodes share one secret.
	TURNURLs []string `json:"turn"`
}

// RegionsFile is the JSON given to -regions-file.
type RegionsFile struct {
	// An offline country database: CSV "first,last,CC" per line (DB-IP
	// "IP to Country Lite", CC BY 4.0), optionally gzipped.
	GeoFile string   `json:"geo"`
	Regions []Region `json:"regions"`
}

// DefaultRegion names clients whose country is unknown or in no region.
const DefaultRegion = "other"

func LoadRegionsFile(path string) (RegionsFile, error) {
	var f RegionsFile
	data, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

type geoRange4 struct {
	first, last uint32
	cc          [2]byte
}

type geoRange6 struct {
	first, last [16]byte
	cc          [2]byte
}

// geoDB answers "which country is this address in" from sorted, merged ranges.
type geoDB struct {
	v4 []geoRange4
	v6 []geoRange6
}

func loadGeo(path string) (*geoDB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var r io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		z, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer z.Close()
		r = z
	}
	return parseGeo(r)
}

func parseGeo(r io.Reader) (*geoDB, error) {
	db := &geoDB{}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		parts := strings.Split(text, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("geo line %d: want first,last,CC", line)
		}
		first, err1 := netip.ParseAddr(strings.Trim(parts[0], `"`))
		last, err2 := netip.ParseAddr(strings.Trim(parts[1], `"`))
		cc := strings.ToUpper(strings.Trim(parts[2], `"`))
		if err1 != nil || err2 != nil || len(cc) != 2 || first.Is4() != last.Is4() || last.Less(first) {
			return nil, fmt.Errorf("geo line %d: invalid range", line)
		}
		code := [2]byte{cc[0], cc[1]}
		if first.Is4() {
			a, b := first.As4(), last.As4()
			db.v4 = append(db.v4, geoRange4{be32(a), be32(b), code})
		} else {
			db.v6 = append(db.v6, geoRange6{first.As16(), last.As16(), code})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(db.v4) == 0 {
		return nil, errors.New("geo database has no IPv4 ranges")
	}
	sort.Slice(db.v4, func(i, j int) bool { return db.v4[i].first < db.v4[j].first })
	sort.Slice(db.v6, func(i, j int) bool { return less16(db.v6[i].first, db.v6[j].first) })
	// Adjacent ranges of one country become one: the lite database splits many.
	merged4 := db.v4[:1]
	for _, g := range db.v4[1:] {
		p := &merged4[len(merged4)-1]
		if g.cc == p.cc && g.first == p.last+1 {
			p.last = max(p.last, g.last)
		} else {
			merged4 = append(merged4, g)
		}
	}
	db.v4 = merged4
	return db, nil
}

// country is "" when the address is not covered.
func (db *geoDB) country(ip netip.Addr) string {
	if db == nil {
		return ""
	}
	ip = ip.Unmap()
	var cc [2]byte
	if ip.Is4() {
		a := ip.As4()
		v := be32(a)
		i := sort.Search(len(db.v4), func(i int) bool { return db.v4[i].first > v }) - 1
		if i < 0 || v > db.v4[i].last {
			return ""
		}
		cc = db.v4[i].cc
	} else {
		v := ip.As16()
		i := sort.Search(len(db.v6), func(i int) bool { return less16(v, db.v6[i].first) }) - 1
		if i < 0 || less16(db.v6[i].last, v) {
			return ""
		}
		cc = db.v6[i].cc
	}
	return string(cc[:])
}

func be32(a [4]byte) uint32 {
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

func less16(a, b [16]byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// regionTable maps a country to its region index; -1 is the default region.
type regionTable struct {
	geo     *geoDB
	regions []Region
	byCC    map[string]int
}

func newRegionTable(geo *geoDB, regions []Region) (*regionTable, error) {
	t := &regionTable{geo: geo, regions: regions, byCC: map[string]int{}}
	for i, r := range regions {
		if r.Name == "" || r.Name == DefaultRegion || len(r.Name) > 16 || strings.ContainsAny(r.Name, " \t\r\n\"{}") {
			return nil, fmt.Errorf("region %d: invalid name %q", i, r.Name)
		}
		for _, cc := range r.Countries {
			cc = strings.ToUpper(cc)
			if len(cc) != 2 {
				return nil, fmt.Errorf("region %s: invalid country %q", r.Name, cc)
			}
			if _, dup := t.byCC[cc]; dup {
				return nil, fmt.Errorf("country %s is in two regions", cc)
			}
			t.byCC[cc] = i
		}
		if len(r.STUNURLs) > 8 {
			return nil, fmt.Errorf("region %s: at most eight STUN URLs", r.Name)
		}
		for _, uri := range r.STUNURLs {
			if err := checkSTUN(uri); err != nil {
				return nil, fmt.Errorf("region %s: %w", r.Name, err)
			}
		}
		if len(r.TURNURLs) > 0 {
			urls, err := ParseTURNURLs(r.TURNURLs)
			if err != nil {
				return nil, fmt.Errorf("region %s: %w", r.Name, err)
			}
			t.regions[i].TURNURLs = urls
		}
	}
	return t, nil
}

func (t *regionTable) lookup(ip netip.Addr) int {
	if t == nil {
		return -1
	}
	if i, ok := t.byCC[t.geo.country(ip)]; ok {
		return i
	}
	return -1
}

func (t *regionTable) name(i int) string {
	if t == nil || i < 0 {
		return DefaultRegion
	}
	return t.regions[i].Name
}
