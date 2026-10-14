package signal

import (
	"net/netip"
	"os"
	"testing"
)

// XFS_GEO=<dbip-country-lite .csv.gz> go test -run TestRealGeoDatabase: spot checks on the real file.
func TestRealGeoDatabase(t *testing.T) {
	path := os.Getenv("XFS_GEO")
	if path == "" {
		t.Skip("XFS_GEO not set")
	}
	db, err := loadGeo(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d IPv4 / %d IPv6 ranges", len(db.v4), len(db.v6))
	for ip, want := range map[string]string{
		"114.114.114.114": "CN", "223.5.5.5": "CN", "8.8.8.8": "US", "1.1.1.1": "AU",
		"2400:3200::1": "CN", "2a00:1450:4001:80b::200e": "DE", "2001:da8::1": "CN",
	} {
		if got := db.country(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
}
