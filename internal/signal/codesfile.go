package signal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Codes keep out of reuse across a restart (04 §3.2: none is handed out again
// within T_wait of its end). A stopping server writes every code it knew — the
// rooms still open end with it, so they count as just retired — and the next
// one reads them back, then removes the file. Layout: magic ‖ pepper ‖
// u32(count) ‖ count × (code HMAC ‖ u64(untilUnix)) ‖ SHA-256(all before)[0..8].
//
// Not covered: a crash or power loss writes nothing, so that restart has no
// quarantine; the codes are then as likely to come back as any other (SAS and
// the receiving confirmation still stand between a late joiner and a stranger).
// The file holds the pepper with the hashes, so it reveals the codes in it —
// all of which are dead by the time it exists.

var codesFileMagic = []byte("XFSRC1\x00\x00")

const codesEntry = 32 + 8

func encodeRetired(pepper [32]byte, retired map[[32]byte]time.Time) []byte {
	b := make([]byte, 0, 8+32+4+len(retired)*codesEntry+8)
	b = append(b, codesFileMagic...)
	b = append(b, pepper[:]...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(retired)))
	for hash, until := range retired {
		b = append(b, hash[:]...)
		b = binary.BigEndian.AppendUint64(b, uint64(until.Unix()))
	}
	sum := sha256.Sum256(b)
	return append(b, sum[:8]...)
}

func decodeRetired(b []byte, now time.Time) ([32]byte, map[[32]byte]time.Time, error) {
	var pepper [32]byte
	if len(b) < 8+32+4+8 || !bytes.Equal(b[:8], codesFileMagic) {
		return pepper, nil, errors.New("not a retired-codes file")
	}
	body, mac := b[:len(b)-8], b[len(b)-8:]
	if sum := sha256.Sum256(body); !bytes.Equal(sum[:8], mac) {
		return pepper, nil, errors.New("retired-codes file is damaged")
	}
	copy(pepper[:], body[8:40])
	n := int(binary.BigEndian.Uint32(body[40:44]))
	rest := body[44:]
	if len(rest) != n*codesEntry {
		return pepper, nil, errors.New("retired-codes file is damaged")
	}
	retired := make(map[[32]byte]time.Time, n)
	for i := 0; i < n; i++ {
		e := rest[i*codesEntry:]
		until := time.Unix(int64(binary.BigEndian.Uint64(e[32:40])), 0)
		if now.Before(until) {
			var hash [32]byte
			copy(hash[:], e[:32])
			retired[hash] = until
		}
	}
	return pepper, retired, nil
}

// loadRetired takes over the previous run's quarantine, if it left one; the file
// is removed either way. Problems are logged, never fatal: losing one restart's
// quarantine must not keep the service down.
func (s *Server) loadRetired(path string, now time.Time) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err == nil {
		var retired map[[32]byte]time.Time
		s.pepper, retired, err = decodeRetired(b, now)
		if err == nil {
			s.retired = retired
		}
	}
	if err != nil {
		log.Printf("retired codes not restored (%s), codes from before the restart may be reused: %v", path, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("retired-codes file not removed: %v", err)
	}
}

// saveRetired runs as the server stops, under s.mu.
func (s *Server) saveRetired(path string, now time.Time) {
	retired := make(map[[32]byte]time.Time, len(s.retired)+len(s.codes))
	for hash, until := range s.retired {
		if now.Before(until) {
			retired[hash] = until
		}
	}
	for hash := range s.codes {
		retired[hash] = now.Add(s.cfg.Wait)
	}
	if len(retired) == 0 {
		return
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err == nil {
		tmp := f.Name()
		_, err = f.Write(encodeRetired(s.pepper, retired))
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp, path)
		}
		if err != nil {
			_ = os.Remove(tmp)
		}
	}
	if err != nil {
		log.Printf("retired codes not saved, they may be reused after the restart: %v", err)
	}
}
