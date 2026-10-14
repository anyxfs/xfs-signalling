package signal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// The ticket keys on disk (04 §2.6 "密钥存储"), so a restart keeps every
// outstanding ticket valid. Layout: magic ‖ u64(rotatedUnix) ‖ cur ‖ prev ‖
// SHA-256(all before)[0..8]. Only the current and the previous key are ever on
// disk: a stolen file forges tickets for at most the 48 hours they cover.

var ticketFileMagic = []byte("XFSTK1\x00\x00")

const ticketFileSize = 8 + 8 + 32 + 32 + 8

func encodeTicketKeys(k ticketKeys) []byte {
	b := make([]byte, 0, ticketFileSize)
	b = append(b, ticketFileMagic...)
	b = binary.BigEndian.AppendUint64(b, uint64(k.rotated.Unix()))
	b = append(b, k.cur[:]...)
	b = append(b, k.prev[:]...)
	sum := sha256.Sum256(b)
	return append(b, sum[:8]...)
}

func decodeTicketKeys(b []byte) (ticketKeys, error) {
	var k ticketKeys
	if len(b) != ticketFileSize || !bytes.Equal(b[:8], ticketFileMagic) {
		return k, errors.New("not a ticket key file")
	}
	sum := sha256.Sum256(b[:ticketFileSize-8])
	if !bytes.Equal(sum[:8], b[ticketFileSize-8:]) {
		return k, errors.New("ticket key file is damaged")
	}
	k.rotated = time.Unix(int64(binary.BigEndian.Uint64(b[8:16])), 0)
	copy(k.cur[:], b[16:48])
	copy(k.prev[:], b[48:80])
	return k, nil
}

// loadTicketKeys reads path, creating it when missing, and brings the keys up to
// now: a day or more since the last rotation rotates once; two days or more
// replaces both (every ticket they signed has expired anyway). A file that is
// there but unreadable is an error, never silently replaced: that would end
// every outstanding ticket without anyone noticing.
func loadTicketKeys(path string, now time.Time) (ticketKeys, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		k := newTicketKeys(now)
		k.path = path
		return k, saveTicketKeys(k)
	}
	if err != nil {
		return ticketKeys{}, err
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
			return ticketKeys{}, fmt.Errorf("%s is readable by others (mode %v); chmod 600 it", path, info.Mode().Perm())
		}
	}
	k, err := decodeTicketKeys(b)
	if err != nil {
		return ticketKeys{}, fmt.Errorf("%s: %w (remove it to start over; outstanding tickets then end)", path, err)
	}
	k.path = path
	if now.Sub(k.rotated) >= 2*ticketKeyLife {
		k = newTicketKeys(now)
		k.path = path
		return k, saveTicketKeys(k)
	}
	if k.rotate(now) {
		return k, saveTicketKeys(k)
	}
	return k, nil
}

// saveTicketKeys replaces the file whole: a crash leaves the old one or the new
// one, never half of either. The temporary file is new and exclusively created
// (0600 on POSIX), so a stale or planted one can never lend the keys its mode.
// One process writes a key file.
func saveTicketKeys(k ticketKeys) error {
	f, err := os.CreateTemp(filepath.Dir(k.path), filepath.Base(k.path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(encodeTicketKeys(k))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, k.path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(k.path))
}

// syncDir makes the rename itself durable. Windows cannot open a directory for
// syncing (NTFS journals the rename); there it is not attempted.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
