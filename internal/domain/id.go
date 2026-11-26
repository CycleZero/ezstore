package domain

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// NewID returns a lexicographically sortable identifier: 8 bytes of big-endian
// Unix nanoseconds followed by 8 random bytes. Sorting by ID approximates
// insertion order without relying on a database sequence, which keeps SQLite
// and MySQL behaviour identical.
func NewID() string {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], uint64(time.Now().UnixNano()))
	if _, err := rand.Read(buf[8:]); err != nil {
		// crypto/rand only fails when the OS entropy source is broken; at that
		// point the process cannot safely issue identifiers at all.
		panic("ezstore: entropy source unavailable: " + err.Error())
	}
	return hex.EncodeToString(buf[:])
}
