package task

import (
	"crypto/rand"
	"fmt"
)

// NewTransactionID returns a random UUIDv4. It is attached to every log message
// belonging to one request so they can be traced in the journal.
func NewTransactionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand must never fail
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
