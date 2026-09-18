package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
)

// newTransactionID returns a random UUIDv4. It is attached to every log message
// belonging to one request so they can be traced in the journal.
func newTransactionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand must never fail
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// requestLogger returns a logger preloaded with the transaction_id and
// source_ip attributes required for request tracing.
func requestLogger(base *slog.Logger, tx, remoteAddr string) *slog.Logger {
	return base.With("transaction_id", tx, "source_ip", clientHost(remoteAddr))
}

// clientHost strips the port from a remote address.
func clientHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
