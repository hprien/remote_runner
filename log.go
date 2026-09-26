package main

import (
	"log/slog"
	"net"
)

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
