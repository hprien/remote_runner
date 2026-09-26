package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("remote_runner terminated", "error", err)
		os.Exit(1)
	}
}

// run configures and starts the TLS server. It returns when the server stops.
func run() error {
	cfg := parseFlags()
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCert, cfg.ServerKey)
	if err != nil {
		return fmt.Errorf("load server certificate: %w", err)
	}
	clientPin, err := loadCertFingerprint(cfg.ClientCert)
	if err != nil {
		return fmt.Errorf("load pinned client certificate: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	s := &server{
		cfg:       cfg,
		clientPin: clientPin,
		logger:    logger,
		slots:     make(chan struct{}, cfg.MaxConcurrent),
	}
	if s.webhookClient, err = s.newWebhookClient(); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", s.handleRun)

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: s.authenticate(mux),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{serverCert},
			// Any client certificate is accepted during the handshake. The
			// pinned certificate is enforced per request in authenticate.
			ClientAuth: tls.RequireAnyClientCert,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("remote_runner listening",
		"addr", cfg.Listen,
		"task_socket", cfg.TaskSocket,
		"max_concurrent", cfg.MaxConcurrent)
	return srv.ListenAndServeTLS("", "")
}
