package main

import (
	"errors"
	"flag"
)

// config holds all server settings. Everything is configured via command line
// flags to keep the codebase minimal.
type config struct {
	Listen               string
	TaskSocket           string
	ServerCert           string
	ServerKey            string
	ClientCert           string
	MaxConcurrent        int
	MaxScriptTimeoutSecs int
	MaxWebhookDelaySecs  int
	WebhookTimeoutSecs   int
	WebhookClientCert    string
	WebhookClientKey     string
	WebhookServerCert    string
}

func parseFlags() *config {
	cfg := &config{}
	flag.StringVar(&cfg.Listen, "listen", ":8443", "listen address (host:port)")
	flag.StringVar(&cfg.TaskSocket, "task-socket", "", "unix socket of the task helper that executes the scripts")
	flag.StringVar(&cfg.ServerCert, "server-cert", "", "PEM encoded TLS server certificate (required)")
	flag.StringVar(&cfg.ServerKey, "server-key", "", "PEM encoded TLS server key (required)")
	flag.StringVar(&cfg.ClientCert, "client-cert", "", "PEM encoded client certificate that is pinned for authentication (required)")
	flag.IntVar(&cfg.MaxConcurrent, "max-concurrent", 4, "maximum number of scripts running simultaneously")
	flag.IntVar(&cfg.MaxScriptTimeoutSecs, "max-script-timeout-seconds", 3600, "maximum allowed script_timeout_seconds per request")
	flag.IntVar(&cfg.MaxWebhookDelaySecs, "max-webhook-delay-seconds", 300, "maximum allowed webhook_delay_seconds per request")
	flag.IntVar(&cfg.WebhookTimeoutSecs, "webhook-timeout-seconds", 30, "timeout for outgoing webhook calls")
	flag.StringVar(&cfg.WebhookClientCert, "webhook-client-cert", "", "PEM certificate presented to the webhook server")
	flag.StringVar(&cfg.WebhookClientKey, "webhook-client-key", "", "PEM key for the webhook client certificate")
	flag.StringVar(&cfg.WebhookServerCert, "webhook-server-cert", "", "PEM certificate of the webhook server that is pinned")
	flag.Parse()
	return cfg
}

// validate rejects invalid flag combinations as early as possible.
func (c *config) validate() error {
	if c.ServerCert == "" || c.ServerKey == "" || c.ClientCert == "" {
		return errors.New("-server-cert, -server-key and -client-cert are required")
	}
	if c.TaskSocket == "" {
		return errors.New("-task-socket is required")
	}
	if (c.WebhookClientCert == "") != (c.WebhookClientKey == "") {
		return errors.New("-webhook-client-cert and -webhook-client-key must be set together")
	}
	if c.MaxConcurrent < 1 {
		return errors.New("-max-concurrent must be at least 1")
	}
	if c.MaxScriptTimeoutSecs < 1 {
		return errors.New("-max-script-timeout-seconds must be at least 1")
	}
	if c.MaxWebhookDelaySecs < 0 {
		return errors.New("-max-webhook-delay-seconds must not be negative")
	}
	if c.WebhookTimeoutSecs < 1 {
		return errors.New("-webhook-timeout-seconds must be at least 1")
	}
	return nil
}
