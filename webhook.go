package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// webhookPayload is sent to script_response_webhook_url after the script
// finished and webhook_delay_seconds elapsed.
type webhookPayload struct {
	ScriptName string `json:"script_name"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ReturnCode int    `json:"return_code"`
}

// newWebhookClient builds the HTTP client used for webhook calls. Webhook
// connections use TLS 1.3 and, when configured, a pinned server certificate
// and a client certificate that is presented to the webhook server.
func (s *server) newWebhookClient() (*http.Client, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	if s.cfg.WebhookServerCert != "" {
		pin, err := loadCertFingerprint(s.cfg.WebhookServerCert)
		if err != nil {
			return nil, fmt.Errorf("webhook server certificate: %w", err)
		}
		// The webhook server certificate is pinned, therefore CA verification
		// is replaced by a fingerprint comparison.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = pinVerifier(pin)
	}
	if s.cfg.WebhookClientCert != "" {
		pair, err := tls.LoadX509KeyPair(s.cfg.WebhookClientCert, s.cfg.WebhookClientKey)
		if err != nil {
			return nil, fmt.Errorf("load webhook client certificate: %w", err)
		}
		tlsCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &pair, nil
		}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   time.Duration(s.cfg.WebhookTimeoutSecs) * time.Second,
	}, nil
}

// deliverWebhook sleeps for the requested delay and then posts the script
// result to the webhook url. Failures are logged, never retried.
func (s *server) deliverWebhook(logger *slog.Logger, rawURL string, delay time.Duration, res *scriptResult) {
	logger = logger.With("script_name", res.ScriptName, "webhook_url", rawURL)

	if delay > 0 {
		logger.Info("webhook delivery delayed", "delay_seconds", int(delay.Seconds()))
		time.Sleep(delay)
	}

	// Fail closed: without a pinned server certificate no webhook call is
	// made at all.
	if s.cfg.WebhookServerCert == "" {
		logger.Error("webhook delivery failed", "reason", "no webhook server certificate pin configured")
		return
	}

	payload, err := json.Marshal(webhookPayload{
		ScriptName: res.ScriptName,
		Stdout:     res.Stdout.String(),
		Stderr:     res.Stderr.String(),
		ReturnCode: res.ExitCode,
	})
	if err != nil {
		logger.Error("webhook delivery failed", "reason", fmt.Sprintf("encode payload: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.WebhookTimeoutSecs)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(payload))
	if err != nil {
		logger.Error("webhook delivery failed", "reason", fmt.Sprintf("build request: %v", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	logger.Info("webhook delivery started")
	resp, err := s.webhookClient.Do(req)
	if err != nil {
		logger.Error("webhook delivery failed", "reason", err.Error())
		return
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		logger.Warn("reading webhook response body", "error", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		logger.Error("webhook delivery failed", "reason", fmt.Sprintf("unexpected status code %d", resp.StatusCode))
		return
	}
	logger.Info("webhook delivery succeeded", "status", resp.StatusCode)
}
