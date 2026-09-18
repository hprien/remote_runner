package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// maxRequestBodySize bounds the accepted request body to prevent abuse.
const maxRequestBodySize = 16 << 10

// scriptNamePattern only allows plain names: no separators, no leading dot and
// no "..". This makes path traversal via script_name impossible.
var (
	scriptNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	checksumPattern   = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

type server struct {
	cfg           *config
	clientPin     [32]byte
	logger        *slog.Logger
	slots         chan struct{}
	webhookClient *http.Client
}

// runRequest is the API request body. Pointers are used to distinguish missing
// from zero valued fields for required input validation.
type runRequest struct {
	ScriptName         string `json:"script_name"`
	ScriptChecksum     string `json:"script_checksum"`
	StreamStdoutStderr *bool  `json:"stream_script_stdout_stderr"`
	WebhookURL         string `json:"script_response_webhook_url"`
	WebhookDelaySecs   *int   `json:"webhook_delay_seconds"`
	ScriptTimeoutSecs  *int   `json:"script_timeout_seconds"`
}

type statusResponse struct {
	Type       string `json:"type"` // "accepted" | "denied"
	ScriptName string `json:"script_name"`
	Message    string `json:"message"`
}

type streamResponse struct {
	Type string `json:"type"` // "stdout" | "stderr"
	Txt  string `json:"txt"`
}

// authenticate rejects every request that was not made with the pinned client
// certificate. It is the only authentication mechanism; no CA is involved.
func (s *server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := requestLogger(s.logger, newTransactionID(), r.RemoteAddr)

		var peerCerts []*x509.Certificate
		if r.TLS != nil {
			peerCerts = r.TLS.PeerCertificates
		}
		if !pinnedPeer(peerCerts, s.clientPin) {
			logger.Warn("security event: client certificate not pinned", "event", "client_cert_not_pinned")
			http.Error(w, "forbidden", http.StatusForbidden)
			logger.Info("response", "status", http.StatusForbidden, "response_message", "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleRun validates the request, starts the script and streams its output if
// requested. Response objects are written as newline delimited JSON (NDJSON).
func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	logger := requestLogger(s.logger, newTransactionID(), r.RemoteAddr)

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodySize))
	if err != nil {
		s.badRequest(logger, w, fmt.Sprintf("read request body: %v", err))
		return
	}

	req := new(runRequest)
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(req); err != nil {
		s.badRequest(logger, w, fmt.Sprintf("decode request body: %v", err))
		return
	}
	if dec.More() {
		s.badRequest(logger, w, "trailing data in request body")
		return
	}

	reqMessage, err := json.Marshal(req)
	if err != nil {
		s.badRequest(logger, w, fmt.Sprintf("encode request message: %v", err))
		return
	}
	logger.Info("request received",
		"method", r.Method,
		"path", r.URL.Path,
		"request_message", string(reqMessage))

	if err := validateRequest(s.cfg, req); err != nil {
		s.badRequest(logger, w, err.Error())
		return
	}

	scriptPath := filepath.Join(s.cfg.ScriptsDir, req.ScriptName, req.ScriptName)
	info, err := os.Lstat(scriptPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		s.badRequest(logger, w, fmt.Sprintf("script %q is not available as executable", req.ScriptName))
		return
	}
	sum, err := fileChecksum(scriptPath)
	if err != nil {
		s.badRequest(logger, w, err.Error())
		return
	}
	if !strings.EqualFold(sum, req.ScriptChecksum) {
		logger.Warn("security event: script checksum mismatch",
			"event", "script_checksum_mismatch",
			"script_name", req.ScriptName)
		s.badRequest(logger, w, "script checksum mismatch")
		return
	}

	// Reserve a concurrency slot without blocking; a full server denies the
	// request instead of queueing it.
	select {
	case s.slots <- struct{}{}:
	default:
		logger.Warn("security event: too many concurrent scripts",
			"event", "concurrency_limit_reached",
			"script_name", req.ScriptName,
			"max_concurrent", s.cfg.MaxConcurrent)
		s.respond(logger, w, http.StatusOK, statusResponse{
			Type:       "denied",
			ScriptName: req.ScriptName,
			Message:    "too many concurrent scripts",
		})
		return
	}

	s.respond(logger, w, http.StatusOK, statusResponse{
		Type:       "accepted",
		ScriptName: req.ScriptName,
		Message:    "Script execution started",
	})

	// emit streams output chunks to the client as NDJSON lines. It is nil when
	// the client did not request streaming.
	var emit streamFunc
	if req.StreamStdoutStderr != nil && *req.StreamStdoutStderr {
		flusher, canFlush := w.(http.Flusher)
		var mu sync.Mutex
		emit = func(kind, txt string) {
			mu.Lock()
			defer mu.Unlock()
			s.respond(logger, w, 0, streamResponse{Type: kind, Txt: txt})
			if canFlush {
				flusher.Flush()
			}
		}
	}

	// The script runs in the background. When streaming is requested the
	// handler stays open until the script finished, otherwise the response
	// ends right here and the result is only delivered via webhook.
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { <-s.slots }()

		res := executeScript(logger, scriptPath, req.ScriptName,
			time.Duration(*req.ScriptTimeoutSecs)*time.Second, emit)

		if req.WebhookURL != "" {
			delay := time.Duration(0)
			if req.WebhookDelaySecs != nil {
				delay = time.Duration(*req.WebhookDelaySecs) * time.Second
			}
			go s.deliverWebhook(logger, req.WebhookURL, delay, res)
		}
	}()

	if emit != nil {
		<-done
	}
}

// validateRequest checks all request fields against the configured limits and
// syntactic rules. It returns a descriptive error for the log; the client only
// ever receives a plain "bad request".
func validateRequest(cfg *config, req *runRequest) error {
	if req.ScriptName == "" {
		return errors.New("script_name is required")
	}
	if !scriptNamePattern.MatchString(req.ScriptName) {
		return errors.New("script_name contains invalid characters")
	}
	if req.ScriptChecksum == "" {
		return errors.New("script_checksum is required")
	}
	if !checksumPattern.MatchString(req.ScriptChecksum) {
		return errors.New("script_checksum is not a valid sha256 hex checksum")
	}
	if req.StreamStdoutStderr == nil {
		return errors.New("stream_script_stdout_stderr is required")
	}
	if req.ScriptTimeoutSecs == nil {
		return errors.New("script_timeout_seconds is required")
	}
	if *req.ScriptTimeoutSecs < 1 || *req.ScriptTimeoutSecs > cfg.MaxScriptTimeoutSecs {
		return fmt.Errorf("script_timeout_seconds must be between 1 and %d", cfg.MaxScriptTimeoutSecs)
	}
	if req.WebhookDelaySecs != nil && req.WebhookURL == "" {
		return errors.New("webhook_delay_seconds requires script_response_webhook_url")
	}
	if req.WebhookDelaySecs != nil && (*req.WebhookDelaySecs < 0 || *req.WebhookDelaySecs > cfg.MaxWebhookDelaySecs) {
		return fmt.Errorf("webhook_delay_seconds must be between 0 and %d", cfg.MaxWebhookDelaySecs)
	}
	if req.WebhookURL != "" {
		u, err := url.Parse(req.WebhookURL)
		if err != nil {
			return fmt.Errorf("script_response_webhook_url is not a valid url: %w", err)
		}
		if u.Scheme != "https" || u.Host == "" {
			return errors.New("script_response_webhook_url must be an https url")
		}
	}
	return nil
}

// badRequest responds with a plain "bad request" without any details. The
// detailed reason is only written to the log.
func (s *server) badRequest(logger *slog.Logger, w http.ResponseWriter, reason string) {
	logger.Warn("security event: request rejected", "event", "bad_request", "reason", reason)
	http.Error(w, "bad request", http.StatusBadRequest)
	logger.Info("response", "status", http.StatusBadRequest, "response_message", "bad request")
}

// respond writes one response object as a single NDJSON line and logs it.
// A status <= 0 means the response header was already written (streaming).
func (s *server) respond(logger *slog.Logger, w http.ResponseWriter, status int, v any) {
	line, err := json.Marshal(v)
	if err != nil {
		logger.Error("encode response", "error", err)
		if status > 0 {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}
	if status > 0 {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(status)
	}
	if _, err := w.Write(append(line, '\n')); err != nil {
		logger.Warn("write response", "error", err)
	}
	if status > 0 {
		logger.Info("response", "status", status, "response_message", string(line))
	} else {
		logger.Info("response", "response_message", string(line))
	}
}
