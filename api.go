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
	"sync"
	"time"

	"remote_runner/internal/task"
)

// maxRequestBodySize bounds the accepted request body to prevent abuse.
const maxRequestBodySize = 16 << 10

type server struct {
	cfg           *config
	clientPin     [32]byte
	logger        *slog.Logger
	slots         chan struct{}
	webhookClient *http.Client
}

// scriptResult is the result of a finished script, filled by the task client
// while the task helper streams the output.
type scriptResult = task.Result

// streamFunc is called with every output chunk a script produces. It is nil
// when the client did not request streaming.
type streamFunc = task.StreamFunc

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
		logger := requestLogger(s.logger, task.NewTransactionID(), r.RemoteAddr)

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

// handleRun validates the request, asks the task helper to run the script and
// streams its output if requested. Response objects are written as newline
// delimited JSON (NDJSON).
func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	logger := requestLogger(s.logger, task.NewTransactionID(), r.RemoteAddr)

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

	// Reserve a concurrency slot without blocking; a full server denies the
	// request instead of queueing it. The slot is owned by this handler until
	// the script started; the defer below releases it on every early return
	// and on panics, so it can never leak. Once the script started, the
	// background goroutine owns the slot and releases it when it finished.
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
	started := false
	defer func() {
		if !started {
			<-s.slots
		}
	}()

	client, err := dialTaskClient(s.cfg.TaskSocket)
	if err != nil {
		s.internalError(logger, w, err)
		return
	}
	first, err := client.start(task.Request{
		ScriptName:     req.ScriptName,
		ScriptChecksum: req.ScriptChecksum,
		TimeoutSecs:    *req.ScriptTimeoutSecs,
	})
	if err != nil {
		client.close()
		s.internalError(logger, w, err)
		return
	}
	if first.Type == task.EventRejected {
		client.close()
		if first.Reason == task.ReasonBusy {
			logger.Warn("security event: too many concurrent scripts",
				"event", "concurrency_limit_reached",
				"script_name", req.ScriptName)
			s.respond(logger, w, http.StatusOK, statusResponse{
				Type:       "denied",
				ScriptName: req.ScriptName,
				Message:    "too many concurrent scripts",
			})
			return
		}
		s.badRequest(logger, w, first.Reason)
		return
	}
	if first.Type != task.EventStarted {
		client.close()
		s.internalError(logger, w, fmt.Errorf("unexpected first task event %q", first.Type))
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
	// ends right here and the result is only delivered via webhook. The
	// goroutine owns the concurrency slot from here on.
	started = true
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { <-s.slots }()
		defer client.close()

		res := client.stream(logger, req.ScriptName,
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
	if err := task.ValidateName(req.ScriptName); err != nil {
		return err
	}
	if req.ScriptChecksum == "" {
		return errors.New("script_checksum is required")
	}
	// The checksum format itself is validated by the task helper, which is
	// the only component that reads the script file.
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

// internalError responds with a plain "internal server error", e.g. when the
// task helper is unreachable. The detailed reason is only written to the log.
func (s *server) internalError(logger *slog.Logger, w http.ResponseWriter, err error) {
	logger.Error("internal error", "error", err.Error())
	http.Error(w, "internal server error", http.StatusInternalServerError)
	logger.Info("response", "status", http.StatusInternalServerError, "response_message", "internal server error")
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
