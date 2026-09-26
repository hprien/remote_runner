package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"remote_runner/internal/task"
)

// maxRequestSize bounds the request line accepted from the web daemon.
const maxRequestSize = 1 << 10

// requestReadTimeout bounds how long the helper waits for the request line.
const requestReadTimeout = 10 * time.Second

// handleConn serves one connection from the web daemon: it authorizes the
// peer, validates the request and checksum, runs the script as root and
// streams its output back as NDJSON events.
func handleConn(logger *slog.Logger, cfg *config, allowedUID uint32, slots chan struct{}, conn *net.UnixConn) {
	defer conn.Close()
	logger = logger.With("transaction_id", task.NewTransactionID())

	peerUID, err := peerUID(conn)
	if err != nil {
		logger.Warn("security event: peer credentials unavailable", "event", "peer_creds_unavailable", "error", err.Error())
		return
	}
	logger = logger.With("peer_uid", peerUID)
	if peerUID != allowedUID {
		logger.Warn("security event: connection from unauthorized user", "event", "peer_not_allowed")
		return
	}

	reject := func(reason string) {
		logger.Warn("security event: request rejected", "event", "task_rejected", "reason", reason)
		if err := writeEvent(conn, task.Event{Type: task.EventRejected, Reason: reason}); err != nil {
			logger.Error("write rejected event", "error", err.Error())
		}
	}

	req, err := readRequest(conn)
	if err != nil {
		logger.Warn("security event: request rejected", "event", "task_rejected", "reason", "unreadable request")
		if err := writeEvent(conn, task.Event{Type: task.EventRejected, Reason: "unreadable request"}); err != nil {
			logger.Error("write rejected event", "error", err.Error())
		}
		return
	}
	logger.Info("request received",
		"script_name", req.ScriptName,
		"timeout_seconds", req.TimeoutSecs)

	if err := task.ValidateName(req.ScriptName); err != nil {
		reject(err.Error())
		return
	}
	if req.ScriptChecksum == "" || !task.ValidChecksumFormat(req.ScriptChecksum) {
		reject("script_checksum is not a valid sha256 hex checksum")
		return
	}
	if req.TimeoutSecs < 1 {
		reject("script_timeout_seconds must be at least 1")
		return
	}

	scriptPath, err := task.ResolveScript(cfg.ScriptsDir, req.ScriptName)
	if err != nil {
		reject(err.Error())
		return
	}
	sum, err := task.FileChecksum(scriptPath)
	if err != nil {
		reject(err.Error())
		return
	}
	if !strings.EqualFold(sum, req.ScriptChecksum) {
		reject("script checksum mismatch")
		return
	}

	// Reserve a concurrency slot without blocking; a full helper rejects the
	// request instead of queueing it.
	select {
	case slots <- struct{}{}:
	default:
		logger.Warn("security event: too many concurrent scripts",
			"event", "concurrency_limit_reached",
			"max_concurrent", cfg.MaxConcurrent)
		if err := writeEvent(conn, task.Event{Type: task.EventRejected, Reason: task.ReasonBusy}); err != nil {
			logger.Error("write rejected event", "error", err.Error())
		}
		return
	}
	defer func() { <-slots }()

	if err := writeEvent(conn, task.Event{Type: task.EventStarted}); err != nil {
		logger.Error("write started event", "error", err.Error())
		return
	}

	// When the web daemon disappears mid-run, writing the next output chunk
	// fails and cancels the context, which terminates the script's process
	// group. The same happens when the timeout is exceeded.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	emit := func(kind, txt string) {
		mu.Lock()
		defer mu.Unlock()
		if err := writeEvent(conn, task.Event{Type: kind, Txt: txt}); err != nil {
			cancel()
		}
	}

	timeout := time.Duration(min(req.TimeoutSecs, cfg.MaxTimeoutSecs)) * time.Second
	res := task.ExecuteScript(ctx, logger, scriptPath, req.ScriptName, timeout, emit)

	mu.Lock()
	defer mu.Unlock()
	code := res.ExitCode
	if err := writeEvent(conn, task.Event{Type: task.EventExit, Code: &code, TimedOut: res.TimedOut}); err != nil {
		logger.Error("write exit event", "error", err.Error())
	}
}

// readRequest reads the single request line. The peer is the trusted web
// daemon, nevertheless the line is size limited and strictly decoded.
func readRequest(conn *net.UnixConn) (task.Request, error) {
	if err := conn.SetReadDeadline(time.Now().Add(requestReadTimeout)); err != nil {
		return task.Request{}, err
	}
	defer conn.SetReadDeadline(time.Time{})
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequestSize+1)).ReadString('\n')
	if err != nil {
		return task.Request{}, fmt.Errorf("read request line: %w", err)
	}
	if len(line) > maxRequestSize {
		return task.Request{}, errors.New("request line too large")
	}
	var req task.Request
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &req); err != nil {
		return task.Request{}, fmt.Errorf("decode request: %w", err)
	}
	return req, nil
}

// writeEvent writes one protocol message as a single NDJSON line.
func writeEvent(conn net.Conn, ev task.Event) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

// peerUID returns the uid of the connecting process, verified by the kernel
// via SO_PEERCRED. This is defense in depth on top of the socket permissions.
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("get raw connection: %w", err)
	}
	var uid uint32
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			sockErr = err
			return
		}
		uid = ucred.Uid
	}); err != nil {
		return 0, fmt.Errorf("getsockopt SO_PEERCRED: %w", err)
	}
	if sockErr != nil {
		return 0, fmt.Errorf("getsockopt SO_PEERCRED: %w", sockErr)
	}
	return uid, nil
}
