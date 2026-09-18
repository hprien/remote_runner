package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// streamFunc is called with every output chunk a script produces. It is nil
// when the client did not request streaming.
type streamFunc func(kind, txt string)

// scriptResult holds everything needed for the webhook after the script
// finished. Stdout and Stderr are filled by the output writers while the
// script runs.
type scriptResult struct {
	ScriptName string
	Stdout     bytes.Buffer
	Stderr     bytes.Buffer
	ExitCode   int
	TimedOut   bool
}

// executeScript runs the executable at scriptPath, collects its output and
// optionally streams it to the client. The script is terminated when it does
// not finish within timeout.
func executeScript(logger *slog.Logger, scriptPath, scriptName string, timeout time.Duration, emit streamFunc) *scriptResult {
	logger = logger.With("script_name", scriptName)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	res := &scriptResult{ScriptName: scriptName, ExitCode: -1}
	cmd := exec.CommandContext(ctx, scriptPath)
	// The script runs in its own process group. When it exceeds the timeout
	// the whole group is terminated, otherwise children holding the output
	// pipes open would delay the end of the script and keep the server busy.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}
	cmd.Stdout = &outputWriter{kind: "stdout", buf: &res.Stdout, emit: emit}
	cmd.Stderr = &outputWriter{kind: "stderr", buf: &res.Stderr, emit: emit}

	logger.Info("script execution started", "timeout_seconds", int(timeout.Seconds()))
	runErr := cmd.Run()

	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	res.TimedOut = ctx.Err() == context.DeadlineExceeded

	switch {
	case res.TimedOut:
		// The Cancel hook above already terminated the process group.
		logger.Warn("script execution aborted",
			"reason", "timeout exceeded",
			"return_code", res.ExitCode,
			"stdout_bytes", res.Stdout.Len(),
			"stderr_bytes", res.Stderr.Len())
	case runErr != nil:
		logger.Error("script execution failed",
			"error", runErr.Error(),
			"return_code", res.ExitCode,
			"stdout_bytes", res.Stdout.Len(),
			"stderr_bytes", res.Stderr.Len())
	default:
		logger.Info("script execution finished",
			"return_code", res.ExitCode,
			"stdout_bytes", res.Stdout.Len(),
			"stderr_bytes", res.Stderr.Len())
	}
	return res
}

// outputWriter collects one output stream of a script and forwards every
// written chunk to the client via emit, if streaming was requested.
type outputWriter struct {
	kind string
	buf  *bytes.Buffer
	emit streamFunc
}

func (ow *outputWriter) Write(p []byte) (int, error) {
	n, err := ow.buf.Write(p)
	if err != nil {
		return n, err
	}
	if ow.emit != nil {
		ow.emit(ow.kind, string(p))
	}
	return n, nil
}

// fileChecksum returns the sha256 hex checksum of the file at path. It is
// compared against script_checksum to ensure the executable was not changed.
func fileChecksum(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read script %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
