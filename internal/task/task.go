package task

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
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

// scriptNamePattern only allows plain names: no separators, no leading dot and
// no "..". This makes path traversal via script_name impossible.
var (
	scriptNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	checksumPattern   = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

// ValidateName reports whether script_name is present and syntactically valid.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("script_name is required")
	}
	if !scriptNamePattern.MatchString(name) {
		return errors.New("script_name contains invalid characters")
	}
	return nil
}

// ValidChecksumFormat reports whether checksum looks like a sha256 hex digest.
func ValidChecksumFormat(checksum string) bool {
	return checksumPattern.MatchString(checksum)
}

// ResolveScript returns the path of the executable for name inside scriptsDir.
// The script must be an executable regular file, no symlinks are accepted.
func ResolveScript(scriptsDir, name string) (string, error) {
	scriptPath := filepath.Join(scriptsDir, name, name)
	info, err := os.Lstat(scriptPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("script %q is not available as executable", name)
	}
	return scriptPath, nil
}

// FileChecksum returns the sha256 hex checksum of the file at path. It is
// compared against script_checksum to ensure the executable was not changed.
func FileChecksum(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read script %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// StreamFunc is called with every output chunk a script produces. It is nil
// when the caller did not request streaming.
type StreamFunc func(kind, txt string)

// Result holds everything needed after a script finished. Stdout and Stderr
// are filled by the output writers while the script runs.
type Result struct {
	ScriptName string
	Stdout     bytes.Buffer
	Stderr     bytes.Buffer
	ExitCode   int
	TimedOut   bool
}

// ExecuteScript runs the executable at scriptPath, collects its output and
// forwards every chunk to emit (when not nil). The script runs in its own
// process group. It is terminated when it does not finish within timeout or
// when ctx is canceled, e.g. when the client of the task helper disappears.
func ExecuteScript(ctx context.Context, logger *slog.Logger, scriptPath, scriptName string, timeout time.Duration, emit StreamFunc) *Result {
	logger = logger.With("script_name", scriptName)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := &Result{ScriptName: scriptName, ExitCode: -1}
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
// written chunk to the caller via emit, if streaming was requested.
type outputWriter struct {
	kind string
	buf  *bytes.Buffer
	emit StreamFunc
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
