package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// config holds all helper settings. Everything is configured via command line
// flags to keep the codebase minimal.
type config struct {
	ScriptsDir     string
	AllowedUser    string
	MaxConcurrent  int
	MaxTimeoutSecs int
}

func parseFlags() *config {
	cfg := &config{}
	flag.StringVar(&cfg.ScriptsDir, "scripts-dir", "/var/lib/remote-runner/scripts", "root owned directory containing one folder per script")
	flag.StringVar(&cfg.AllowedUser, "allowed-user", "remote-runner", "the only user allowed to connect to the socket")
	flag.IntVar(&cfg.MaxConcurrent, "max-concurrent", 4, "maximum number of scripts running simultaneously")
	flag.IntVar(&cfg.MaxTimeoutSecs, "max-script-timeout-seconds", 3600, "maximum allowed timeout per request")
	flag.Parse()
	return cfg
}

// validate rejects invalid flags as early as possible.
func (c *config) validate() error {
	if c.MaxConcurrent < 1 {
		return errors.New("-max-concurrent must be at least 1")
	}
	if c.MaxTimeoutSecs < 1 {
		return errors.New("-max-script-timeout-seconds must be at least 1")
	}
	info, err := os.Stat(c.ScriptsDir)
	if err != nil {
		return fmt.Errorf("-scripts-dir: %w", err)
	}
	if !info.IsDir() {
		return errors.New("-scripts-dir is not a directory")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		slog.Error("task-helper terminated", "error", err)
		os.Exit(1)
	}
}

// run configures the helper and serves the socket until it stops.
func run() error {
	cfg := parseFlags()
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	allowedUser, err := user.Lookup(cfg.AllowedUser)
	if err != nil {
		return fmt.Errorf("lookup allowed user: %w", err)
	}
	allowedUID, err := strconv.ParseUint(allowedUser.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("parse uid of allowed user: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	l, err := systemdListener()
	if err != nil {
		return err
	}

	slots := make(chan struct{}, cfg.MaxConcurrent)
	logger.Info("task-helper listening",
		"scripts_dir", cfg.ScriptsDir,
		"allowed_user", cfg.AllowedUser,
		"max_concurrent", cfg.MaxConcurrent)
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EINTR) {
				logger.Warn("accept failed", "error", err.Error())
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			continue
		}
		go handleConn(logger, cfg, uint32(allowedUID), slots, unixConn)
	}
}

// systemdListener returns the listening socket passed by systemd via socket
// activation (LISTEN_FDS). It fails when the helper was not started by
// systemd, so the socket file and its permissions are always controlled by the
// socket unit and never by this process.
func systemdListener() (net.Listener, error) {
	pidStr, fdsStr := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	if pidStr == "" || fdsStr == "" {
		return nil, errors.New("not started via systemd socket activation (LISTEN_PID/LISTEN_FDS missing)")
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid != os.Getpid() {
		return nil, errors.New("LISTEN_PID does not match this process")
	}
	n, err := strconv.Atoi(fdsStr)
	if err != nil || n < 1 {
		return nil, fmt.Errorf("invalid LISTEN_FDS %q", fdsStr)
	}
	f := os.NewFile(uintptr(3), "systemd listener")
	l, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("use systemd listener: %w", err)
	}
	f.Close()
	return l, nil
}
