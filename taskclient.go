package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"time"

	"remote_runner/internal/task"
)

// taskStreamSlack extends the read deadline of a task connection beyond the
// requested timeout. The helper enforces the timeout itself; the deadline only
// guards against a helper that crashed without sending the exit event.
const taskStreamSlack = time.Minute

// taskClient is one connection to the task helper socket.
type taskClient struct {
	conn *net.UnixConn
	dec  *json.Decoder
}

// dialTaskClient connects to the task helper socket.
func dialTaskClient(path string) (*taskClient, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("dial task helper socket: %w", err)
	}
	return &taskClient{conn: conn.(*net.UnixConn), dec: json.NewDecoder(conn)}, nil
}

// start sends the request line, half-closes the write side and waits for the
// helper's verdict: a started event when the script is being executed or a
// rejected event otherwise.
func (c *taskClient) start(req task.Request) (task.Event, error) {
	line, err := json.Marshal(req)
	if err != nil {
		return task.Event{}, fmt.Errorf("encode task request: %w", err)
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return task.Event{}, err
	}
	if _, err := c.conn.Write(append(line, '\n')); err != nil {
		return task.Event{}, fmt.Errorf("write task request: %w", err)
	}
	if err := c.conn.CloseWrite(); err != nil {
		return task.Event{}, fmt.Errorf("close write side: %w", err)
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return task.Event{}, err
	}
	var ev task.Event
	if err := c.dec.Decode(&ev); err != nil {
		return task.Event{}, fmt.Errorf("read first task event: %w", err)
	}
	return ev, nil
}

// stream reads events until the terminal exit event, forwards output chunks
// to emit and collects the result for the webhook.
func (c *taskClient) stream(logger *slog.Logger, scriptName string, timeout time.Duration, emit streamFunc) *scriptResult {
	res := &scriptResult{ScriptName: scriptName, ExitCode: -1}
	if err := c.conn.SetReadDeadline(time.Now().Add(timeout + taskStreamSlack)); err != nil {
		logger.Error("task stream failed", "error", err.Error())
		return res
	}
	for {
		var ev task.Event
		if err := c.dec.Decode(&ev); err != nil {
			logger.Error("task stream failed", "error", err.Error())
			return res
		}
		switch ev.Type {
		case task.EventStdout, task.EventStderr:
			if ev.Type == task.EventStdout {
				res.Stdout.WriteString(ev.Txt)
			} else {
				res.Stderr.WriteString(ev.Txt)
			}
			if emit != nil {
				emit(ev.Type, ev.Txt)
			}
		case task.EventExit:
			if ev.Code != nil {
				res.ExitCode = *ev.Code
			}
			res.TimedOut = ev.TimedOut
			return res
		}
	}
}

// close terminates the connection to the task helper.
func (c *taskClient) close() {
	c.conn.Close()
}
