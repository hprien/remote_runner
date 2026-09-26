package task

// Request is the single JSON line the web daemon sends to the task helper.
type Request struct {
	ScriptName     string `json:"script_name"`
	ScriptChecksum string `json:"script_checksum"`
	TimeoutSecs    int    `json:"timeout_seconds"`
}

// Event types sent from the task helper to the web daemon as NDJSON lines.
const (
	EventStarted  = "started"
	EventStdout   = "stdout"
	EventStderr   = "stderr"
	EventExit     = "exit"
	EventRejected = "rejected"
)

// ReasonBusy is the rejection reason for a helper whose concurrency slots are
// exhausted; the web daemon maps it to its "denied" response.
const ReasonBusy = "busy"

// Event is one protocol message from the task helper to the web daemon. Every
// connection ends with exactly one terminal event (exit or rejected).
type Event struct {
	Type     string `json:"type"` // started | stdout | stderr | exit | rejected
	Txt      string `json:"txt,omitempty"`
	Code     *int   `json:"code,omitempty"` // only set for exit
	TimedOut bool   `json:"timed_out,omitempty"`
	Reason   string `json:"reason,omitempty"` // only set for rejected
}
