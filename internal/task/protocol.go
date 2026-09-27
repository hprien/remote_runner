package task

import "regexp"

// Request is the single JSON line the web daemon sends to the remote-runner-execd.
type Request struct {
	// TransactionID is assigned by the web daemon per request. The
	// remote-runner-execd adopts it so both journals can be correlated.
	TransactionID  string `json:"transaction_id"`
	ScriptName     string `json:"script_name"`
	ScriptChecksum string `json:"script_checksum"`
	TimeoutSecs    int    `json:"timeout_seconds"`
}

// transactionIDPattern matches exactly the shape produced by NewTransactionID.
// Anything else is not adopted, so a crafted id cannot inject into the log.
var transactionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidTransactionID reports whether id looks like a transaction id generated
// by NewTransactionID.
func ValidTransactionID(id string) bool {
	return transactionIDPattern.MatchString(id)
}

// Event types sent from the remote-runner-execd to the web daemon as NDJSON lines.
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

// Event is one protocol message from the remote-runner-execd to the web daemon. Every
// connection ends with exactly one terminal event (exit or rejected).
type Event struct {
	Type     string `json:"type"` // started | stdout | stderr | exit | rejected
	Txt      string `json:"txt,omitempty"`
	Code     *int   `json:"code,omitempty"` // only set for exit
	TimedOut bool   `json:"timed_out,omitempty"`
	Reason   string `json:"reason,omitempty"` // only set for rejected
}
