package types

import "time"

// ConnectEvent represents a connect(2) syscall attempt captured by the probe.
type ConnectEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	Comm      string    `json:"comm"`
	Family    uint16    `json:"family"`
	DstAddr   string    `json:"dst_addr"`
	DstPort   uint16    `json:"dst_port"`
}

// Report is the final scan output.
type Report struct {
	Package     string         `json:"package"`
	Version     string         `json:"version,omitempty"`
	Timestamp   time.Time      `json:"timestamp"`
	Verdict     string         `json:"verdict"`
	Events      []ConnectEvent `json:"events"`
	ProbeMethod string         `json:"probe_method"`
}

const (
	VerdictClean      = "clean"
	VerdictSuspicious = "suspicious"
)
