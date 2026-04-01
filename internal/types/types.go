package types

import "time"

// ConnectEvent represents a connect(2) syscall attempt captured by the probe.
type ConnectEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Comm      string    `json:"comm"`
	DstAddr   string    `json:"dst_addr"`
	PID       uint32    `json:"pid"`
	Family    uint16    `json:"family"`
	DstPort   uint16    `json:"dst_port"`
}

// Report is the final scan output.
type Report struct {
	Timestamp   time.Time      `json:"timestamp"`
	Package     string         `json:"package"`
	Version     string         `json:"version,omitempty"`
	Verdict     string         `json:"verdict"`
	ProbeMethod string         `json:"probe_method"`
	Events      []ConnectEvent `json:"events"`
	LostSamples uint64         `json:"lost_samples,omitempty"`
}

const (
	VerdictClean        = "clean"
	VerdictSuspicious   = "suspicious"
	VerdictInconclusive = "inconclusive"
)
