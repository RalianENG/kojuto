package types

import "time"

// Syscall event types.
const (
	EventConnect = "connect"
	EventSendto  = "sendto"
	EventSendmsg = "sendmsg"
	EventExecve  = "execve"
)

// SyscallEvent represents a suspicious syscall captured by the probe.
type SyscallEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Comm      string    `json:"comm"`
	DstAddr   string    `json:"dst_addr,omitempty"`
	Cmdline   string    `json:"cmdline,omitempty"`
	Syscall   string    `json:"syscall"`
	PID       uint32    `json:"pid"`
	Family    uint16    `json:"family,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
}

// Report is the final scan output.
type Report struct {
	Timestamp   time.Time      `json:"timestamp"`
	Package     string         `json:"package"`
	Version     string         `json:"version,omitempty"`
	Ecosystem   string         `json:"ecosystem"`
	Verdict     string         `json:"verdict"`
	ProbeMethod string         `json:"probe_method"`
	Events      []SyscallEvent `json:"events"`
	LostSamples uint64         `json:"lost_samples,omitempty"`
}

// Verdict constants.
const (
	VerdictClean        = "clean"
	VerdictSuspicious   = "suspicious"
	VerdictInconclusive = "inconclusive"
)

// Ecosystem constants.
const (
	EcosystemPyPI = "pypi"
	EcosystemNpm  = "npm"
)
