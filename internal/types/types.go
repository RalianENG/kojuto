package types

import "time"

// Syscall event types.
const (
	EventConnect  = "connect"
	EventSendto   = "sendto"
	EventSendmsg  = "sendmsg"
	EventSendmmsg = "sendmmsg"
	EventBind     = "bind"
	EventListen   = "listen"
	EventAccept   = "accept"
	EventExecve   = "execve"
	EventOpenat   = "openat"
	EventRename   = "rename"
)

// SyscallEvent represents a suspicious syscall captured by the probe.
type SyscallEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Comm      string    `json:"comm"`
	DstAddr   string    `json:"dst_addr,omitempty"`
	Cmdline   string    `json:"cmdline,omitempty"`
	FilePath  string    `json:"file_path,omitempty"`
	OpenFlags string    `json:"open_flags,omitempty"`
	SrcPath   string    `json:"src_path,omitempty"`
	DstPath   string    `json:"dst_path,omitempty"`
	Syscall   string    `json:"syscall"`
	PID       uint32    `json:"pid"`
	Family    uint16    `json:"family,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
}

// StaticFinding represents a suspicious pattern found by static analysis.
type StaticFinding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Snippet string `json:"snippet"`
}

// Report is the final scan output.
type Report struct {
	Timestamp      time.Time       `json:"timestamp"`
	Package        string          `json:"package"`
	Version        string          `json:"version,omitempty"`
	Ecosystem      string          `json:"ecosystem"`
	Verdict        string          `json:"verdict"`
	ProbeMethod    string          `json:"probe_method"`
	Events         []SyscallEvent  `json:"events"`
	StaticFindings []StaticFinding `json:"static_findings,omitempty"`
	LostSamples    uint64          `json:"lost_samples,omitempty"`
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
