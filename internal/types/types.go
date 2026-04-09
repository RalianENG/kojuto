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
	EventPtrace   = "ptrace"
	EventMmap     = "mmap"
	EventMprotect = "mprotect"
	EventUnlink   = "unlink"
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
	DNSQuery  string    `json:"dns_query,omitempty"`
	MemProt   string    `json:"mem_prot,omitempty"`   // mmap/mprotect protection flags (e.g. "PROT_READ|PROT_WRITE|PROT_EXEC")
	MemFlags  string    `json:"mem_flags,omitempty"`  // mmap flags (e.g. "MAP_PRIVATE|MAP_ANONYMOUS")
	Syscall   string    `json:"syscall"`
	Category  string    `json:"category,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Phase     string    `json:"phase,omitempty"`
	PID       uint32    `json:"pid"`
	Family    uint16    `json:"family,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
}

// Attack categories.
const (
	CategoryC2               = "c2_communication"
	CategoryDataExfil        = "data_exfiltration"
	CategoryCredentialAccess = "credential_access"
	CategoryCodeExecution    = "code_execution"
	CategoryBinaryHijack     = "binary_hijacking"
	CategoryBackdoor         = "backdoor"
	CategoryPersistence      = "persistence"
	CategoryDNSTunnel        = "dns_tunneling"
	CategoryEvasion          = "evasion"
	CategoryMemExec          = "memory_execution"
	CategoryAntiForensics    = "anti_forensics"
)

// Scan phases.
const (
	PhaseInstall = "install"
	PhaseImport  = "import"
)

// StaticFinding represents a suspicious pattern found by static analysis.
type StaticFinding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Snippet string `json:"snippet"`
}

// ReportSummary provides a human-readable overview of the scan findings.
type ReportSummary struct {
	RiskLevel   string   `json:"risk_level"`
	Categories  []string `json:"categories,omitempty"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation,omitempty"`
}

// Report is the final scan output.
type Report struct {
	Timestamp      time.Time       `json:"timestamp"`
	Package        string          `json:"package"`
	Version        string          `json:"version,omitempty"`
	Ecosystem      string          `json:"ecosystem"`
	Verdict        string          `json:"verdict"`
	ProbeMethod    string          `json:"probe_method"`
	Summary        *ReportSummary  `json:"summary,omitempty"`
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
