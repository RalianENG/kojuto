package types

import "time"

// Syscall event types.
const (
	EventConnect     = "connect"
	EventSendto      = "sendto"
	EventSendmsg     = "sendmsg"
	EventSendmmsg    = "sendmmsg"
	EventBind        = "bind"
	EventListen      = "listen"
	EventAccept      = "accept"
	EventExecve      = "execve"
	EventOpenat      = "openat"
	EventRename      = "rename"
	EventPtrace      = "ptrace"
	EventMmap        = "mmap"
	EventMprotect    = "mprotect"
	EventUnlink      = "unlink"
	EventDynamicExec = "dynamic_exec"
	// EventClone records a clone/clone3/fork/vfork call. The parent
	// PID lives in PID; the new child PID lives in ChildPID. The
	// analyzer's PID-attribution pre-pass uses these to propagate
	// the parent's execve comm to children that never call execve
	// (V8 worker threads, fork-without-exec helpers), which is the
	// missing link that lets the V8 JIT filter cover thread-PIDs.
	EventClone = "clone"
)

// SyscallEvent represents a suspicious syscall captured by the probe.
type SyscallEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Comm        string    `json:"comm"`
	DstAddr     string    `json:"dst_addr,omitempty"`
	Cmdline     string    `json:"cmdline,omitempty"`
	FilePath    string    `json:"file_path,omitempty"`
	OpenFlags   string    `json:"open_flags,omitempty"`
	SrcPath     string    `json:"src_path,omitempty"`
	DstPath     string    `json:"dst_path,omitempty"`
	DNSQuery    string    `json:"dns_query,omitempty"`
	MemProt     string    `json:"mem_prot,omitempty"`     // mmap/mprotect protection flags (e.g. "PROT_READ|PROT_WRITE|PROT_EXEC")
	MemFlags    string    `json:"mem_flags,omitempty"`    // mmap flags (e.g. "MAP_PRIVATE|MAP_ANONYMOUS")
	AuditEvent  string    `json:"audit_event,omitempty"`  // audit hook event (e.g. "compile", "eval", "Function")
	CodeSnippet string    `json:"code_snippet,omitempty"` // truncated source from audit hook
	Syscall     string    `json:"syscall"`
	Category    string    `json:"category,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Phase       string    `json:"phase,omitempty"`
	PID         uint32    `json:"pid"`
	ChildPID    uint32    `json:"child_pid,omitempty"` // populated for EventClone — see types.EventClone
	Family      uint16    `json:"family,omitempty"`
	DstPort     uint16    `json:"dst_port,omitempty"`
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
	CategoryDynamicExec      = "dynamic_code_execution"
	// CategoryUnknownBinary records execve events that do not match a
	// positively-defined attack pattern (suspicious path, inline -c/-e
	// flag, shell -c with sensitive args). The category exists for chain
	// visibility in the forensic report but does not flip the verdict on
	// its own — see the rationale block above classifyExecve in
	// internal/analyzer/analyzer.go.
	CategoryUnknownBinary = "unknown_binary"
	// CategoryLibraryHijack records writes from a scanned package into
	// ANOTHER installed package's directory (a sibling under
	// /install/node_modules/<other>/). The installed package's source
	// gets backdoored; harm fires when a later workflow imports it,
	// outside kojuto's scan window — placement is the only opportunity
	// to detect it. Pairs with static analysis (which catches obvious
	// AST patterns): the dynamic rule also catches runtime-decoded
	// target paths that static cannot resolve.
	CategoryLibraryHijack = "library_hijacking"
	// CategoryDNSLookup records isolated name-resolution activity: a
	// connect() to :53 or a benign-looking DNS query payload. The real
	// C2 signal is the follow-up connect() to the resolved IP, which
	// fires the HIGH CategoryC2 rule independently. Under
	// --network=none the resolution never completes anyway, so a bare
	// DNS lookup carries no C2 harm on its own — logging it at LOW
	// keeps the forensic chain visible without flipping the verdict on
	// legitimate defensive connectivity probes (getaddrinfo at import
	// time, glibc NSS lookups) that every scan otherwise trips.
	CategoryDNSLookup = "dns_lookup"
	// CategoryDGA records the structural Domain Generation Algorithm
	// pattern: a single PID emits N+ distinct subdomain queries under
	// the same registrable 2LD whose subdomain labels share consistent
	// morphology (uniform length + character-class fingerprint). This
	// is the pattern real C2 discovery uses (SUNBURST/Sunburst-style
	// avsvmcloud.com beaconing) and one that per-query entropy checks
	// can never catch — each individual dictionary-word subdomain
	// passes the entropy threshold, but the aggregate cardinality +
	// morphology gives it away. Emitted at MEDIUM: a single cluster
	// stays under the verdict threshold on its own (heuristic rule
	// with FP potential on very active CDN clients), but pairs with
	// any other MEDIUM signal or a second DGA cluster to flip the
	// verdict.
	CategoryDGA = "dga"
)

// Category severity tiers drive verdict assignment in analyzer.Analyze.
// HIGH: a single event is enough to make the package SUSPICIOUS — these
// patterns have no legitimate explanation during install/import.
// MEDIUM: requires two or more events; isolated occurrences sometimes
// happen in legitimate libraries (e.g. CDN entropy, debugger stubs).
// LOW: never raises the verdict alone — too noisy in popular compat
// libraries (six, attrs, dataclasses) that compile/exec their own
// internal source. Still recorded in the report for forensics.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
)

// CategorySeverity classifies each detection category. Categories not
// in this map default to HIGH (fail-closed — better to flag a future
// category we forgot to weight than silently swallow it).
var CategorySeverity = map[string]string{
	CategoryC2:               SeverityHigh,
	CategoryDataExfil:        SeverityHigh,
	CategoryCredentialAccess: SeverityHigh,
	CategoryCodeExecution:    SeverityHigh,
	CategoryBinaryHijack:     SeverityHigh,
	CategoryBackdoor:         SeverityHigh,
	CategoryPersistence:      SeverityHigh,
	CategoryMemExec:          SeverityHigh,
	CategoryAntiForensics:    SeverityHigh,
	CategoryLibraryHijack:    SeverityHigh,
	CategoryDNSTunnel:        SeverityMedium,
	CategoryDGA:              SeverityMedium,
	CategoryEvasion:          SeverityMedium,
	CategoryDynamicExec:      SeverityLow,
	CategoryUnknownBinary:    SeverityLow,
	CategoryDNSLookup:        SeverityLow,
}

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
	RiskLevel   string        `json:"risk_level"`
	Categories  []string      `json:"categories,omitempty"`
	Breakdown   []CategoryHit `json:"breakdown,omitempty"`
	Description string        `json:"description"`
	Remediation string        `json:"remediation,omitempty"`
}

// CategoryHit is a per-category aggregate used by the CLI verdict
// renderer. Sorted by Count descending. Description is a short
// one-line phrase distinct from ReportSummary.Description (which is a
// full-sentence concatenation across all categories) so the CLI can
// show the breakdown as a table without re-parsing the long string.
type CategoryHit struct {
	Category    string `json:"category"`
	Count       int    `json:"count"`
	Description string `json:"description"`
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
	Dropped        uint64          `json:"dropped,omitempty"`
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
