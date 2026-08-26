package analyzer

import (
	"strings"

	"github.com/RalianENG/kojuto/internal/types"
)

// FlowState centralizes the cross-event context that individual
// classification rules need to reason about a syscall in the flow it
// belongs to, rather than as an isolated point event. Historically
// each correlation lived as its own ad-hoc pre-pass (collectPIDComm
// for V8 JIT filtering, collectExecutedPaths for anti-forensics);
// consolidating them here gives future series-aware rules (DNS→connect
// chain, DGA cardinality, memfd→execveat, sensitive-read→exfil) a
// single place to hang new state without another parallel pre-pass.
//
// This is Phase 1 of the flow-aware analyzer refactor and is
// deliberately behavior-preserving: the two existing correlations
// migrate into FlowState fields, callers switch from raw maps to the
// struct, and no classification changes. Phase 2 will layer per-PID
// DNS query records on top; Phase 3 will use those records for DGA
// structural detection.
type FlowState struct {
	// PIDComm maps a PID observed in an execve (or attributed via a
	// clone from an execve-attributed parent, or the strace main-target
	// alias for a disambiguated PID) to that process's binary path.
	// Used by isV8JITPageOp to distinguish legitimate V8 JIT RWX pages
	// from shellcode injection.
	PIDComm map[uint32]string

	// ExecutedPaths is the set of paths that appeared as the execve
	// target — plus paths in interpreter argv that live under a
	// staging directory (/tmp, /dev/shm, /var/tmp, /run). Used to
	// refine anti_forensics: an unlink is only interesting if the
	// deleted file was also executed in this scan (the
	// create→execute→delete triad).
	ExecutedPaths map[string]bool
}

// newFlowState builds the FlowState from a temporally-ordered event
// stream. Runs the two migrated pre-passes over the events; each pass
// is independent and streaming, so the total cost is O(N) with two
// map allocations.
func newFlowState(events []types.SyscallEvent) *FlowState {
	return &FlowState{
		PIDComm:       collectPIDComm(events),
		ExecutedPaths: collectExecutedPaths(events),
	}
}

// isInSuspiciousDir reports whether a path lives under a staging
// directory that anti_forensics + payload-drop rules watch. Lifted
// out of the analyzer.go body so collectExecutedPaths can reference
// it without dragging classifier helpers along.
func isInSuspiciousDir(filePath string) bool {
	return strings.HasPrefix(filePath, "/tmp/") ||
		strings.HasPrefix(filePath, "/dev/shm/") ||
		strings.HasPrefix(filePath, "/var/tmp/") ||
		strings.HasPrefix(filePath, "/run/")
}
