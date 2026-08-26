package analyzer

import (
	"strings"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

// dnsQueryRecord captures a single DNS observation seen during the
// Analyze() iteration. The record is stored so that a later
// classification pass on a non-53 connect can annotate its Reason
// with the hostnames the same PID previously queried — the "did the
// attacker resolve a name before dialing" forensic chain.
//
// PID = 0 (the strace main-target alias) is stored as-is; downstream
// lookups treat 0 as a normal PID because it consistently maps to
// the phase's primary process across the scan.
type dnsQueryRecord struct {
	PID       uint32
	Query     string    // hostname string extracted by the parser; empty when the parser saw only the resolver connect
	DstAddr   string    // resolver IP address the DNS packet targeted
	Timestamp time.Time // parser assignment time; monotonic within a scan
}

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

	// dnsQueries is an append-only list of DNS observations seen so
	// far during the Analyze() iteration. Populated incrementally via
	// RecordDNSQuery so that a lookup for "queries by PID before now"
	// is trivially temporal-correct (only prior observations are
	// present when classifyConnect runs on a subsequent connect).
	// Package-private because callers should go through the
	// DNSHostnamesForPID accessor.
	dnsQueries []dnsQueryRecord
}

// RecordDNSQuery appends a DNS observation if evt is a DNS-shaped
// syscall (any of connect/sendto/sendmsg/sendmmsg targeting port
// 53). Callers should invoke this on every event BEFORE isBenign
// filtering, because loopback:53 queries (Docker embedded DNS at
// 127.0.0.11) get filtered as benign for verdict purposes but still
// carry attacker-stated intent worth preserving for the connect
// chain annotation ("this PID looked up evil.com then dialed
// 203.0.113.5").
//
// Idempotency is caller-controlled: this appends unconditionally
// when the event shape matches, so double-invocation on the same
// event would double-record. Analyze() calls once per event.
func (s *FlowState) RecordDNSQuery(evt *types.SyscallEvent) {
	if !isDNSObservation(evt) {
		return
	}
	s.dnsQueries = append(s.dnsQueries, dnsQueryRecord{
		PID:       evt.PID,
		Query:     evt.DNSQuery,
		DstAddr:   evt.DstAddr,
		Timestamp: evt.Timestamp,
	})
}

// DNSHostnamesForPID returns unique non-empty hostnames the given
// PID queried up to the current point in the Analyze() iteration,
// in observation order. Empty-query DNS observations (resolver
// connect without a parsed payload) are skipped — the annotation
// only carries actionable hostnames.
func (s *FlowState) DNSHostnamesForPID(pid uint32) []string {
	if len(s.dnsQueries) == 0 {
		return nil
	}
	var out []string
	seen := make(map[string]bool)
	for _, q := range s.dnsQueries {
		if q.PID != pid || q.Query == "" {
			continue
		}
		if seen[q.Query] {
			continue
		}
		seen[q.Query] = true
		out = append(out, q.Query)
	}
	return out
}

// isDNSObservation reports whether the event shape is a DNS syscall:
// either the resolver connect on port 53 or one of the sendto family
// with a port-53 destination. sendto is checked by port because the
// parser only populates DNSQuery for wire-format DNS payloads it can
// decode; a non-decoded packet to :53 is still a DNS observation for
// chain-attribution purposes.
func isDNSObservation(evt *types.SyscallEvent) bool {
	if evt.DstPort != 53 {
		return false
	}
	switch evt.Syscall {
	case types.EventConnect, types.EventSendto, types.EventSendmsg, types.EventSendmmsg:
		return true
	}
	return false
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
