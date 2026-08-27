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

// DGA detection thresholds. Kept as package vars so tests can
// exercise the rule at smaller cluster sizes without waiting for
// real-world attack proportions.
var (
	// dgaMinCluster is the minimum number of distinct subdomains
	// under one 2LD required to consider a DGA. 10 is empirically
	// safe against legit multi-subdomain patterns (S3 buckets, CDN
	// hashes rarely reach 10 in a single install phase).
	dgaMinCluster = 10
	// dgaLengthVariance caps how much subdomain lengths may drift
	// from the median before morphology is considered inconsistent.
	// ±3 covers "node-edge-01" vs "core-flow-05" (both length 11)
	// but rejects "abc" alongside "very-long-bucket-name".
	dgaLengthVariance = 3
)

// DGACluster is a detected DGA pattern: N+ distinct subdomains
// queried by one PID under one registrable 2LD, all sharing
// consistent subdomain morphology (length ±dgaLengthVariance and the
// same character-class fingerprint).
type DGACluster struct {
	PID        uint32
	TwoLD      string   // registrable 2LD (naive rightmost-two-labels — see registrableTwoLD)
	Samples    []string // up to first 3 distinct subdomains, in observation order
	QueryCount int      // total distinct subdomains observed under this 2LD
}

// DetectDGAClusters scans the accumulated DNS observations and
// returns every (PID, 2LD) group that meets both the cardinality
// threshold and the morphology-consistency check. Called from a
// post-classification pass in Analyze so that individual
// dns_lookup / dns_tunneling events are already recorded before the
// aggregate DGA finding lands — the analyst gets both the LOW
// forensic breadcrumbs AND the MEDIUM aggregate.
//
// Returns nil when nothing crosses the threshold — callers can
// range over the result unconditionally.
func (s *FlowState) DetectDGAClusters() []DGACluster {
	if len(s.dnsQueries) < dgaMinCluster {
		return nil
	}
	// Group unique subdomain labels by (PID, 2LD). Order preserved
	// for deterministic Sample selection.
	type key struct {
		pid   uint32
		twoLD string
	}
	groups := make(map[key][]string)
	order := make([]key, 0)
	seen := make(map[key]map[string]bool)
	for i := range s.dnsQueries {
		q := &s.dnsQueries[i]
		if q.Query == "" {
			continue
		}
		twoLD := registrableTwoLD(q.Query)
		sub := strings.TrimSuffix(strings.TrimSuffix(q.Query, twoLD), ".")
		if sub == "" || twoLD == "" {
			continue
		}
		k := key{q.PID, twoLD}
		if _, ok := seen[k]; !ok {
			seen[k] = make(map[string]bool)
			order = append(order, k)
		}
		if seen[k][sub] {
			continue
		}
		seen[k][sub] = true
		groups[k] = append(groups[k], sub)
	}

	var clusters []DGACluster
	for _, k := range order {
		subs := groups[k]
		if len(subs) < dgaMinCluster {
			continue
		}
		if !morphologyConsistent(subs) {
			continue
		}
		samples := subs
		if len(samples) > 3 {
			samples = samples[:3]
		}
		clusters = append(clusters, DGACluster{
			PID:        k.pid,
			TwoLD:      k.twoLD,
			Samples:    samples,
			QueryCount: len(subs),
		})
	}
	return clusters
}

// registrableTwoLD extracts the naive registrable 2LD from a
// hostname: the rightmost two dot-separated labels. This is
// intentionally NOT Public-Suffix-List aware (adding a 200+KB PSL
// data file for one rule was rejected as disproportionate) — the
// consequence is that queries under multi-label public suffixes
// (co.uk, ap-northeast-1.compute.amazonaws.com) get grouped by a
// smaller 2LD than a strict eTLD+1 would. In practice this widens
// what counts as "same domain" and is conservative for DGA
// detection: false clustering, if any, tends to fire the rule on
// legit multi-region cloud clients that also happen to be
// morphology-uniform. The morphology gate filters those out.
func registrableTwoLD(hostname string) string {
	// Strip trailing dot if present.
	h := strings.TrimSuffix(hostname, ".")
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return ""
	}
	return labels[len(labels)-2] + "." + labels[len(labels)-1]
}

// morphologyConsistent reports whether the subdomain labels share
// enough structural similarity to look algorithmically generated.
// Two axes:
//
//  1. Length variance: max - min of subdomain byte lengths must be
//     at most dgaLengthVariance. `node-edge-01` and `core-flow-05`
//     are 11 chars each (variance 0); `pip` and `mycompany-prod-x`
//     are wildly different (variance ≥10) and would not pass.
//
//  2. Character-class fingerprint: each subdomain's fingerprint is a
//     tuple of (has-lowercase, has-uppercase, has-digit, has-hyphen).
//     All subdomains must share the same fingerprint. Uniform hex
//     hashes (only lowercase+digit) match each other; mixing plain
//     words (lowercase only) with hex hashes (lowercase+digit) does
//     not.
//
// Both gates must pass — either alone lets in too much legit noise.
func morphologyConsistent(subs []string) bool {
	if len(subs) < 2 {
		return false
	}
	minLen, maxLen := len(subs[0]), len(subs[0])
	firstFp := charClassFingerprint(subs[0])
	for _, s := range subs[1:] {
		if l := len(s); l < minLen {
			minLen = l
		} else if l > maxLen {
			maxLen = l
		}
		if charClassFingerprint(s) != firstFp {
			return false
		}
	}
	return maxLen-minLen <= dgaLengthVariance
}

// charClassFingerprint returns a compact tuple describing which
// character classes appear in s. Two subdomains with the same
// fingerprint use the same "alphabet"; different fingerprints mean
// heterogeneous character sets and disqualify morphology matching.
func charClassFingerprint(s string) uint8 {
	const (
		fpLower  uint8 = 1 << 0
		fpUpper  uint8 = 1 << 1
		fpDigit  uint8 = 1 << 2
		fpHyphen uint8 = 1 << 3
	)
	var fp uint8
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			fp |= fpLower
		case c >= 'A' && c <= 'Z':
			fp |= fpUpper
		case c >= '0' && c <= '9':
			fp |= fpDigit
		case c == '-':
			fp |= fpHyphen
		}
	}
	return fp
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
