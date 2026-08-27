package analyzer

import (
	"strconv"
	"strings"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

// TestNewFlowState_PopulatesPIDCommAndExecutedPaths pins the Phase 1
// invariant: newFlowState must produce the same PIDComm map and
// ExecutedPaths set as the pre-refactor collectPIDComm /
// collectExecutedPaths pair produced when called separately. If this
// ever regresses, isV8JITPageOp and the anti_forensics refinement
// silently break — both consume FlowState fields directly.
func TestNewFlowState_PopulatesPIDCommAndExecutedPaths(t *testing.T) {
	events := []types.SyscallEvent{
		// Execve into node — populates PIDComm and ExecutedPaths.
		{Syscall: types.EventExecve, PID: 100, Comm: "/usr/bin/node", Cmdline: "node index.js"},
		// Execve into /tmp payload — populates both.
		{Syscall: types.EventExecve, PID: 200, Comm: "/tmp/.payload"},
		// Interpreter with a /tmp cmdline argument — argv path
		// captured into ExecutedPaths so the anti-forensics
		// correlation can fire on the subsequent unlink.
		{Syscall: types.EventExecve, PID: 201, Comm: "/usr/bin/python3", Cmdline: "python3 /tmp/dropper.py"},
		// Clone from node — child PID inherits parent's comm.
		{Syscall: types.EventClone, PID: 100, ChildPID: 101},
		// Sensitive openat — path must NOT enter ExecutedPaths (it
		// was read, not executed).
		{Syscall: types.EventOpenat, PID: 100, FilePath: "/home/dev/.ssh/id_rsa"},
	}

	state := newFlowState(events)

	if got := state.PIDComm[100]; got != "/usr/bin/node" {
		t.Errorf("PIDComm[100] = %q, want /usr/bin/node", got)
	}
	if got := state.PIDComm[200]; got != "/tmp/.payload" {
		t.Errorf("PIDComm[200] = %q, want /tmp/.payload", got)
	}
	if got := state.PIDComm[101]; got != "/usr/bin/node" {
		t.Errorf("cloned PIDComm[101] = %q, want /usr/bin/node (inherited from parent)", got)
	}

	if !state.ExecutedPaths["/tmp/.payload"] {
		t.Error("ExecutedPaths missing /tmp/.payload")
	}
	if !state.ExecutedPaths["/tmp/dropper.py"] {
		t.Error("ExecutedPaths missing /tmp/dropper.py (should be captured from cmdline)")
	}
	if state.ExecutedPaths["/home/dev/.ssh/id_rsa"] {
		t.Error("openat-only path leaked into ExecutedPaths")
	}
}

// TestNewFlowState_EmptyEvents documents the empty-input contract:
// no allocations beyond the two empty maps, no panics, all lookups
// safe. Real scans that observe nothing (dead container, immediate
// pip failure) hit this path.
func TestNewFlowState_EmptyEvents(t *testing.T) {
	state := newFlowState(nil)

	if state == nil {
		t.Fatal("newFlowState(nil) returned nil")
	}
	if state.PIDComm == nil {
		t.Error("PIDComm must be non-nil (safe to read/index)")
	}
	if state.ExecutedPaths == nil {
		t.Error("ExecutedPaths must be non-nil (safe to read/index)")
	}
	if len(state.PIDComm) != 0 || len(state.ExecutedPaths) != 0 {
		t.Errorf("expected empty maps, got PIDComm=%d ExecutedPaths=%d",
			len(state.PIDComm), len(state.ExecutedPaths))
	}
	if hosts := state.DNSHostnamesForPID(0); hosts != nil {
		t.Errorf("empty state DNSHostnamesForPID(0) = %v, want nil", hosts)
	}
}

// TestFlowState_DNSChainAttribution documents the Phase 2 contract:
// DNS queries recorded via RecordDNSQuery are attributed per-PID and
// returned in observation order, deduplicated, with empty-query
// records skipped (resolver connect with no parsed payload).
func TestFlowState_DNSChainAttribution(t *testing.T) {
	state := &FlowState{}

	// Observations arrive: PID 100 queries evil.com then attacker.example
	// then a duplicate evil.com; PID 200 queries other.example; PID 100
	// also emits a resolver-connect with empty Query (parser miss).
	state.RecordDNSQuery(&types.SyscallEvent{
		Syscall: types.EventSendto, PID: 100, DstPort: 53,
		DstAddr: "8.8.8.8", DNSQuery: "evil.com",
	})
	state.RecordDNSQuery(&types.SyscallEvent{
		Syscall: types.EventSendto, PID: 100, DstPort: 53,
		DstAddr: "8.8.8.8", DNSQuery: "attacker.example",
	})
	state.RecordDNSQuery(&types.SyscallEvent{
		Syscall: types.EventSendto, PID: 100, DstPort: 53,
		DstAddr: "8.8.8.8", DNSQuery: "evil.com", // duplicate
	})
	state.RecordDNSQuery(&types.SyscallEvent{
		Syscall: types.EventSendto, PID: 200, DstPort: 53,
		DstAddr: "8.8.8.8", DNSQuery: "other.example",
	})
	state.RecordDNSQuery(&types.SyscallEvent{
		Syscall: types.EventConnect, PID: 100, DstPort: 53,
		DstAddr: "127.0.0.11", // resolver-connect with no Query
	})
	// Non-DNS event — must be skipped by the isDNSObservation guard.
	state.RecordDNSQuery(&types.SyscallEvent{
		Syscall: types.EventConnect, PID: 100, DstPort: 443,
		DstAddr: "203.0.113.5",
	})

	got := state.DNSHostnamesForPID(100)
	want := []string{"evil.com", "attacker.example"}
	if len(got) != len(want) {
		t.Fatalf("DNSHostnamesForPID(100) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("hostname[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if hosts := state.DNSHostnamesForPID(200); len(hosts) != 1 || hosts[0] != "other.example" {
		t.Errorf("PID 200 hostnames = %v, want [other.example]", hosts)
	}
	if hosts := state.DNSHostnamesForPID(999); hosts != nil {
		t.Errorf("unknown PID hostnames = %v, want nil", hosts)
	}
}

// TestAnalyze_C2ChainAnnotation exercises the end-to-end chain:
// a DNS query and a subsequent non-53 connect from the SAME PID
// produce a C2 event whose Reason names the earlier hostname.
// Verdict + category are unchanged from the pre-Phase-2 baseline —
// this is purely additive forensic enrichment.
func TestAnalyze_C2ChainAnnotation(t *testing.T) {
	events := []types.SyscallEvent{
		// Docker embedded DNS is loopback so this is filtered as
		// benign for verdict purposes, but RecordDNSQuery still
		// captures the queried hostname pre-filter — that's what
		// the annotation needs.
		{Syscall: types.EventSendto, PID: 100, Family: 2, DstAddr: "127.0.0.11", DstPort: 53, DNSQuery: "evil.example"},
		{Syscall: types.EventConnect, PID: 100, Family: 2, DstAddr: "203.0.113.5", DstPort: 443},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Fatalf("expected suspicious verdict for connect, got %s", verdict)
	}
	var c2 *types.SyscallEvent
	for i := range filtered {
		if filtered[i].Category == types.CategoryC2 {
			c2 = &filtered[i]
			break
		}
	}
	if c2 == nil {
		t.Fatal("expected a C2 event in filtered output")
	}
	if !strings.Contains(c2.Reason, "evil.example") {
		t.Errorf("C2 Reason should mention the queried hostname, got: %s", c2.Reason)
	}
	if !strings.Contains(c2.Reason, "Preceded by DNS query") {
		t.Errorf("C2 Reason should mention the DNS chain, got: %s", c2.Reason)
	}
}

// TestAnalyze_C2NoDNSChain confirms that a connect without any prior
// DNS query gets its baseline Reason with NO chain annotation. Guards
// against the annotation always firing (which would be noise).
func TestAnalyze_C2NoDNSChain(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, PID: 100, Family: 2, DstAddr: "203.0.113.5", DstPort: 443},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered event, got %d", len(filtered))
	}
	if strings.Contains(filtered[0].Reason, "Preceded by DNS query") {
		t.Errorf("no DNS observed but Reason claims a chain: %s", filtered[0].Reason)
	}
}

// TestAnalyze_C2DifferentPIDNoChain confirms PID scope: a DNS query
// from one PID must NOT annotate a connect from another PID.
func TestAnalyze_C2DifferentPIDNoChain(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventSendto, PID: 100, Family: 2, DstAddr: "127.0.0.11", DstPort: 53, DNSQuery: "evil.example"},
		{Syscall: types.EventConnect, PID: 200, Family: 2, DstAddr: "203.0.113.5", DstPort: 443},
	}
	_, filtered := Analyze(events)
	for _, e := range filtered {
		if e.Category == types.CategoryC2 && strings.Contains(e.Reason, "evil.example") {
			t.Errorf("PID 200 connect got PID 100's DNS chain: %s", e.Reason)
		}
	}
}

// buildDGAEvents produces N synthetic DNS-query events for a single
// PID under one 2LD, with morphologically-uniform subdomain labels.
// Used by DGA tests as a compact fixture.
func buildDGAEvents(pid uint32, twoLD string, n int) []types.SyscallEvent {
	events := make([]types.SyscallEvent, 0, n)
	for i := range n {
		// Uniform shape: three-letter word + hyphen + zero-padded two-digit index.
		// Length 6 for all: `abc-NN`. Character-class fingerprint: lower+digit+hyphen.
		sub := "abc-"
		if i < 10 {
			sub += "0"
		}
		sub += strconv.Itoa(i)
		events = append(events, types.SyscallEvent{
			Syscall:  types.EventSendto,
			PID:      pid,
			Family:   2,
			DstAddr:  "8.8.8.8",
			DstPort:  53,
			DNSQuery: sub + "." + twoLD,
		})
	}
	return events
}

// TestDetectDGAClusters_PositiveMatch exercises the happy path:
// dgaMinCluster distinct uniform subdomains under one 2LD from one
// PID → one DGA cluster with correct metadata.
func TestDetectDGAClusters_PositiveMatch(t *testing.T) {
	state := &FlowState{}
	for _, e := range buildDGAEvents(100, "metrics.legit-analytics.com", dgaMinCluster) {
		state.RecordDNSQuery(&e)
	}

	clusters := state.DetectDGAClusters()
	if len(clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(clusters))
	}
	c := clusters[0]
	if c.PID != 100 {
		t.Errorf("PID = %d, want 100", c.PID)
	}
	// registrableTwoLD is rightmost-two-labels, so this becomes
	// legit-analytics.com (not the full metrics.legit-analytics.com).
	if c.TwoLD != "legit-analytics.com" {
		t.Errorf("TwoLD = %q, want legit-analytics.com", c.TwoLD)
	}
	if c.QueryCount != dgaMinCluster {
		t.Errorf("QueryCount = %d, want %d", c.QueryCount, dgaMinCluster)
	}
	if len(c.Samples) != 3 {
		t.Errorf("Samples length = %d, want 3", len(c.Samples))
	}
}

// TestDetectDGAClusters_BelowThreshold confirms sub-threshold
// cardinality does not fire — dgaMinCluster is the floor.
func TestDetectDGAClusters_BelowThreshold(t *testing.T) {
	state := &FlowState{}
	for _, e := range buildDGAEvents(100, "example.com", dgaMinCluster-1) {
		state.RecordDNSQuery(&e)
	}
	if clusters := state.DetectDGAClusters(); len(clusters) != 0 {
		t.Errorf("expected 0 clusters (below threshold), got %d", len(clusters))
	}
}

// TestDetectDGAClusters_MorphologyInconsistent pins that a group
// large enough by count but morphology-inconsistent is rejected.
// Legit CDN clients that hit many differently-shaped bucket names
// under one 2LD fall in this bucket.
func TestDetectDGAClusters_MorphologyInconsistent(t *testing.T) {
	state := &FlowState{}
	// N distinct subdomains, but wildly different lengths — legit
	// bucket-name-per-lookup pattern.
	buckets := []string{
		"a", "medium-name", "very-long-bucket-name-here", "xyz",
		"another", "b", "prod-eu-west-2-storage", "u",
		"test-01", "customer-analytics-data",
	}
	for _, b := range buckets {
		evt := types.SyscallEvent{
			Syscall: types.EventSendto, PID: 100, Family: 2,
			DstAddr: "8.8.8.8", DstPort: 53,
			DNSQuery: b + ".s3.amazonaws.com",
		}
		state.RecordDNSQuery(&evt)
	}
	if clusters := state.DetectDGAClusters(); len(clusters) != 0 {
		t.Errorf("expected 0 clusters (morphology inconsistent), got %d", len(clusters))
	}
}

// TestDetectDGAClusters_MultiplePIDsSeparate confirms PID scope:
// two PIDs each with own DGA cluster produce two separate findings,
// not one merged.
func TestDetectDGAClusters_MultiplePIDsSeparate(t *testing.T) {
	state := &FlowState{}
	for _, e := range buildDGAEvents(100, "one.example.com", dgaMinCluster) {
		state.RecordDNSQuery(&e)
	}
	for _, e := range buildDGAEvents(200, "two.example.com", dgaMinCluster) {
		state.RecordDNSQuery(&e)
	}
	clusters := state.DetectDGAClusters()
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters (one per PID), got %d", len(clusters))
	}
	pids := map[uint32]bool{}
	for _, c := range clusters {
		pids[c.PID] = true
	}
	if !pids[100] || !pids[200] {
		t.Errorf("expected clusters for PID 100 and 200, got %v", pids)
	}
}

// TestDetectDGAClusters_DedupSubdomains guards against the same
// subdomain repeated many times being counted as N distinct entries.
// Legit code retrying a single failing hostname must not fire the
// rule.
func TestDetectDGAClusters_DedupSubdomains(t *testing.T) {
	state := &FlowState{}
	for range dgaMinCluster * 3 {
		evt := types.SyscallEvent{
			Syscall: types.EventSendto, PID: 100, Family: 2,
			DstAddr: "8.8.8.8", DstPort: 53,
			DNSQuery: "same-name.example.com",
		}
		state.RecordDNSQuery(&evt)
	}
	if clusters := state.DetectDGAClusters(); len(clusters) != 0 {
		t.Errorf("expected 0 clusters (all queries are the same subdomain), got %d", len(clusters))
	}
}

// TestAnalyze_DGAFiringAsMedium exercises the end-to-end: enough DGA
// queries on their own produce one MEDIUM synthetic event. Verdict
// stays clean because MEDIUM needs 2+ to flip — the safety choice
// documented on CategoryDGA. A second cluster (or any other MEDIUM
// signal) is what would tip the verdict; that composition is
// verified in TestAnalyze_DGATwoClustersFlipVerdict.
func TestAnalyze_DGAFiringAsMedium(t *testing.T) {
	events := buildDGAEvents(100, "legit-analytics.com", dgaMinCluster)
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for single DGA cluster (MEDIUM alone), got %s", verdict)
	}
	var dgaSeen bool
	for _, e := range filtered {
		if e.Category == types.CategoryDGA {
			dgaSeen = true
			if !strings.Contains(e.Reason, "Structural DGA") {
				t.Errorf("DGA event Reason missing structural label: %s", e.Reason)
			}
		}
	}
	if !dgaSeen {
		t.Error("expected one dga synthetic event in filtered output")
	}
}

// TestAnalyze_DGATwoClustersFlipVerdict confirms that two separate
// DGA clusters (say, two distinct 2LDs) push the verdict to
// SUSPICIOUS via the "2+ MEDIUM" rule.
func TestAnalyze_DGATwoClustersFlipVerdict(t *testing.T) {
	events := append(
		buildDGAEvents(100, "one.example.com", dgaMinCluster),
		buildDGAEvents(100, "two.example.net", dgaMinCluster)...,
	)
	verdict, _ := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for two DGA clusters, got %s", verdict)
	}
}

// TestMorphologyConsistent_CharClassFingerprint pins that character
// classes must match, not just lengths. Legit hex-hash CDN
// (lowercase+digit) and legit dictionary-word DGA (lowercase+hyphen)
// have the same length but different fingerprints and must NOT be
// clustered together.
func TestMorphologyConsistent_CharClassFingerprint(t *testing.T) {
	// Mixed: two hex hashes + one hyphen-word. Lengths match, but
	// fingerprints diverge (digit vs hyphen).
	subs := []string{"a1b2c3d4", "e5f6a7b8", "abc-defg"}
	if morphologyConsistent(subs) {
		t.Error("morphology check accepted mixed fingerprints (hex hashes + hyphen words)")
	}
	// All hex hashes: same fingerprint (lower+digit), same length.
	hexes := []string{"a1b2c3d4", "e5f6a7b8", "1234abcd"}
	if !morphologyConsistent(hexes) {
		t.Error("morphology check rejected uniform hex hashes")
	}
}
