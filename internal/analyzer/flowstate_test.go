package analyzer

import (
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
}
