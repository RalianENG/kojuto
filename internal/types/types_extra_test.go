package types

import "testing"

func TestEventConstants(t *testing.T) {
	events := map[string]string{
		"EventConnect":  EventConnect,
		"EventSendto":   EventSendto,
		"EventSendmsg":  EventSendmsg,
		"EventSendmmsg": EventSendmmsg,
		"EventBind":     EventBind,
		"EventListen":   EventListen,
		"EventAccept":   EventAccept,
		"EventExecve":   EventExecve,
		"EventOpenat":   EventOpenat,
		"EventRename":   EventRename,
	}

	// All constants should be non-empty.
	for name, val := range events {
		if val == "" {
			t.Errorf("%s is empty", name)
		}
	}

	// All constants should be unique.
	seen := make(map[string]string)
	for name, val := range events {
		if prev, ok := seen[val]; ok {
			t.Errorf("%s and %s have same value %q", name, prev, val)
		}
		seen[val] = name
	}
}

func TestEcosystemConstants(t *testing.T) {
	if EcosystemPyPI != "pypi" {
		t.Errorf("EcosystemPyPI = %q, want 'pypi'", EcosystemPyPI)
	}
	if EcosystemNpm != "npm" {
		t.Errorf("EcosystemNpm = %q, want 'npm'", EcosystemNpm)
	}
	if EcosystemPyPI == EcosystemNpm {
		t.Error("ecosystem constants must differ")
	}
}

func TestSyscallEventJSON(t *testing.T) {
	// Verify omitempty fields — SyscallEvent with only required fields
	// should serialize without optional fields.
	evt := SyscallEvent{
		Syscall: EventConnect,
		PID:     1234,
	}

	if evt.Syscall != EventConnect {
		t.Errorf("Syscall = %q, want %q", evt.Syscall, EventConnect)
	}
	if evt.DstAddr != "" {
		t.Error("DstAddr should be empty")
	}
	if evt.Cmdline != "" {
		t.Error("Cmdline should be empty")
	}
	if evt.FilePath != "" {
		t.Error("FilePath should be empty")
	}
}

func TestReportStructure(t *testing.T) {
	r := Report{
		Package:   "test",
		Ecosystem: EcosystemPyPI,
		Verdict:   VerdictClean,
		Events:    []SyscallEvent{},
	}

	if r.Package != "test" {
		t.Errorf("Package = %q, want 'test'", r.Package)
	}
	if len(r.Events) != 0 {
		t.Errorf("Events length = %d, want 0", len(r.Events))
	}
	if r.LostSamples != 0 {
		t.Errorf("LostSamples = %d, want 0", r.LostSamples)
	}
}
