package types

import (
	"encoding/json"
	"testing"
)

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
	// Verify omitempty: a minimal event should omit optional fields in JSON.
	evt := SyscallEvent{
		Syscall: EventConnect,
		PID:     1234,
	}

	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded["syscall"] != EventConnect {
		t.Errorf("syscall = %v, want %q", decoded["syscall"], EventConnect)
	}
	// omitempty fields should be absent from JSON.
	for _, key := range []string{"dst_addr", "cmdline", "file_path", "src_path", "dst_path", "dns_query"} {
		if _, ok := decoded[key]; ok {
			t.Errorf("expected %q to be omitted from JSON", key)
		}
	}
}

func TestReportStructure(t *testing.T) {
	r := Report{
		Package:   "test",
		Ecosystem: EcosystemPyPI,
		Verdict:   VerdictClean,
		Events:    []SyscallEvent{},
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Package != "test" {
		t.Errorf("Package = %q, want 'test'", decoded.Package)
	}
	if len(decoded.Events) != 0 {
		t.Errorf("Events length = %d, want 0", len(decoded.Events))
	}
	if decoded.LostSamples != 0 {
		t.Errorf("LostSamples = %d, want 0", decoded.LostSamples)
	}
}
