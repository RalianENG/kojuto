package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

func TestGenerate_EmptyEvents(t *testing.T) {
	r := Generate("testpkg", "1.0.0", types.EcosystemPyPI, types.VerdictClean, "ebpf", nil, 0, nil)

	if r.Package != "testpkg" {
		t.Errorf("expected package testpkg, got %s", r.Package)
	}

	if r.Ecosystem != types.EcosystemPyPI {
		t.Errorf("expected ecosystem pypi, got %s", r.Ecosystem)
	}

	if r.Verdict != types.VerdictClean {
		t.Errorf("expected clean verdict, got %s", r.Verdict)
	}

	if len(r.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(r.Events))
	}
}

func TestGenerate_WithEvents(t *testing.T) {
	events := []types.SyscallEvent{
		{Timestamp: time.Now(), PID: 1, Syscall: types.EventConnect, DstAddr: "1.2.3.4", DstPort: 80, Family: 2},
	}

	r := Generate("badpkg", "", types.EcosystemNpm, types.VerdictSuspicious, "strace", events, 0, nil)

	if len(r.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(r.Events))
	}

	if r.Ecosystem != types.EcosystemNpm {
		t.Errorf("expected ecosystem npm, got %s", r.Ecosystem)
	}
}

func TestGenerate_LostSamples(t *testing.T) {
	r := Generate("pkg", "1.0", types.EcosystemPyPI, types.VerdictInconclusive, "ebpf", nil, 5, nil)

	if r.LostSamples != 5 {
		t.Errorf("expected 5 lost samples, got %d", r.LostSamples)
	}
}

func TestWriteJSON(t *testing.T) {
	r := Generate("testpkg", "1.0.0", types.EcosystemPyPI, types.VerdictClean, "ebpf", nil, 0, nil)

	var buf bytes.Buffer
	if err := WriteJSON(&r, &buf); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var decoded types.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	if decoded.Package != "testpkg" {
		t.Errorf("expected testpkg, got %s", decoded.Package)
	}

	if decoded.Verdict != types.VerdictClean {
		t.Errorf("expected clean, got %s", decoded.Verdict)
	}
}
