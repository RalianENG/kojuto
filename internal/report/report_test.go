package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

func TestGenerate_EmptyEvents(t *testing.T) {
	r := Generate("testpkg", "1.0.0", types.EcosystemPyPI, types.VerdictClean, "ebpf", nil, 0, 0, nil)

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

	r := Generate("badpkg", "", types.EcosystemNpm, types.VerdictSuspicious, "strace", events, 0, 0, nil)

	if len(r.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(r.Events))
	}

	if r.Ecosystem != types.EcosystemNpm {
		t.Errorf("expected ecosystem npm, got %s", r.Ecosystem)
	}
}

func TestGenerate_LostSamples(t *testing.T) {
	r := Generate("pkg", "1.0", types.EcosystemPyPI, types.VerdictInconclusive, "ebpf", nil, 5, 0, nil)

	if r.LostSamples != 5 {
		t.Errorf("expected 5 lost samples, got %d", r.LostSamples)
	}
}

func TestGenerate_Dropped(t *testing.T) {
	r := Generate("pkg", "1.0", types.EcosystemPyPI, types.VerdictInconclusive, "ebpf", nil, 0, 17, nil)

	if r.Dropped != 17 {
		t.Errorf("expected 17 dropped events, got %d", r.Dropped)
	}
	if r.LostSamples != 0 {
		t.Errorf("expected 0 lost samples, got %d", r.LostSamples)
	}
}

func TestWriteJSON(t *testing.T) {
	r := Generate("testpkg", "1.0.0", types.EcosystemPyPI, types.VerdictClean, "ebpf", nil, 0, 0, nil)

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

func TestSanitizeControl(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain ascii", "plain ascii"},
		{"日本語", "日本語"},
		{"with\nnewline", `with\nnewline`},
		{"with\ttab", `with\ttab`},
		{"esc\x1b[2J", `esc\x1b[2J`},
		{"\x00null", `\x00null`},
		{"\x07bell", `\x07bell`},
		{"del\x7f", `del\x7f`},
		{"all\x00\x01\x1b\x7fclean", `all\x00\x01\x1b\x7fclean`},
	}
	for _, tc := range cases {
		if got := sanitizeControl(tc.in); got != tc.want {
			t.Errorf("sanitizeControl(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestWriteJSON_StripsAnsiFromAttackerFields pins the security
// invariant: any attacker-controlled string field (CodeSnippet, Comm,
// Cmdline, etc.) carrying ANSI escape sequences is rendered into the
// JSON as a printable backslash escape, so a downstream `jq -r` style
// raw-string consumer cannot be fed terminal control bytes.
func TestWriteJSON_StripsAnsiFromAttackerFields(t *testing.T) {
	events := []types.SyscallEvent{
		{
			Timestamp:   time.Now(),
			PID:         1,
			Syscall:     types.EventDynamicExec,
			AuditEvent:  "exec",
			CodeSnippet: "payload\x1b[2J\x1b[Hverdict: clean",
			Comm:        "evil\x1b[31m",
			Cmdline:     "sh\x07-c\x00boom",
			FilePath:    "/tmp/\x1bweird",
		},
	}
	r := Generate("badpkg", "1.0.0", types.EcosystemPyPI, types.VerdictSuspicious, "ebpf", events, 0, 0, nil)

	var buf bytes.Buffer
	if err := WriteJSON(&r, &buf); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// The serialised JSON must not contain a literal ESC byte (0x1b)
	// or BEL/NUL anywhere, even after JSON decoding.
	var decoded types.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, e := range decoded.Events {
		fields := []struct{ name, val string }{
			{"CodeSnippet", e.CodeSnippet},
			{"Comm", e.Comm},
			{"Cmdline", e.Cmdline},
			{"FilePath", e.FilePath},
		}
		for _, f := range fields {
			for i := 0; i < len(f.val); i++ {
				c := f.val[i]
				if c < 0x20 || c == 0x7f {
					t.Errorf("%s contains raw control byte 0x%02x: %q", f.name, c, f.val)
					break
				}
			}
		}
		// Spot-check the encoded form is human-readable.
		if !bytes.Contains(buf.Bytes(), []byte(`\\x1b`)) {
			t.Errorf("expected printable backslash-escaped ESC in JSON output, got:\n%s", buf.String())
		}
	}
}
