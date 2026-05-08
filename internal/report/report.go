package report

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

// Generate creates a Report from scan results.
func Generate(pkg, version, ecosystem, verdict, probeMethod string, events []types.SyscallEvent, lostSamples, dropped uint64, summary *types.ReportSummary) types.Report {
	if events == nil {
		events = []types.SyscallEvent{}
	}

	return types.Report{
		Package:     pkg,
		Version:     version,
		Ecosystem:   ecosystem,
		Timestamp:   time.Now().UTC(),
		Verdict:     verdict,
		Summary:     summary,
		Events:      events,
		ProbeMethod: probeMethod,
		LostSamples: lostSamples,
		Dropped:     dropped,
	}
}

// WriteJSON writes the report as indented JSON to w. Every string field
// of every event is run through sanitizeControl first so a downstream
// consumer that decodes the JSON and prints a string field raw (e.g.
// `jq -r .events[].code_snippet`) cannot be fed an attacker-controlled
// ANSI escape sequence smuggled in via a malicious package's audit-hook
// snippet, prctl-set comm name, or future attacker-reachable string
// slot. The Python audit hook performs the same escape on its own side;
// this is the host-side belt-and-braces guard.
func WriteJSON(r *types.Report, w io.Writer) error {
	for i := range r.Events {
		sanitizeEventStrings(&r.Events[i])
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}

	return nil
}

// sanitizeEventStrings rewrites every string field of e in place so any
// C0 control byte (0x00-0x1f) or DEL (0x7f) that an attacker placed in
// an event field is rendered as a printable `\xNN` escape rather than
// passing through to the report consumer's terminal.
//
// Reflection is used so future string fields added to SyscallEvent are
// covered automatically. Non-string fields are skipped. Fields kojuto
// itself populates (Syscall, Category, Phase, etc.) are no-ops because
// their values never contain control bytes.
func sanitizeEventStrings(e *types.SyscallEvent) {
	v := reflect.ValueOf(e).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		if f.Kind() == reflect.String && f.CanSet() {
			f.SetString(sanitizeControl(f.String()))
		}
	}
}

// sanitizeControl escapes C0 control bytes and DEL to printable forms.
// Common whitespace bytes use the conventional \n / \r / \t shorthand;
// all others render as \xNN. Any other byte (printable ASCII, UTF-8
// multibyte, etc.) passes through unchanged.
func sanitizeControl(s string) string {
	if !needsControlEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func needsControlEscape(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
