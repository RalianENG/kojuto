package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"

	"github.com/RalianENG/kojuto/internal/types"
)

// init disables ANSI styling for the whole test file so string
// assertions don't have to account for escape sequences. Tests that
// want to exercise the styled path can re-enable it locally.
func init() {
	color.NoColor = true
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0.0s"},
		{500 * time.Millisecond, "0.5s"},
		{999 * time.Millisecond, "1.0s"},
		{1 * time.Second, "1s"},
		{42 * time.Second, "42s"},
		{59 * time.Second, "59s"},
		{60 * time.Second, "1m 0s"},
		{83 * time.Second, "1m 23s"},
		{2 * time.Hour, "120m 0s"},
	}
	for _, c := range cases {
		got := formatDuration(c.d)
		if got != c.want {
			t.Errorf("formatDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestPadRight(t *testing.T) {
	cases := []struct {
		s    string
		n    int
		want string
	}{
		{"x", 5, "x    "},
		{"hello", 5, "hello"},
		{"hello", 3, "hello"}, // overflow keeps full input
		{"", 3, "   "},
	}
	for _, c := range cases {
		got := padRight(c.s, c.n)
		if got != c.want {
			t.Errorf("padRight(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
}

func TestPkgCoord(t *testing.T) {
	if got := pkgCoord("six", "1.17.0"); got != "six@1.17.0" {
		t.Errorf("got %q, want six@1.17.0", got)
	}
	if got := pkgCoord("six", ""); got != "six" {
		t.Errorf("got %q, want six", got)
	}
}

// TestRenderVerdictBlockSuspiciousContent exercises the full
// suspicious branch including the breakdown table. We capture stderr
// to a buffer so non-color output can be string-asserted.
func TestRenderVerdictBlockSuspiciousContent(t *testing.T) {
	var buf bytes.Buffer
	summary := &types.ReportSummary{
		RiskLevel:  "critical",
		Categories: []string{types.CategoryC2, types.CategoryMemExec},
		Breakdown: []types.CategoryHit{
			{Category: types.CategoryMemExec, Count: 14, Description: "shellcode injection (mmap+mprotect RWX)"},
			{Category: types.CategoryC2, Count: 2, Description: "outbound to non-loopback addresses"},
		},
		Description: "writable+executable memory; outbound C2.",
		Remediation: "Do NOT install this package.",
	}
	renderVerdictBlock(&buf, types.VerdictSuspicious, "axios-attack-demo", "1.14.1", 16, summary, 0, 0)
	out := buf.String()

	expected := []string{
		"SUSPICIOUS",
		"axios-attack-demo@1.14.1",
		"16 events across 2 categories",
		"memory_execution",
		"shellcode injection",
		"c2_communication",
		"outbound to non-loopback",
		"Do NOT install this package",
	}
	for _, s := range expected {
		if !strings.Contains(out, s) {
			t.Errorf("expected output to contain %q. Got:\n%s", s, out)
		}
	}
}

func TestRenderVerdictBlockCleanIsTerse(t *testing.T) {
	var buf bytes.Buffer
	renderVerdictBlock(&buf, types.VerdictClean, "six", "1.17.0", 0, &types.ReportSummary{
		RiskLevel:   "none",
		Description: "No suspicious activity detected.",
	}, 0, 0)
	out := buf.String()

	if !strings.Contains(out, "CLEAN") {
		t.Errorf("clean verdict should mention CLEAN. Got:\n%s", out)
	}
	if !strings.Contains(out, "six@1.17.0") {
		t.Errorf("clean verdict should include pkg coord. Got:\n%s", out)
	}
	// Clean output should NOT include the breakdown wording — keep terse.
	if strings.Contains(out, "events across") {
		t.Errorf("clean verdict should not include breakdown header. Got:\n%s", out)
	}
}

func TestRenderVerdictBlockInconclusiveExplains(t *testing.T) {
	var buf bytes.Buffer
	renderVerdictBlock(&buf, types.VerdictInconclusive, "pkg", "0.1.0", 0, &types.ReportSummary{
		Remediation: "Re-run with --probe-method strace-container.",
	}, 5, 17)
	out := buf.String()

	for _, want := range []string{"INCONCLUSIVE", "5 kernel sample(s) lost", "17 event(s) dropped", "Re-run with"} {
		if !strings.Contains(out, want) {
			t.Errorf("inconclusive output missing %q. Got:\n%s", want, out)
		}
	}
}

func TestRenderBatchSummary(t *testing.T) {
	var buf bytes.Buffer
	suspicious := []batchSuspicious{
		{name: "evil-pkg-a", categories: []string{types.CategoryC2, types.CategoryCredentialAccess}},
		{name: "evil-pkg-b", categories: []string{types.CategoryCodeExecution}},
	}
	renderBatchSummary(&buf, 50, 1, suspicious, 98*time.Second)
	out := buf.String()

	for _, want := range []string{
		"scanned 50 packages",
		"1m 38s",
		"47 clean", // 50 total - 2 suspicious - 1 errored
		"1 errored",
		"2 suspicious",
		"evil-pkg-a",
		"evil-pkg-b",
		"c2_communication",
		"code_execution",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("batch summary missing %q. Got:\n%s", want, out)
		}
	}
}

// TestShouldDisableColor pins the precedence rules used by
// configureColor. The key non-obvious case is "stderr-TTY + stdout-pipe"
// (e.g. `kojuto scan ... > report.json`) — the verdict block must keep
// its colors because the user is still watching stderr in a terminal.
func TestShouldDisableColor(t *testing.T) {
	cases := []struct {
		name        string
		flag        bool
		env         string
		stderrIsTTY bool
		want        bool
	}{
		{"flag forces off even with TTY", true, "", true, true},
		{"flag forces off even with env unset", true, "", false, true},
		{"NO_COLOR=1 forces off even on TTY", false, "1", true, true},
		// no-color.org spec: any non-empty value disables, including "0".
		{"NO_COLOR=0 still forces off (any non-empty)", false, "0", true, true},
		{"empty env, stderr TTY → color on", false, "", true, false},
		{"empty env, stderr piped → color off", false, "", false, true},
		// The bug we fixed: stdout being redirected does not appear in
		// this decision because configureColor checks stderr only. The
		// caller can't represent stdout state here, which is intentional.
		{"stderr TTY wins regardless of stdout state", false, "", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shouldDisableColor(c.flag, c.env, c.stderrIsTTY)
			if got != c.want {
				t.Errorf("shouldDisableColor(flag=%v, env=%q, tty=%v) = %v, want %v",
					c.flag, c.env, c.stderrIsTTY, got, c.want)
			}
		})
	}
}
