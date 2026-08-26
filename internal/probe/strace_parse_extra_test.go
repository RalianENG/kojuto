package probe

import (
	"strings"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

func TestParseStraceLine_Sendmsg(t *testing.T) {
	line := `[pid 600] sendmsg(5, {msg_name={sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("10.0.0.1")}, msg_namelen=16, msg_iov=[{iov_base="...", iov_len=100}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 100`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected sendmsg parse to succeed")
	}

	if evt.Syscall != types.EventSendmsg {
		t.Errorf("expected syscall sendmsg, got %s", evt.Syscall)
	}

	if evt.DstAddr != "10.0.0.1" {
		t.Errorf("expected addr 10.0.0.1, got %s", evt.DstAddr)
	}

	if evt.DstPort != 443 {
		t.Errorf("expected port 443, got %d", evt.DstPort)
	}

	if evt.PID != 600 {
		t.Errorf("expected pid 600, got %d", evt.PID)
	}
}

func TestParseStraceLine_Sendmmsg(t *testing.T) {
	line := `[pid 700] sendmmsg(6, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.4.4")}, msg_namelen=16, msg_iov=[{...}], msg_iovlen=1}, msg_len=40}], 1, 0) = 1`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected sendmmsg parse to succeed")
	}

	if evt.Syscall != types.EventSendmmsg {
		t.Errorf("expected syscall sendmmsg, got %s", evt.Syscall)
	}

	if evt.DstAddr != "8.8.4.4" {
		t.Errorf("expected addr 8.8.4.4, got %s", evt.DstAddr)
	}

	if evt.DstPort != 53 {
		t.Errorf("expected port 53, got %d", evt.DstPort)
	}
}

func TestParseStraceLine_Bind(t *testing.T) {
	line := `[pid 800] bind(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, 16) = 0`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected bind parse to succeed")
	}

	if evt.Syscall != types.EventBind {
		t.Errorf("expected syscall bind, got %s", evt.Syscall)
	}

	if evt.DstAddr != "0.0.0.0" {
		t.Errorf("expected addr 0.0.0.0, got %s", evt.DstAddr)
	}

	if evt.DstPort != 4444 {
		t.Errorf("expected port 4444, got %d", evt.DstPort)
	}
}

func TestParseStraceLine_Listen(t *testing.T) {
	line := `[pid 900] listen(3, 5) = 0`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected listen parse to succeed")
	}

	if evt.Syscall != types.EventListen {
		t.Errorf("expected syscall listen, got %s", evt.Syscall)
	}

	if evt.PID != 900 {
		t.Errorf("expected pid 900, got %d", evt.PID)
	}
}

func TestParseStraceLine_Accept(t *testing.T) {
	line := `[pid 1000] accept(3, {sa_family=AF_INET, sin_port=htons(54321), sin_addr=inet_addr("192.168.1.100")}, [16]) = 4`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected accept parse to succeed")
	}

	if evt.Syscall != types.EventAccept {
		t.Errorf("expected syscall accept, got %s", evt.Syscall)
	}

	if evt.DstAddr != "192.168.1.100" {
		t.Errorf("expected addr 192.168.1.100, got %s", evt.DstAddr)
	}

	if evt.DstPort != 54321 {
		t.Errorf("expected port 54321, got %d", evt.DstPort)
	}
}

func TestParseStraceLine_Accept4(t *testing.T) {
	line := `[pid 1100] accept4(3, {sa_family=AF_INET, sin_port=htons(12345), sin_addr=inet_addr("10.0.0.2")}, [16], SOCK_CLOEXEC) = 5`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected accept4 parse to succeed")
	}

	if evt.Syscall != types.EventAccept {
		t.Errorf("expected syscall accept, got %s", evt.Syscall)
	}

	if evt.DstAddr != "10.0.0.2" {
		t.Errorf("expected addr 10.0.0.2, got %s", evt.DstAddr)
	}
}

func TestParseStraceLine_Sendmsg_IPv6(t *testing.T) {
	line := `[pid 1200] sendmsg(5, {msg_name={sa_family=AF_INET6, sin6_port=htons(443), sin6_addr=inet6_addr("2001:db8::1")}, msg_namelen=28, msg_iov=[{...}], msg_iovlen=1}, 0) = 50`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected IPv6 sendmsg parse to succeed")
	}

	if evt.Family != 10 {
		t.Errorf("expected family 10 (AF_INET6), got %d", evt.Family)
	}

	if evt.DstAddr != "2001:db8::1" {
		t.Errorf("expected addr 2001:db8::1, got %s", evt.DstAddr)
	}
}

func TestParseStraceLine_Bind_IPv6(t *testing.T) {
	line := `[pid 1300] bind(3, {sa_family=AF_INET6, sin6_port=htons(8080), sin6_addr=inet6_addr("::")}, 28) = 0`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected IPv6 bind parse to succeed")
	}

	if evt.Syscall != types.EventBind {
		t.Errorf("expected bind, got %s", evt.Syscall)
	}

	if evt.Family != 10 {
		t.Errorf("expected family 10, got %d", evt.Family)
	}

	if evt.DstAddr != "::" {
		t.Errorf("expected addr ::, got %s", evt.DstAddr)
	}
}

func TestParseStraceLine_OpenatGnupg(t *testing.T) {
	line := `[pid 1400] openat(AT_FDCWD, "/home/dev/.gnupg/secring.gpg", O_RDONLY) = 3`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected gnupg openat parse to succeed")
	}

	if evt.Syscall != types.EventOpenat {
		t.Errorf("expected openat, got %s", evt.Syscall)
	}

	if evt.FilePath != "/home/dev/.gnupg/secring.gpg" {
		t.Errorf("expected gnupg path, got %s", evt.FilePath)
	}
}

func TestParseStraceLine_OpenatNetrc(t *testing.T) {
	line := `[pid 1500] openat(AT_FDCWD, "/home/dev/.netrc", O_RDONLY) = 3`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected netrc openat parse to succeed")
	}

	if evt.FilePath != "/home/dev/.netrc" {
		t.Errorf("expected .netrc path, got %s", evt.FilePath)
	}
}

func TestParseStraceLine_OpenatConfigGh(t *testing.T) {
	line := `[pid 1600] openat(AT_FDCWD, "/home/dev/.config/gh/hosts.yml", O_RDONLY) = 3`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected gh config openat parse to succeed")
	}

	if evt.FilePath != "/home/dev/.config/gh/hosts.yml" {
		t.Errorf("expected gh config path, got %s", evt.FilePath)
	}
}

func TestParseClone(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantPID   uint32 // parent PID (0 = main strace target)
		wantChild uint32
		wantOK    bool
	}{
		{
			name:      "clone from main strace target",
			line:      `clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f...) = 12`,
			wantPID:   0,
			wantChild: 12,
			wantOK:    true,
		},
		{
			name:      "clone from child PID",
			line:      `[pid   220] clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS, child_tidptr=0x...) = 633`,
			wantPID:   220,
			wantChild: 633,
			wantOK:    true,
		},
		{
			name:      "clone3 with structured args",
			line:      `[pid   220] clone3({flags=CLONE_VM|CLONE_FS|CLONE_THREAD, child_tid=0x..., parent_tid=0x..., exit_signal=0, stack=0x..., stack_size=0x...}, 88) = 634`,
			wantPID:   220,
			wantChild: 634,
			wantOK:    true,
		},
		{
			name:      "vfork",
			line:      `[pid    50] vfork() = 51`,
			wantPID:   50,
			wantChild: 51,
			wantOK:    true,
		},
		{
			name:      "failed clone — negative return rejected by regex",
			line:      `[pid   220] clone(...) = -1 EAGAIN`,
			wantPID:   0,
			wantChild: 0,
			wantOK:    false,
		},
		{
			name:      "not a clone line",
			line:      `[pid   220] execve("/usr/bin/node", ["node"], ...) = 0`,
			wantPID:   0,
			wantChild: 0,
			wantOK:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt, ok := parseClone(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if evt.PID != tc.wantPID {
				t.Errorf("PID = %d, want %d", evt.PID, tc.wantPID)
			}
			if evt.ChildPID != tc.wantChild {
				t.Errorf("ChildPID = %d, want %d", evt.ChildPID, tc.wantChild)
			}
			if evt.Syscall != "clone" {
				t.Errorf("Syscall = %q, want %q", evt.Syscall, "clone")
			}
		})
	}
}

func TestExtractPID(t *testing.T) {
	cases := []struct {
		line string
		want uint32
	}{
		{`[pid 12345] connect(...)`, 12345},
		{`[pid 1] openat(...)`, 1},
		{`connect(...)`, 0},
		{`[pid abc] connect(...)`, 0},
		{`[pid ] connect(...)`, 0},
		// strace right-pads small PIDs with spaces to align columns.
		// Without TrimSpace handling, ParseUint would reject these and
		// every container PID (almost always small) would extract as
		// 0, silently disabling all PID-aware analysis downstream.
		{`[pid    12] mprotect(0x7f..., 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = 0`, 12},
		{`[pid     1] execve("/usr/bin/sh", ...) = 0`, 1},
		{`[pid   999] openat(AT_FDCWD, "/etc/passwd", ...) = 3`, 999},
	}

	for _, tc := range cases {
		got := extractPID(tc.line)
		if got != tc.want {
			t.Errorf("extractPID(%q) = %d, want %d", tc.line, got, tc.want)
		}
	}
}

func TestUnescapeStraceBuf_OctalAndSpecial(t *testing.T) {
	// Test octal escapes.
	input := `\101\102\103` // 'A', 'B', 'C' in octal.
	got := unescapeStraceBuf(input)
	if string(got) != "ABC" {
		t.Errorf("octal unescape = %q, want 'ABC'", string(got))
	}

	// Test special escapes.
	input2 := `hello\nworld\ttab\\slash`
	got2 := unescapeStraceBuf(input2)
	if string(got2) != "hello\nworld\ttab\\slash" {
		t.Errorf("special unescape = %q, want %q", string(got2), "hello\nworld\ttab\\slash")
	}

	// Test \r.
	input3 := `test\rvalue`
	got3 := unescapeStraceBuf(input3)
	if string(got3) != "test\rvalue" {
		t.Errorf("\\r unescape = %q, want %q", string(got3), "test\rvalue")
	}
}

func TestParseDNSName_TruncatedLabel(t *testing.T) {
	// Label length exceeds remaining data → should stop gracefully.
	data := []byte{10, 'a', 'b', 0} // claims 10 bytes but only 2 available
	got := parseDNSName(data)
	if got != "" {
		t.Errorf("expected empty for truncated label, got %q", got)
	}
}

func TestParseDNSName_LabelTooLong(t *testing.T) {
	// Label > 63 chars → should stop.
	data := []byte{64} // 64 > 63 max
	got := parseDNSName(data)
	if got != "" {
		t.Errorf("expected empty for oversized label, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// SetSensitivePaths
// ---------------------------------------------------------------------------

func TestSetSensitivePaths(t *testing.T) {
	orig := make([]string, len(sensitivePathPatterns))
	copy(orig, sensitivePathPatterns)
	defer SetSensitivePaths(orig)

	custom := []string{"/.custom/secret", "/.my/key"}
	SetSensitivePaths(custom)

	if !isSensitivePath("/home/dev/.custom/secret/file") {
		t.Error("expected custom path to be sensitive")
	}
	if isSensitivePath("/home/dev/.ssh/id_rsa") {
		t.Error("expected .ssh to NOT be sensitive after override")
	}
}

func TestParsePtraceTraceme(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "PTRACE_TRACEME failure",
			line: `[pid 123] ptrace(PTRACE_TRACEME) = -1 EPERM (Operation not permitted)`,
			want: true,
		},
		{
			name: "PTRACE_TRACEME success",
			line: `[pid 456] ptrace(PTRACE_TRACEME) = 0`,
			want: true,
		},
		{
			name: "PTRACE_ATTACH not matched",
			line: `[pid 789] ptrace(PTRACE_ATTACH, 100) = 0`,
			want: false,
		},
		{
			name: "unrelated syscall",
			line: `[pid 100] openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt, ok := parsePtraceTraceme(tc.line)
			if ok != tc.want {
				t.Errorf("parsePtraceTraceme(%q) = _, %v; want %v", tc.line, ok, tc.want)
			}
			if ok {
				if evt.Syscall != types.EventPtrace {
					t.Errorf("expected syscall %q, got %q", types.EventPtrace, evt.Syscall)
				}
			}
		})
	}
}

func TestParseStraceLine_PtraceTraceme(t *testing.T) {
	line := `[pid 500] ptrace(PTRACE_TRACEME) = -1 EPERM (Operation not permitted)`
	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected parseStraceLine to match ptrace line")
	}
	if evt.Syscall != types.EventPtrace {
		t.Errorf("expected syscall %q, got %q", types.EventPtrace, evt.Syscall)
	}
	if evt.PID != 500 {
		t.Errorf("expected PID 500, got %d", evt.PID)
	}
}

func TestAntiForensics_CreateExecuteDelete(t *testing.T) {
	// Simulate: malware creates /tmp/payload, executes it, deletes it.
	lines := []string{
		`openat(AT_FDCWD, "/tmp/.payload", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 3`,
		`[pid 10] execve("/tmp/.payload", ["/tmp/.payload"], 0xfff /* 7 vars */) = -1 EACCES (Permission denied)`,
		`unlinkat(AT_FDCWD, "/tmp/.payload", 0) = 0`,
	}

	state := NewParseState()
	var events []types.SyscallEvent
	for _, line := range lines {
		evt, ok := parseStraceLine(line, state)
		if ok {
			events = append(events, evt)
		}
	}

	// Should have: openat (sensitive? no, but tracked), execve, unlink
	var hasExecve, hasUnlink bool
	for _, e := range events {
		if e.Syscall == types.EventExecve && e.Comm == "/tmp/.payload" {
			hasExecve = true
		}
		if e.Syscall == types.EventUnlink && e.FilePath == "/tmp/.payload" {
			hasUnlink = true
		}
	}

	if !hasExecve {
		t.Error("expected execve event for /tmp/.payload (even EACCES)")
	}
	if !hasUnlink {
		t.Error("expected unlink event for /tmp/.payload (create→delete tracked)")
	}
}

func TestAntiForensics_PipTempNotFlagged(t *testing.T) {
	// pip creates and deletes temp files but never executes them.
	// Only the delete should appear; without a matching create in state, it won't.
	lines := []string{
		// pip temp file deleted WITHOUT prior openat(O_CREAT) in this session
		`unlinkat(AT_FDCWD, "/tmp/pip-build-tracker-abc123", 0) = 0`,
	}

	state := NewParseState()
	for _, line := range lines {
		evt, ok := parseStraceLine(line, state)
		if ok && evt.Syscall == types.EventUnlink {
			t.Error("unlink of file not created in this session should not be emitted")
		}
	}
}

func TestAntiForensics_CreateDeleteWithoutExecute(t *testing.T) {
	// File created and deleted but NOT executed — should still emit unlink
	// event (the execute check is in the analyzer, not the parser).
	lines := []string{
		`openat(AT_FDCWD, "/tmp/tempfile", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 3`,
		`unlinkat(AT_FDCWD, "/tmp/tempfile", 0) = 0`,
	}

	state := NewParseState()
	var hasUnlink bool
	for _, line := range lines {
		evt, ok := parseStraceLine(line, state)
		if ok && evt.Syscall == types.EventUnlink {
			hasUnlink = true
		}
	}

	if !hasUnlink {
		t.Error("expected unlink event for file created in same session")
	}
}

// --- mmap/mprotect tests ---

func TestParseMmapRWX(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			"rwx anonymous",
			`mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1234000000`,
			true,
		},
		{
			"rx only (normal .so load)",
			`mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f1234000000`,
			false,
		},
		{
			"rw only (normal alloc)",
			`mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1234000000`,
			false,
		},
		{
			"rwx failed",
			`mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1 ENOMEM`,
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evt, ok := parseStraceLine(tc.line, NewParseState())
			if ok != tc.want {
				t.Errorf("parseStraceLine(%q) = _, %v; want %v", tc.line[:60], ok, tc.want)
			}
			if ok && evt.Syscall != types.EventMmap {
				t.Errorf("expected syscall %q, got %q", types.EventMmap, evt.Syscall)
			}
			if ok && !strings.Contains(evt.MemProt, "PROT_WRITE") {
				t.Errorf("expected MemProt to contain PROT_WRITE, got %q", evt.MemProt)
			}
		})
	}
}

func TestParseMprotectRWX(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			"rwx mprotect",
			`mprotect(0x7f1234000000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = 0`,
			true,
		},
		{
			"rx only (V8 JIT W^X)",
			`mprotect(0x7f1234000000, 4096, PROT_READ|PROT_EXEC) = 0`,
			false,
		},
		{
			"rwx failed",
			`mprotect(0x7f1234000000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = -1 ENOMEM`,
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evt, ok := parseStraceLine(tc.line, NewParseState())
			if ok != tc.want {
				t.Errorf("parseStraceLine(%q) = _, %v; want %v", tc.line[:60], ok, tc.want)
			}
			if ok && evt.Syscall != types.EventMprotect {
				t.Errorf("expected syscall %q, got %q", types.EventMprotect, evt.Syscall)
			}
		})
	}
}

// --- connected-socket DNS tests ---

func TestParseConnectedSendtoDNS(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		want   bool
		domain string
	}{
		{
			"glibc resolver discord",
			`sendto(4, "e\27\1\0\0\1\0\0\0\0\0\0\7discord\3com\0\0\1\0\1", 29, MSG_NOSIGNAL, NULL, 0) = 29`,
			true,
			"discord.com",
		},
		{
			"glibc resolver telegram",
			`sendto(3, "Q\26\1\0\0\1\0\0\0\0\0\0\3api\10telegram\3org\0\0\1\0\1", 34, MSG_NOSIGNAL, NULL, 0) = 34`,
			true,
			"api.telegram.org",
		},
		{
			"non-DNS sendto with sockaddr (normal pattern)",
			`sendto(4, "hello", 5, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 5`,
			false, // has sockaddr → handled by straceSendtoRe, not connected pattern
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evt, ok := parseConnectedSendtoDNS(tc.line)
			if ok != tc.want {
				t.Errorf("got ok=%v, want %v", ok, tc.want)
			}
			if ok && evt.DNSQuery != tc.domain {
				t.Errorf("DNSQuery = %q, want %q", evt.DNSQuery, tc.domain)
			}
		})
	}
}

// --- isUserHomePath tests ---

func TestIsUserHomePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/home/dev/.bashrc", true},
		{"/home/user/.config/systemd/user/evil.service", true},
		{"/root/.ssh/id_rsa", true},
		{"/usr/local/lib/python3.12/site-packages/foo.py", false},
		{"/tmp/payload", false},
		{"/etc/shadow", false},
	}
	for _, tc := range tests {
		if got := isUserHomePath(tc.path); got != tc.want {
			t.Errorf("isUserHomePath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// --- /proc/<pid>/ detection tests ---

func TestIsSensitivePath_ProcPid(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/proc/self/status", true},  // in config patterns
		{"/proc/self/maps", true},    // in config patterns
		{"/proc/10/comm", true},      // numeric PID → procPidRe
		{"/proc/12345/status", true}, // numeric PID
		{"/proc/version", false},     // not sensitive
		{"/proc/meminfo", false},     // not sensitive
	}
	saved := sensitivePathPatterns
	defer func() { sensitivePathPatterns = saved }()
	SetSensitivePaths([]string{"/proc/self/status", "/proc/self/maps"})
	for _, tc := range tests {
		if got := isSensitivePath(tc.path); got != tc.want {
			t.Errorf("isSensitivePath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// --- openat home dir write test ---

func TestParseOpenat_HomeWrite(t *testing.T) {
	saved := sensitivePathPatterns
	defer func() { sensitivePathPatterns = saved }()
	SetSensitivePaths([]string{"/.ssh/"}) // minimal
	state := NewParseState()

	// Write to /home/ should be emitted even if not in sensitive paths
	line := `openat(AT_FDCWD, "/home/dev/.config/systemd/user/evil.service", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644) = 3`
	evt, ok := parseStraceLine(line, state)
	if !ok {
		t.Fatal("expected openat write to /home/ to be emitted")
	}
	if evt.Syscall != types.EventOpenat {
		t.Errorf("expected openat, got %s", evt.Syscall)
	}
	if evt.FilePath != "/home/dev/.config/systemd/user/evil.service" {
		t.Errorf("unexpected path: %s", evt.FilePath)
	}
}

func TestParseOpenat_HomeReadNotEmitted(t *testing.T) {
	saved := sensitivePathPatterns
	defer func() { sensitivePathPatterns = saved }()
	SetSensitivePaths([]string{}) // empty → only home write check applies
	state := NewParseState()

	// Read from /home/ that's not in sensitive paths → NOT emitted
	line := `openat(AT_FDCWD, "/home/dev/somefile.txt", O_RDONLY|O_CLOEXEC) = 3`
	_, ok := parseStraceLine(line, state)
	if ok {
		t.Error("read from /home/ not in sensitive paths should not be emitted")
	}
}

// ============================================================
// Audit hook tests
// ============================================================

func TestParseAuditHook_PythonCompile(t *testing.T) {
	line := "KOJUTO:compile:evil.py:b'import os\\nos.getcwd()'"
	evt, ok := parseAuditHook(line)
	if !ok {
		t.Fatal("expected audit hook parse to succeed")
	}
	if evt.Syscall != types.EventDynamicExec {
		t.Errorf("syscall = %q, want %q", evt.Syscall, types.EventDynamicExec)
	}
	if evt.AuditEvent != "compile" {
		t.Errorf("audit_event = %q, want compile", evt.AuditEvent)
	}
	if evt.FilePath != "evil.py" {
		t.Errorf("file_path = %q, want evil.py", evt.FilePath)
	}
	if evt.CodeSnippet != "b'import os\\nos.getcwd()'" {
		t.Errorf("code_snippet = %q", evt.CodeSnippet)
	}
}

func TestParseAuditHook_PythonExec(t *testing.T) {
	line := `KOJUTO:exec:evil.py:<code object <module> at 0x7f0fc81cd020, file "evil.py", line 1>`
	evt, ok := parseAuditHook(line)
	if !ok {
		t.Fatal("expected audit hook parse to succeed")
	}
	if evt.AuditEvent != "exec" {
		t.Errorf("audit_event = %q, want exec", evt.AuditEvent)
	}
	if evt.FilePath != "evil.py" {
		t.Errorf("file_path = %q, want evil.py", evt.FilePath)
	}
}

func TestParseAuditHook_NodeEval(t *testing.T) {
	line := "KOJUTO:eval:process.env.GITHUB_TOKEN"
	evt, ok := parseAuditHook(line)
	if !ok {
		t.Fatal("expected Node.js eval audit hook parse to succeed")
	}
	if evt.AuditEvent != "eval" {
		t.Errorf("audit_event = %q, want eval", evt.AuditEvent)
	}
	if evt.CodeSnippet != "process.env.GITHUB_TOKEN" {
		t.Errorf("code_snippet = %q", evt.CodeSnippet)
	}
}

func TestParseAuditHook_NodeFunction(t *testing.T) {
	line := "KOJUTO:Function:return process.env.AWS_SECRET_ACCESS_KEY"
	evt, ok := parseAuditHook(line)
	if !ok {
		t.Fatal("expected Function audit hook parse to succeed")
	}
	if evt.AuditEvent != "Function" {
		t.Errorf("audit_event = %q, want Function", evt.AuditEvent)
	}
}

func TestParseAuditHook_NodeVm(t *testing.T) {
	line := `KOJUTO:vm.runInNewContext:typeof process !== "undefined" && process.env.NPM_TOKEN`
	evt, ok := parseAuditHook(line)
	if !ok {
		t.Fatal("expected vm.runInNewContext audit hook parse to succeed")
	}
	if evt.AuditEvent != "vm.runInNewContext" {
		t.Errorf("audit_event = %q, want vm.runInNewContext", evt.AuditEvent)
	}
}

func TestParseAuditHook_NotKojutoLine(t *testing.T) {
	lines := []string{
		`[pid 100] connect(3, {sa_family=AF_INET}, 16) = 0`,
		`execve("/usr/bin/python3", ["python3"], ...) = 0`,
		`some random strace output`,
	}
	for _, line := range lines {
		_, ok := parseAuditHook(line)
		if ok {
			t.Errorf("non-KOJUTO line should not parse: %q", line)
		}
	}
}

func TestIsBenignAuditEvent_Import(t *testing.T) {
	// All import events are benign.
	if !isBenignAuditEvent("import", "", "os") {
		t.Error("import os should be benign")
	}
	if !isBenignAuditEvent("import", "", "malicious_package") {
		t.Error("all imports should be benign (caught by openat/execve)")
	}
}

func TestIsBenignAuditEvent_StdlibCompile(t *testing.T) {
	// compile from standard library path.
	if !isBenignAuditEvent("compile", "/usr/local/lib/python3.12/re/__init__.py", "b'...'") {
		t.Error("stdlib compile should be benign")
	}
	// compile from frozen module.
	if !isBenignAuditEvent("compile", "<frozen importlib>", "b'...'") {
		t.Error("frozen module compile should be benign")
	}
}

func TestIsBenignAuditEvent_DataclassCodegen(t *testing.T) {
	if !isBenignAuditEvent("compile", "<string>", `b"def __create_fn__(__dataclass_type_name__):\n..."`) {
		t.Error("dataclass codegen should be benign")
	}
}

func TestIsBenignAuditEvent_ShortStringSnippet(t *testing.T) {
	// Short snippets from <string> are interpreter internals.
	if !isBenignAuditEvent("compile", "<string>", "b'int'") {
		t.Error("short <string> snippet should be benign")
	}
}

func TestIsBenignAuditEvent_SuspiciousExec(t *testing.T) {
	// exec from a non-stdlib file should NOT be benign.
	if isBenignAuditEvent("exec", "evil.py", "<code object>") {
		t.Error("exec from evil.py should be suspicious")
	}
}

func TestIsBenignAuditEvent_NodeEventsNeverBenign(t *testing.T) {
	// Node.js audit events must never be filtered.
	nodeEvents := []string{"eval", "Function", "vm.runInNewContext", "vm.runInThisContext", "vm.Script"}
	for _, event := range nodeEvents {
		if isBenignAuditEvent(event, "", "short") {
			t.Errorf("Node.js event %q should never be benign", event)
		}
	}
}

func TestIsBenignAuditEvent_KojutoProbeScript(t *testing.T) {
	// kojuto's own probe scripts should be filtered.
	if !isBenignAuditEvent("exec", "/tmp/_kojuto_probe_win32.py", "<code object>") {
		t.Error("kojuto probe script should be benign")
	}
}

// "+" prefix is the wire marker emitted by sitecustomize.py when its
// frame walk located a user-controlled origin (the scanned package, or
// /tmp/install/home). Such events bypass the path-based benign list:
// the originator IS the audited code, regardless of where it lives.
func TestIsBenignAuditEvent_UserOriginMarker(t *testing.T) {
	// Site-packages path looks benign on its face but the "+" marker
	// says it's the scanned package — must report.
	if isBenignAuditEvent("exec", "+/usr/local/lib/python3.12/site-packages/evil_pkg/__init__.py", "<code object>") {
		t.Error("user-marked site-packages exec should be suspicious")
	}
	// Same path without the marker is benign (compat library doing
	// its own internal exec).
	if !isBenignAuditEvent("exec", "/usr/local/lib/python3.12/site-packages/six.py", "<code object>") {
		t.Error("unmarked site-packages exec should be benign")
	}
}

func TestParseAuditHook_StripsUserOriginMarker(t *testing.T) {
	// The "+" prefix is wire-protocol detail; FilePath in the parsed
	// event must not retain it.
	line := "KOJUTO:exec:+/usr/local/lib/python3.12/site-packages/evil_pkg/__init__.py:<code object>"
	evt, ok := parseAuditHook(line)
	if !ok {
		t.Fatal("expected audit hook parse to succeed")
	}
	if evt.FilePath != "/usr/local/lib/python3.12/site-packages/evil_pkg/__init__.py" {
		t.Errorf("FilePath = %q, want path without leading '+'", evt.FilePath)
	}
}

// ============================================================
// System binary write tests
// ============================================================

func TestIsSystemBinaryWrite(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/usr/local/bin/python3", true},
		{"/usr/local/bin/node", true},
		{"/usr/bin/sh", true},
		{"/usr/local/bin/pip", true},
		{"/bin/bash", true},
		{"/usr/local/bin/my-new-tool", false}, // not a system binary
		{"/tmp/python3", false},               // wrong directory
		{"/home/dev/python3", false},          // wrong directory
		{"/usr/local/bin/black", false},       // pip entry_point, not system binary
	}

	for _, tt := range tests {
		got := isSystemBinaryWrite(tt.path)
		if got != tt.want {
			t.Errorf("isSystemBinaryWrite(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestParseOpenat_SystemBinaryWrite(t *testing.T) {
	saved := sensitivePathPatterns
	defer func() { sensitivePathPatterns = saved }()
	SetSensitivePaths([]string{})
	state := NewParseState()

	// Write to /usr/local/bin/python3 — should be emitted.
	line := `openat(AT_FDCWD, "/usr/local/bin/python3", O_WRONLY|O_CREAT|O_TRUNC, 0755) = 3`
	evt, ok := parseStraceLine(line, state)
	if !ok {
		t.Fatal("write to system binary should be emitted")
	}
	if evt.FilePath != "/usr/local/bin/python3" {
		t.Errorf("file_path = %q", evt.FilePath)
	}

	// Read from /usr/local/bin/python3 — should NOT be emitted.
	readLine := `openat(AT_FDCWD, "/usr/local/bin/python3", O_RDONLY|O_CLOEXEC) = 3`
	_, ok = parseStraceLine(readLine, state)
	if ok {
		t.Error("read from system binary should not be emitted")
	}
}

func TestIsInstalledPackageWrite(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/install/node_modules/lodash/index.js", true},
		{"/install/node_modules/@babel/core/lib/index.js", true},
		// npm bookkeeping — never a real package, do not emit.
		{"/install/node_modules/.package-lock.json", false},
		{"/install/node_modules/.bin/foo", false},
		// Boundary cases.
		{"/install/node_modules/", false},
		{"/install/node_modules", false},
		{"/install/foo/bar", false},
		{"/home/dev/.npm/_logs/x.log", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := isInstalledPackageWrite(tc.path); got != tc.want {
				t.Errorf("isInstalledPackageWrite(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestParseOpenat_InstalledPackageWrite(t *testing.T) {
	saved := sensitivePathPatterns
	defer func() { sensitivePathPatterns = saved }()
	SetSensitivePaths([]string{})
	state := NewParseState()

	// Write to a package directory under /install/node_modules/ — emitted
	// so the analyzer can apply the library_hijacking rule.
	line := `openat(AT_FDCWD, "/install/node_modules/lodash/index.js", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3`
	evt, ok := parseStraceLine(line, state)
	if !ok {
		t.Fatal("write into installed package directory should be emitted")
	}
	if evt.FilePath != "/install/node_modules/lodash/index.js" {
		t.Errorf("file_path = %q", evt.FilePath)
	}

	// Read from a package directory — NOT emitted; the rule is about
	// placement (writes), and read events would flood every install.
	readLine := `openat(AT_FDCWD, "/install/node_modules/lodash/index.js", O_RDONLY|O_CLOEXEC) = 3`
	if _, ok := parseStraceLine(readLine, state); ok {
		t.Error("read from installed package directory must not be emitted")
	}

	// npm bookkeeping write — NOT emitted; .package-lock.json is npm
	// internal, not an attacker-installed package.
	bookkeeping := `openat(AT_FDCWD, "/install/node_modules/.package-lock.json", O_WRONLY|O_CREAT, 0644) = 3`
	if _, ok := parseStraceLine(bookkeeping, state); ok {
		t.Error("write to npm bookkeeping under node_modules/.<x> must not be emitted")
	}
}

func TestParseAuditHook_IntegratedWithParseStraceLine(t *testing.T) {
	state := NewParseState()

	// KOJUTO: line should be parsed by parseStraceLine via parseAuditHook.
	line := "KOJUTO:eval:require('child_process').execSync('whoami')"
	evt, ok := parseStraceLine(line, state)
	if !ok {
		t.Fatal("KOJUTO: line should be parsed by parseStraceLine")
	}
	if evt.Syscall != types.EventDynamicExec {
		t.Errorf("syscall = %q, want %q", evt.Syscall, types.EventDynamicExec)
	}
	if evt.AuditEvent != "eval" {
		t.Errorf("audit_event = %q, want eval", evt.AuditEvent)
	}
}

// TestParseStraceLine_RenameWithEscapedQuotes pins the security fix for
// the prior `"([^"]+)"` capture pattern, which silently dropped the
// rename event whenever a filename contained a literal `"` (escaped by
// strace as `\"`). Without an event the analyzer never sees the hijack
// and the verdict stays clean — a malicious package could rename
// `/tmp/x"y` over `/usr/local/bin/python3` invisibly.
func TestParseStraceLine_RenameWithEscapedQuotes(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantSrc string
		wantDst string
	}{
		{
			name:    "rename with escaped quote in src",
			line:    `[pid 100] rename("/tmp/x\"y", "/usr/local/bin/python3") = 0`,
			wantSrc: `/tmp/x\"y`,
			wantDst: "/usr/local/bin/python3",
		},
		{
			name:    "renameat with escaped quote in dst",
			line:    `[pid 101] renameat(AT_FDCWD, "/tmp/legit", AT_FDCWD, "/etc/x\"y") = 0`,
			wantSrc: "/tmp/legit",
			wantDst: `/etc/x\"y`,
		},
		{
			name:    "plain rename still parses",
			line:    `[pid 102] rename("/tmp/a", "/usr/local/bin/node") = 0`,
			wantSrc: "/tmp/a",
			wantDst: "/usr/local/bin/node",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt, ok := parseStraceLine(tc.line, NewParseState())
			if !ok {
				t.Fatalf("expected rename to parse, line=%q", tc.line)
			}
			if evt.Syscall != types.EventRename {
				t.Errorf("syscall = %q, want %q", evt.Syscall, types.EventRename)
			}
			if evt.SrcPath != tc.wantSrc {
				t.Errorf("SrcPath = %q, want %q", evt.SrcPath, tc.wantSrc)
			}
			if evt.DstPath != tc.wantDst {
				t.Errorf("DstPath = %q, want %q", evt.DstPath, tc.wantDst)
			}
		})
	}
}

// TestParseExecveat pins the three execveat shapes kojuto cares
// about. glibc 2.34+ routes ordinary path-based execve through
// execveat(AT_FDCWD, ...); the AT_EMPTY_PATH form is the fexecve /
// memfd-loader fileless-exec pattern; and fd-relative paths still
// produce a recorded event without matching suspiciousExecDirs.
func TestParseExecveat(t *testing.T) {
	cases := []struct {
		name        string
		line        string
		wantOK      bool
		wantComm    string
		wantPID     uint32
		wantCmdline string
	}{
		{
			name:        "AT_FDCWD path form (glibc 2.34+ execve)",
			line:        `[pid  100] execveat(AT_FDCWD, "/bin/sh", ["sh", "-c", "echo hi"], 0x7ffe..., 0) = 0`,
			wantOK:      true,
			wantComm:    "/bin/sh",
			wantPID:     100,
			wantCmdline: "sh -c echo hi",
		},
		{
			name:     "AT_EMPTY_PATH fexecve / memfd loader",
			line:     `[pid  200] execveat(3, "", ["payload"], 0x7ffe..., AT_EMPTY_PATH) = 0`,
			wantOK:   true,
			wantComm: "/proc/self/fd/3", // synthetic path so suspiciousExecDirs fires
			wantPID:  200,
		},
		{
			name:     "AT_EMPTY_PATH with two-digit fd",
			line:     `execveat(42, "", ["loader"], 0x7ffe..., AT_EMPTY_PATH) = 0`,
			wantOK:   true,
			wantComm: "/proc/self/fd/42",
			wantPID:  0,
		},
		{
			name:     "fd-relative subpath (rare, recorded as-is)",
			line:     `[pid  300] execveat(4, "bin/sh", ["sh"], 0x..., 0) = 0`,
			wantOK:   true,
			wantComm: "bin/sh",
			wantPID:  300,
		},
		{
			name:     "failed execveat from /tmp (kept — attempt is evidence)",
			line:     `[pid  400] execveat(AT_FDCWD, "/tmp/payload", ["p"], 0x..., 0) = -1 EACCES (Permission denied)`,
			wantOK:   true,
			wantComm: "/tmp/payload",
			wantPID:  400,
		},
		{
			name:   "failed execveat PATH-search — dropped",
			line:   `execveat(AT_FDCWD, "/usr/local/bin/foo", ["foo"], 0x..., 0) = -1 ENOENT (No such file or directory)`,
			wantOK: false,
		},
		{
			name:   "AT_FDCWD with empty path — malformed, dropped",
			line:   `execveat(AT_FDCWD, "", ["x"], 0x..., AT_EMPTY_PATH) = 0`,
			wantOK: false,
		},
		{
			name:   "not an execveat line",
			line:   `[pid  500] execve("/usr/bin/node", ["node"], ...) = 0`,
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt, ok := parseExecveat(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if evt.Syscall != types.EventExecve {
				t.Errorf("Syscall = %q, want %q", evt.Syscall, types.EventExecve)
			}
			if evt.Comm != tc.wantComm {
				t.Errorf("Comm = %q, want %q", evt.Comm, tc.wantComm)
			}
			if evt.PID != tc.wantPID {
				t.Errorf("PID = %d, want %d", evt.PID, tc.wantPID)
			}
			if tc.wantCmdline != "" && evt.Cmdline != tc.wantCmdline {
				t.Errorf("Cmdline = %q, want %q", evt.Cmdline, tc.wantCmdline)
			}
		})
	}
}
