package probe

import "testing"

func TestParseStraceLine_IPv4(t *testing.T) {
	line := `[pid 12345] connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH`

	evt, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}

	if evt.DstPort != 443 {
		t.Errorf("expected port 443, got %d", evt.DstPort)
	}

	if evt.DstAddr != "93.184.216.34" {
		t.Errorf("expected addr 93.184.216.34, got %s", evt.DstAddr)
	}

	if evt.Family != 2 {
		t.Errorf("expected family 2 (AF_INET), got %d", evt.Family)
	}

	if evt.PID != 12345 {
		t.Errorf("expected pid 12345, got %d", evt.PID)
	}
}

func TestParseStraceLine_IPv6(t *testing.T) {
	line := `[pid 999] connect(5, {sa_family=AF_INET6, sin6_port=htons(80), sin6_addr=inet6_addr("::1")}, 28) = 0`

	evt, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}

	if evt.Family != 10 {
		t.Errorf("expected family 10 (AF_INET6), got %d", evt.Family)
	}

	if evt.DstAddr != "::1" {
		t.Errorf("expected addr ::1, got %s", evt.DstAddr)
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
