package probe

import (
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

func TestParseStraceLine_Sendmsg(t *testing.T) {
	line := `[pid 600] sendmsg(5, {msg_name={sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("10.0.0.1")}, msg_namelen=16, msg_iov=[{iov_base="...", iov_len=100}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 100`

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
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

	evt, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected netrc openat parse to succeed")
	}

	if evt.FilePath != "/home/dev/.netrc" {
		t.Errorf("expected .netrc path, got %s", evt.FilePath)
	}
}

func TestParseStraceLine_OpenatConfigGh(t *testing.T) {
	line := `[pid 1600] openat(AT_FDCWD, "/home/dev/.config/gh/hosts.yml", O_RDONLY) = 3`

	evt, ok := parseStraceLine(line)
	if !ok {
		t.Fatal("expected gh config openat parse to succeed")
	}

	if evt.FilePath != "/home/dev/.config/gh/hosts.yml" {
		t.Errorf("expected gh config path, got %s", evt.FilePath)
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
