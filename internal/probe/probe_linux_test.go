//go:build linux

package probe

import "testing"

func TestFormatOpenFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  string
	}{
		{"read-only", 0, "O_RDONLY"},
		{"write-only", oWronly, "O_WRONLY"},
		{"read-write", oRdwr, "O_RDWR"},
		{"create + write", oWronly | oCreat, "O_WRONLY|O_CREAT"},
		{"create + truncate + write", oWronly | oCreat | oTrunc, "O_WRONLY|O_CREAT|O_TRUNC"},
		{"append + write", oWronly | oAppend, "O_WRONLY|O_APPEND"},
		{"cloexec only", oCloexec, "O_RDONLY|O_CLOEXEC"},
		{"nonblock + rdwr", oRdwr | oNonblock, "O_RDWR|O_NONBLOCK"},
		{"full write+create+trunc+cloexec", oWronly | oCreat | oTrunc | oCloexec, "O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatOpenFlags(tt.flags)
			if got != tt.want {
				t.Errorf("formatOpenFlags(%#x) = %q, want %q", tt.flags, got, tt.want)
			}
		})
	}
}

func TestFormatProt(t *testing.T) {
	tests := []struct {
		name string
		prot uint32
		want string
	}{
		{"none", 0, "PROT_NONE"},
		{"read only", protRead, "PROT_READ"},
		{"write only", protWrite, "PROT_WRITE"},
		{"exec only", protExec, "PROT_EXEC"},
		{"read+write", protRead | protWrite, "PROT_READ|PROT_WRITE"},
		{"read+exec (W^X executable phase)", protRead | protExec, "PROT_READ|PROT_EXEC"},
		{"write+exec (RWX shellcode hallmark)", protWrite | protExec, "PROT_WRITE|PROT_EXEC"},
		{"read+write+exec (full RWX)", protRead | protWrite | protExec, "PROT_READ|PROT_WRITE|PROT_EXEC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatProt(tt.prot)
			if got != tt.want {
				t.Errorf("formatProt(%#x) = %q, want %q", tt.prot, got, tt.want)
			}
		})
	}
}

// The analyzer classifyMemExec substring-matches on "PROT_WRITE" and "PROT_EXEC"
// to flag shellcode injection. Confirm both tokens are present in the RWX output
// so eBPF events produce the same reason strings as strace events.
func TestFormatProtRWXMatchesAnalyzerExpectations(t *testing.T) {
	got := formatProt(protRead | protWrite | protExec)
	if !contains(got, "PROT_WRITE") || !contains(got, "PROT_EXEC") {
		t.Errorf("formatProt RWX = %q, analyzer expects both PROT_WRITE and PROT_EXEC tokens", got)
	}
}

func TestFormatMmapFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  string
	}{
		{"private", mapPrivate, "MAP_PRIVATE"},
		{"shared", mapShared, "MAP_SHARED"},
		{"private+anonymous (shellcode mapping)", mapPrivate | mapAnonymous, "MAP_PRIVATE|MAP_ANONYMOUS"},
		{"private+anonymous+fixed", mapPrivate | mapAnonymous | mapFixed, "MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS"},
		{"empty (unknown flags only)", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatMmapFlags(tt.flags)
			if got != tt.want {
				t.Errorf("formatMmapFlags(%#x) = %q, want %q", tt.flags, got, tt.want)
			}
		})
	}
}

func TestIsSuspiciousTmpPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Suspicious — under monitored tmp dirs.
		{"/tmp/payload.sh", true},
		{"/tmp/ld.py", true},
		{"/dev/shm/stage2", true},
		{"/var/tmp/exploit", true},
		{"/run/malware", true},

		// Not suspicious — outside monitored dirs.
		{"/home/user/.bashrc", false},
		{"/etc/passwd", false},
		{"/usr/local/bin/python3", false},
		{"/root/.ssh/id_rsa", false},

		// Edge cases that must NOT match.
		{"/tmpfiles/normal", false},   // prefix collision: /tmp vs /tmpfiles
		{"/var/log/syslog", false},    // /var but not /var/tmp
		{"/runtime/app", false},       // /run prefix collision
		{"", false},                   // empty path
		{"/t", false},                 // too short to match
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isSuspiciousTmpPath(tt.path)
			if got != tt.want {
				t.Errorf("isSuspiciousTmpPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
