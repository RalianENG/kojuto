package probe

import (
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

// ParseState tracks cross-line state during strace output parsing.
// Used to correlate events like file creation → deletion (anti-forensics).
type ParseState struct {
	// createdTmpFiles tracks files created via openat(O_CREAT) in suspicious
	// directories (/tmp, /dev/shm). Only unlinks of files that were created
	// during this scan are flagged as anti-forensics — pre-existing file
	// cleanup (pip temp dirs) is ignored.
	createdTmpFiles map[string]bool
}

// NewParseState creates a fresh parse state for a scan phase.
func NewParseState() *ParseState {
	return &ParseState{
		createdTmpFiles: make(map[string]bool),
	}
}

// straceOpenatCreateRe matches openat calls with O_CREAT flag for tracking
// file creation in temp directories.
var straceOpenatCreateRe = regexp.MustCompile(
	`openat\([^,]+,\s*"([^"]+)",\s*([A-Z_|]*O_CREAT[A-Z_|]*)`,
)

var (
	// Pattern: connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16).
	straceConnectRe = regexp.MustCompile(
		`connect\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet6?_addr\("([^"]+)"\)`,
	)

	// Pattern: sendto(3, ..., {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16).
	straceSendtoRe = regexp.MustCompile(
		`sendto\(\d+,.*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet6?_addr\("([^"]+)"\)`,
	)

	// Pattern: sendto(4, "...", 29, MSG_NOSIGNAL, NULL, 0) = 29
	// Connected-socket sendto (e.g. DNS via glibc on connected UDP socket).
	// No sockaddr — destination was set by prior connect().
	straceSendtoConnectedRe = regexp.MustCompile(
		`sendto\((\d+),\s*"([^"]*)",\s*\d+,\s*[^,]+,\s*NULL`,
	)

	// sendmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, ...}, 0).
	straceSendmsgRe = regexp.MustCompile(
		`sendmsg\(\d+,.*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet6?_addr\("([^"]+)"\)`,
	)

	// sendmmsg(3, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, ...}, ...}], ...).
	straceSendmmsgRe = regexp.MustCompile(
		`sendmmsg\(\d+,.*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet6?_addr\("([^"]+)"\)`,
	)

	// bind(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, 16).
	straceBindRe = regexp.MustCompile(
		`bind\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet6?_addr\("([^"]+)"\)`,
	)

	// listen(3, 5).
	straceListenRe = regexp.MustCompile(
		`listen\((\d+),\s*(\d+)\)`,
	)

	// accept(3, {sa_family=AF_INET, ...}, ...) or accept4(...)
	straceAcceptRe = regexp.MustCompile(
		`accept4?\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet6?_addr\("([^"]+)"\)`,
	)

	// execve("/usr/bin/curl", ["curl", "http://evil.com"], ...)
	straceExecveRe = regexp.MustCompile(
		`execve\("([^"]+)",\s*\[([^\]]+)\]`,
	)

	// openat(AT_FDCWD, "/home/dev/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 3.
	straceOpenatRe = regexp.MustCompile(
		`openat\([^,]+,\s*"([^"]+)",\s*([A-Z_|]+)`,
	)

	// rename("/tmp/evil", "/usr/local/bin/python3") = 0.
	straceRenameRe = regexp.MustCompile(
		`rename\("([^"]+)",\s*"([^"]+)"\)`,
	)

	// renameat(AT_FDCWD, "old", AT_FDCWD, "new") or renameat2(...)
	straceRenameatRe = regexp.MustCompile(
		`renameat2?\([^,]+,\s*"([^"]+)",\s*[^,]+,\s*"([^"]+)"`,
	)

	// mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f...
	// Only match calls that include both PROT_WRITE and PROT_EXEC (RWX).
	// Normal .so loading uses PROT_READ|PROT_EXEC (no WRITE).
	// V8 JIT classically uses W^X (RW then mprotect to RX), but recent
	// Node/Bun/Deno builds — especially under containers without PKU/MTE
	// — fall back to a code range that does emit simultaneous RWX,
	// producing memory_execution false positives on every node-driven
	// scan. See follow-up issue (interpreter-PID tracking) for the
	// permanent fix; the current detection still catches ffi-napi /
	// ctypes shellcode patterns that are the more common attack vector.
	straceMmapRWXRe = regexp.MustCompile(
		`mmap\([^,]*,\s*\d+,\s*(PROT_[A-Z_|]+PROT_WRITE[A-Z_|]*PROT_EXEC[A-Z_|]*|PROT_[A-Z_|]*PROT_EXEC[A-Z_|]*PROT_WRITE[A-Z_|]*),\s*([A-Z_|]+)`,
	)

	// mprotect(0x7f..., 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = 0
	// Changing memory permissions to include both WRITE and EXEC. Same
	// caveat as straceMmapRWXRe above re: V8 JIT noise.
	straceMprotectRWXRe = regexp.MustCompile(
		`mprotect\(0x[0-9a-f]+,\s*\d+,\s*(PROT_[A-Z_|]+PROT_WRITE[A-Z_|]*PROT_EXEC[A-Z_|]*|PROT_[A-Z_|]*PROT_EXEC[A-Z_|]*PROT_WRITE[A-Z_|]*)`,
	)

	// unlink("/tmp/.ld-linux-x86-64.py") = 0.
	straceUnlinkRe = regexp.MustCompile(
		`unlink\("([^"]+)"\)`,
	)

	// unlinkat(AT_FDCWD, "/tmp/payload", 0) = 0
	// Excludes AT_REMOVEDIR (directory removal by pip/npm is benign).
	straceUnlinkatRe = regexp.MustCompile(
		`unlinkat\([^,]+,\s*"([^"]+)",\s*0\)`,
	)

	// ptrace(PTRACE_TRACEME, ...) = -1 EPERM — anti-debugging evasion attempt.
	stracePtraceTracemeRe = regexp.MustCompile(
		`ptrace\(PTRACE_TRACEME`,
	)
)

// sensitivePathPatterns are substrings that indicate access to credential or
// secret files. Only openat calls matching these patterns are emitted as events
// to avoid flooding the event channel with thousands of benign file opens
// during package installation.
//
// This is initialized to a minimal fallback. Call SetSensitivePaths to load
// the full set from config (including user customizations).
var sensitivePathPatterns = []string{
	"/.ssh/",
	"/.gnupg/",
	"/.aws/",
	"/etc/shadow",
	"/proc/self/environ",
	"/.netrc",
	"/.git-credentials",
	"/.docker/config.json",
	"/.config/gh/",
}

// SetSensitivePaths replaces the sensitive path patterns used by the parser.
// Must be called exactly once at startup (from PreRunE) before any parsing
// begins. Not safe for concurrent use.
func SetSensitivePaths(patterns []string) {
	sensitivePathPatterns = patterns
}

// isUserHomePath returns true if the path is inside a user home directory.
// In the sandbox, /home/ is where honeypot files live. pip/npm never write
// here — their legitimate targets are site-packages, /usr/local/bin, /tmp,
// and /install. Any write to /home/ is malicious (persistence, credential
// tampering, config injection, etc.) regardless of the specific filename.
func isUserHomePath(filePath string) bool {
	return strings.HasPrefix(filePath, "/home/") || strings.HasPrefix(filePath, "/root/")
}

// procPidRe matches /proc/<numeric-pid>/ paths (e.g. /proc/10/comm).
// Reading other processes' /proc entries is a sandbox detection technique
// (checking the tracer process name via /proc/<TracerPid>/comm).
var procPidRe = regexp.MustCompile(`^/proc/\d+/`)

func isSensitivePath(filePath string) bool {
	for _, pattern := range sensitivePathPatterns {
		if strings.Contains(filePath, pattern) {
			return true
		}
	}
	// /proc/<pid>/* (not /proc/self/*) — reading another process's info
	// is a sandbox detection vector (tracer name lookup).
	if procPidRe.MatchString(filePath) {
		return true
	}
	return false
}

func parseStraceLine(line string, state *ParseState) (types.SyscallEvent, bool) {
	// Audit hook output from sitecustomize.py / kojuto-require.js.
	// These lines are interleaved with strace output on stderr.
	if evt, ok := parseAuditHook(line); ok {
		return evt, true
	}

	// Track file creation in suspicious dirs (side effect, no event emitted).
	trackTmpFileCreation(line, state)
	if evt, ok := parseConnectOrSendto(line, straceConnectRe, types.EventConnect); ok {
		return evt, true
	}

	if evt, ok := parseConnectOrSendto(line, straceSendtoRe, types.EventSendto); ok {
		// If port is 53, try to extract DNS query domain from the buffer.
		if evt.DstPort == 53 {
			evt.DNSQuery = extractDNSQuery(line)
		}
		return evt, true
	}

	// Connected-socket sendto: sendto(fd, "buf", len, flags, NULL, 0).
	// glibc's resolver uses connect(fd, {DNS:53}) then sendto(fd, query, ..., NULL).
	// The sockaddr is absent, but the buffer contains the DNS wire-format query.
	if evt, ok := parseConnectedSendtoDNS(line); ok {
		return evt, true
	}

	if evt, ok := parseConnectOrSendto(line, straceSendmsgRe, types.EventSendmsg); ok {
		return evt, true
	}

	if evt, ok := parseConnectOrSendto(line, straceSendmmsgRe, types.EventSendmmsg); ok {
		return evt, true
	}

	if evt, ok := parseConnectOrSendto(line, straceBindRe, types.EventBind); ok {
		return evt, true
	}

	if evt, ok := parseListen(line); ok {
		return evt, true
	}

	if evt, ok := parseConnectOrSendto(line, straceAcceptRe, types.EventAccept); ok {
		return evt, true
	}

	if evt, ok := parseExecve(line); ok {
		return evt, true
	}

	if evt, ok := parseOpenat(line); ok {
		return evt, true
	}

	if evt, ok := parseRename(line); ok {
		return evt, true
	}

	if evt, ok := parsePtraceTraceme(line); ok {
		return evt, true
	}

	if evt, ok := parseMmapRWX(line); ok {
		return evt, true
	}

	if evt, ok := parseMprotectRWX(line); ok {
		return evt, true
	}

	if evt, ok := parseUnlink(line, state); ok {
		return evt, true
	}

	return types.SyscallEvent{}, false
}

// systemBinaries are names that benignPaths trusts in /usr/local/bin/ or
// /usr/bin/.  A write to any of these paths is a binary hijack attempt:
// the attacker overwrites a trusted binary so that subsequent execve of
// the same path passes the benignPaths whitelist.
var systemBinaries = map[string]bool{
	"python": true, "python3": true, "python3.12": true,
	"node": true, "npm": true, "npx": true,
	"pip": true, "pip3": true,
	"sh": true, "bash": true, "dash": true,
	"env": true,
}

// isSystemBinaryWrite returns true if the path is a write to a known
// system binary location (e.g. /usr/local/bin/python3).
func isSystemBinaryWrite(filePath string) bool {
	base := filePath
	if idx := strings.LastIndex(filePath, "/"); idx >= 0 {
		base = filePath[idx+1:]
	}
	if !systemBinaries[base] {
		return false
	}
	return strings.HasPrefix(filePath, "/usr/local/bin/") ||
		strings.HasPrefix(filePath, "/usr/bin/") ||
		strings.HasPrefix(filePath, "/bin/")
}

// parseOpenat emits events for:
//  1. Sensitive file paths (credentials, keys, etc.) — any access mode.
//  2. ANY write to the user home directory (/home/) — pip/npm never write here.
//  3. Writes to system binary paths — binary hijack for benignPaths bypass.
func parseOpenat(line string) (types.SyscallEvent, bool) {
	matches := straceOpenatRe.FindStringSubmatch(line)
	if matches == nil {
		return types.SyscallEvent{}, false
	}

	filePath := matches[1]
	var flags string
	if len(matches) > 2 {
		flags = matches[2]
	}

	isWrite := strings.Contains(flags, "O_WRONLY") ||
		strings.Contains(flags, "O_RDWR") ||
		strings.Contains(flags, "O_CREAT")

	// Emit if: sensitive path, write to user home, OR write to system binary.
	if !isSensitivePath(filePath) &&
		(!isWrite || !isUserHomePath(filePath)) &&
		(!isWrite || !isSystemBinaryWrite(filePath)) {
		return types.SyscallEvent{}, false
	}

	return types.SyscallEvent{
		Timestamp: time.Now().UTC(),
		PID:       extractPID(line),
		Syscall:   types.EventOpenat,
		FilePath:  filePath,
		OpenFlags: flags,
	}, true
}

// parseRename handles rename, renameat, and renameat2 syscalls.
// SrcPath holds the source, DstPath holds the destination for analyzer inspection.
func parseRename(line string) (types.SyscallEvent, bool) {
	// Try rename("old", "new").
	if matches := straceRenameRe.FindStringSubmatch(line); matches != nil {
		return types.SyscallEvent{
			Timestamp: time.Now().UTC(),
			PID:       extractPID(line),
			Syscall:   types.EventRename,
			SrcPath:   matches[1],
			DstPath:   matches[2],
		}, true
	}

	// Try renameat/renameat2(dirfd, "old", dirfd, "new").
	if matches := straceRenameatRe.FindStringSubmatch(line); matches != nil {
		return types.SyscallEvent{
			Timestamp: time.Now().UTC(),
			PID:       extractPID(line),
			Syscall:   types.EventRename,
			SrcPath:   matches[1],
			DstPath:   matches[2],
		}, true
	}

	return types.SyscallEvent{}, false
}

// parsePtraceTraceme detects ptrace(PTRACE_TRACEME) calls in strace output.
// Under strace, the traced process's own PTRACE_TRACEME returns EPERM because
// it is already being traced. Malware uses this to detect tracing and suppress
// malicious behavior. Any PTRACE_TRACEME call during install/import is suspicious.
func parsePtraceTraceme(line string) (types.SyscallEvent, bool) {
	if !stracePtraceTracemeRe.MatchString(line) {
		return types.SyscallEvent{}, false
	}

	return types.SyscallEvent{
		Timestamp: time.Now().UTC(),
		PID:       extractPID(line),
		Syscall:   types.EventPtrace,
		Comm:      "ptrace(PTRACE_TRACEME)",
	}, true
}

// parseMmapRWX detects mmap calls with simultaneous PROT_WRITE and PROT_EXEC.
// This combination (RWX) on anonymous mappings is the hallmark of shellcode
// injection: allocate writable+executable memory, write shellcode, jump to it.
//
// Normal shared library loading uses PROT_READ|PROT_EXEC (no WRITE).
// V8 JIT uses W^X: PROT_READ|PROT_WRITE first, then mprotect to PROT_READ|PROT_EXEC.
// Neither produces simultaneous RWX.
func parseMmapRWX(line string) (types.SyscallEvent, bool) {
	matches := straceMmapRWXRe.FindStringSubmatch(line)
	if matches == nil {
		return types.SyscallEvent{}, false
	}

	// Skip failed calls.
	if strings.Contains(line, "= -1 ") || strings.Contains(line, "MAP_FAILED") {
		return types.SyscallEvent{}, false
	}

	prot := matches[1]
	flags := matches[2]

	return types.SyscallEvent{
		Timestamp: time.Now().UTC(),
		PID:       extractPID(line),
		Syscall:   types.EventMmap,
		MemProt:   prot,
		MemFlags:  flags,
	}, true
}

// parseMprotectRWX detects mprotect calls that set simultaneous WRITE+EXEC.
// This indicates a memory region being made both writable and executable,
// which is a classic shellcode injection pattern (modify code in place).
func parseMprotectRWX(line string) (types.SyscallEvent, bool) {
	matches := straceMprotectRWXRe.FindStringSubmatch(line)
	if matches == nil {
		return types.SyscallEvent{}, false
	}

	if strings.Contains(line, "= -1 ") {
		return types.SyscallEvent{}, false
	}

	return types.SyscallEvent{
		Timestamp: time.Now().UTC(),
		PID:       extractPID(line),
		Syscall:   types.EventMprotect,
		MemProt:   matches[1],
	}, true
}

// suspiciousUnlinkDirs are directories where file deletion indicates
// anti-forensics (stage-2 payload self-deletion after execution).
var suspiciousUnlinkDirs = []string{
	"/tmp/",
	"/dev/shm/",
	"/var/tmp/",
	"/run/",
}

// trackTmpFileCreation records file creation in suspicious directories.
// Called as a side effect on every strace line — no event is emitted.
// The created paths are used by parseUnlink to distinguish malware
// payload self-deletion from pre-existing file cleanup.
func trackTmpFileCreation(line string, state *ParseState) {
	matches := straceOpenatCreateRe.FindStringSubmatch(line)
	if matches == nil {
		return
	}

	filePath := matches[1]

	// Skip failed calls.
	if strings.Contains(line, "= -1 ") {
		return
	}

	for _, dir := range suspiciousUnlinkDirs {
		if strings.HasPrefix(filePath, dir) {
			state.createdTmpFiles[filePath] = true
			return
		}
	}
}

// parseUnlink detects unlink/unlinkat of files that were CREATED during
// the current scan. This is the create→delete anti-forensics pattern:
//
//  1. Malware drops payload:  openat("/tmp/ld.py", O_CREAT|O_WRONLY)
//  2. Malware executes it:    execve("/tmp/ld.py", ...)
//  3. Malware deletes it:     unlink("/tmp/ld.py")  ← detected here
//
// Pre-existing files cleaned up by pip/npm are NOT flagged because they
// were not created (openat O_CREAT) during this scan.
func parseUnlink(line string, state *ParseState) (types.SyscallEvent, bool) {
	var filePath string

	if matches := straceUnlinkRe.FindStringSubmatch(line); matches != nil {
		filePath = matches[1]
	} else if matches := straceUnlinkatRe.FindStringSubmatch(line); matches != nil {
		filePath = matches[1]
	}

	if filePath == "" {
		return types.SyscallEvent{}, false
	}

	// Skip failed calls.
	if strings.Contains(line, "= -1 ") {
		return types.SyscallEvent{}, false
	}

	// Only flag files that were CREATED during this scan (create→delete pair).
	// This eliminates false positives from pip/npm cleaning up pre-existing
	// temp files while catching malware payload self-deletion.
	if !state.createdTmpFiles[filePath] {
		return types.SyscallEvent{}, false
	}

	return types.SyscallEvent{
		Timestamp: time.Now().UTC(),
		PID:       extractPID(line),
		Syscall:   types.EventUnlink,
		FilePath:  filePath,
	}, true
}

func parseConnectOrSendto(line string, re *regexp.Regexp, syscall string) (types.SyscallEvent, bool) {
	matches := re.FindStringSubmatch(line)
	if matches == nil {
		return types.SyscallEvent{}, false
	}

	port, err := strconv.ParseUint(matches[1], 10, 16)
	if err != nil {
		return types.SyscallEvent{}, false
	}

	var family uint16 = 2 // AF_INET
	if strings.Contains(line, "AF_INET6") {
		family = 10
	}

	return types.SyscallEvent{
		Timestamp: time.Now().UTC(),
		PID:       extractPID(line),
		Syscall:   syscall,
		Family:    family,
		DstAddr:   matches[2],
		DstPort:   uint16(port),
	}, true
}

// execveFailedRe matches strace lines where execve returned an error
// (e.g. "= -1 ENOENT", "= -1 EACCES"). These are harmless PATH lookups.
var execveFailedRe = regexp.MustCompile(`=\s*-1\s+E[A-Z]+`)

func parseExecve(line string) (types.SyscallEvent, bool) {
	matches := straceExecveRe.FindStringSubmatch(line)
	if matches == nil {
		return types.SyscallEvent{}, false
	}

	// Skip failed execve calls that are harmless PATH search attempts
	// (ENOENT = file not found at /usr/bin/foo, then tries /bin/foo).
	// However, KEEP failed execve from suspicious directories (/tmp, /dev/shm)
	// — these indicate a payload execution attempt that was blocked by
	// permissions (EACCES) or seccomp. The attempt itself is evidence.
	if execveFailedRe.MatchString(line) {
		binaryPath := matches[1]
		isSuspiciousPath := strings.HasPrefix(binaryPath, "/tmp/") ||
			strings.HasPrefix(binaryPath, "/dev/shm/") ||
			strings.HasPrefix(binaryPath, "/var/tmp/")
		if !isSuspiciousPath {
			return types.SyscallEvent{}, false
		}
	}

	// matches[1] = binary path, matches[2] = argv list
	cmdline := strings.ReplaceAll(matches[2], "\"", "")
	cmdline = strings.ReplaceAll(cmdline, ", ", " ")

	return types.SyscallEvent{
		Timestamp: time.Now().UTC(),
		PID:       extractPID(line),
		Syscall:   types.EventExecve,
		Comm:      matches[1],
		Cmdline:   cmdline,
	}, true
}

// parseListen handles listen(fd, backlog) which has no sockaddr.
// Any listen call in a package install is suspicious (backdoor indicator).
func parseListen(line string) (types.SyscallEvent, bool) {
	if !straceListenRe.MatchString(line) {
		return types.SyscallEvent{}, false
	}

	return types.SyscallEvent{
		Timestamp: time.Now().UTC(),
		PID:       extractPID(line),
		Syscall:   types.EventListen,
	}, true
}

func extractPID(line string) uint32 {
	pidIdx := strings.Index(line, "[pid ")
	if pidIdx < 0 {
		return 0
	}

	pidStr := line[pidIdx+5:]

	endIdx := strings.Index(pidStr, "]")
	if endIdx <= 0 {
		return 0
	}

	p, err := strconv.ParseUint(pidStr[:endIdx], 10, 32)
	if err != nil {
		return 0
	}

	return uint32(p)
}

// parseConnectedSendtoDNS handles sendto on connected sockets (NULL dest addr).
// glibc's DNS resolver connects a UDP socket to the nameserver, then sends
// queries via sendto(fd, buf, len, flags, NULL, 0). The sockaddr is absent,
// so the standard sendto regex won't match. Instead we check the buffer
// for DNS wire-format content and extract the queried domain.
//
// Example strace line:
//
//	sendto(4, "e\27\1\0\0\1\0\0\0\0\0\0\7discord\3com\0\0\1\0\1", 29, MSG_NOSIGNAL, NULL, 0) = 29
func parseConnectedSendtoDNS(line string) (types.SyscallEvent, bool) {
	if !straceSendtoConnectedRe.MatchString(line) {
		return types.SyscallEvent{}, false
	}

	// Try to extract DNS domain from the buffer.
	domain := extractDNSQuery(line)
	if domain == "" {
		return types.SyscallEvent{}, false
	}

	return types.SyscallEvent{
		Timestamp: time.Now().UTC(),
		PID:       extractPID(line),
		Syscall:   types.EventSendto,
		DstAddr:   "127.0.0.11", // Docker embedded DNS (connected socket, addr not in strace)
		DstPort:   53,
		DNSQuery:  domain,
	}, true
}

// straceSendtoBufRe captures the buffer content from sendto() output.
// strace format: sendto(4, "...", len, flags, {sockaddr}).
var straceSendtoBufRe = regexp.MustCompile(`sendto\(\d+,\s*"([^"]*)"`)

// extractDNSQuery parses the DNS wire-format query domain from a sendto strace line.
// DNS wire format: [header 12 bytes][question: label-length-prefixed name, type, class]
// strace renders the buffer as C-escaped bytes: \x06google\x03com\0 → "google.com".
func extractDNSQuery(line string) string {
	matches := straceSendtoBufRe.FindStringSubmatch(line)
	if matches == nil {
		return ""
	}

	raw := unescapeStraceBuf(matches[1])
	if len(raw) < 13 { // 12-byte header + at least 1 byte question.
		return ""
	}

	// Skip 12-byte DNS header, parse question name.
	return parseDNSName(raw[12:])
}

// unescapeStraceBuf converts strace's C-escaped buffer representation to bytes.
// Handles: \xNN (hex), \NNN or \N (octal), \n, \t, \r, \\, and literal ASCII.
func unescapeStraceBuf(s string) []byte {
	var buf []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			buf = append(buf, s[i])
			continue
		}
		if i+1 >= len(s) {
			break
		}
		switch {
		case s[i+1] == 'x' && i+4 <= len(s):
			b, err := hex.DecodeString(s[i+2 : i+4])
			if err == nil && len(b) == 1 {
				buf = append(buf, b[0])
				i += 3
				continue
			}
			buf = append(buf, s[i])
		case s[i+1] >= '0' && s[i+1] <= '7':
			// Octal escape: \0, \00, \000, \1, \12, \123, etc.
			val := 0
			j := i + 1
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				val = val*8 + int(s[j]-'0')
				j++
			}
			buf = append(buf, byte(val))
			i = j - 1
		case s[i+1] == 'n':
			buf = append(buf, '\n')
			i++
		case s[i+1] == 't':
			buf = append(buf, '\t')
			i++
		case s[i+1] == 'r':
			buf = append(buf, '\r')
			i++
		case s[i+1] == '\\':
			buf = append(buf, '\\')
			i++
		default:
			buf = append(buf, s[i])
		}
	}
	return buf
}

// parseDNSName reads a DNS wire-format label sequence from the question section.
// Each label is preceded by its length byte. The sequence ends with a 0-byte.
// Example: [6]google[3]com[0] → "google.com".
func parseDNSName(data []byte) string {
	var labels []string
	i := 0
	for i < len(data) {
		labelLen := int(data[i])
		if labelLen == 0 {
			break
		}
		// Sanity: label length must be 1-63 per RFC 1035.
		if labelLen > 63 || i+1+labelLen > len(data) {
			break
		}
		labels = append(labels, string(data[i+1:i+1+labelLen]))
		i += 1 + labelLen
	}
	if len(labels) == 0 {
		return ""
	}
	return strings.Join(labels, ".")
}

// auditHookPrefix is the line prefix emitted by kojuto's audit hooks
// (sitecustomize.py for Python, kojuto-require.js for Node.js).
const auditHookPrefix = "KOJUTO:"

// benignAuditModules lists module prefixes whose import/compile/exec events
// are normal interpreter or tooling internals.
var benignAuditModules = []string{
	"_distutils_hack",
	"pip",
	"setuptools",
	"wheel",
	"pkg_resources",
	"_pytest",
	"npm",
	"node_modules",
	"sitecustomize",
	"kojuto-require",
	"usercustomize",
}

// benignAuditPaths lists path substrings that identify standard library,
// interpreter-internal, or kojuto's own probe scripts.  compile/exec events
// whose filename contains one of these are benign.
var benignAuditPaths = []string{
	"/usr/local/lib/python",
	"/usr/lib/python",
	"<frozen ",
	"/usr/local/bin/",
	"/usr/bin/",
	"importlib",
	"_kojuto_probe_",
}

// benignStringSnippetPrefixes are snippet prefixes that are benign when the
// filename is "<string>" — these are standard library internals like
// namedtuple factories, dataclass code generation, etc.
var benignStringSnippetPrefixes = []string{
	"lambda _cls",           // namedtuple factory
	"def __",                // dataclass generated methods
	"b'lambda _cls",         // bytes variant
	"b'def __create_fn__",   // dataclass code gen
	"b\"def __create_fn__",  // dataclass code gen (double-quote)
	"b'def raise_from",      // pip vendored raise_from helper
	"b\"def raise_from",     // raise_from (double-quote variant)
	"<code object <module>", // exec of stdlib code objects
}

// parseAuditHook parses a KOJUTO: prefixed line emitted by the Python or
// Node.js audit hook.
//
// Python compile/exec format: KOJUTO:<event>:<filename>:<snippet>
// Python import format:       KOJUTO:import:<module_name>
// Node.js format:             KOJUTO:<event>:<snippet>.
func parseAuditHook(line string) (types.SyscallEvent, bool) {
	if !strings.HasPrefix(line, auditHookPrefix) {
		return types.SyscallEvent{}, false
	}

	rest := line[len(auditHookPrefix):]
	idx := strings.Index(rest, ":")
	if idx < 0 {
		return types.SyscallEvent{}, false
	}

	event := rest[:idx]
	payload := rest[idx+1:]

	// For compile/exec, payload is "filename:snippet".
	// For import/ctypes.dlopen and Node.js events, payload is the snippet itself.
	var filename, snippet string
	switch event {
	case "compile", "exec":
		if colonIdx := strings.Index(payload, ":"); colonIdx >= 0 {
			filename = payload[:colonIdx]
			snippet = payload[colonIdx+1:]
		} else {
			snippet = payload
		}
	default:
		snippet = payload
	}

	// Filter benign interpreter/tooling internals.
	if isBenignAuditEvent(event, filename, snippet) {
		return types.SyscallEvent{}, false
	}

	return types.SyscallEvent{
		Timestamp:   time.Now(),
		Syscall:     types.EventDynamicExec,
		AuditEvent:  event,
		FilePath:    filename,
		CodeSnippet: snippet,
	}, true
}

// isBenignAuditEvent returns true for audit events generated by the Python/
// Node.js standard library, pip, npm, setuptools, or other interpreter
// internals.  For compile/exec events the filename field provides the
// definitive signal: anything outside site-packages or /tmp is benign.
// nodeAuditEvents are events emitted by kojuto-require.js.
// These never have a filename and should NOT be filtered by the
// Python-specific <string>/short-snippet heuristics.
var nodeAuditEvents = map[string]bool{
	"eval":                true,
	"Function":            true,
	"vm.runInNewContext":  true,
	"vm.runInThisContext": true,
	"vm.Script":           true,
}

func isBenignAuditEvent(event, filename, snippet string) bool {
	// All import events are benign — suspicious imports are already
	// caught by the openat/execve monitors.
	if event == "import" {
		return true
	}

	// Node.js audit events (eval/Function/vm) are always suspicious.
	// They have no filename and must not fall through to the Python
	// <string> short-snippet filter.
	if nodeAuditEvents[event] {
		return false
	}

	// compile/exec: if filename is available, use it as the primary filter.
	// Standard library, pip internals, and frozen modules are benign.
	if filename != "" {
		for _, pathMarker := range benignAuditPaths {
			if strings.Contains(filename, pathMarker) {
				return true
			}
		}
		// Known tooling modules.
		for _, mod := range benignAuditModules {
			if strings.Contains(filename, mod) {
				return true
			}
		}
	}

	// Fallback: filter by snippet content when filename is absent.
	for _, mod := range benignAuditModules {
		if strings.Contains(snippet, mod) {
			return true
		}
	}

	// "None" or empty snippet = compile(None) from frozen modules.
	if snippet == "None" || snippet == "" {
		return true
	}

	// <string> filename: filter known-benign patterns and short internal
	// compile() calls from the stdlib.
	if filename == "<string>" || filename == "" {
		for _, prefix := range benignStringSnippetPrefixes {
			if strings.HasPrefix(snippet, prefix) {
				return true
			}
		}

		// CPython internally compiles short expressions (type names, format
		// specs) from <string>.  These appear as b'...' with very short
		// content.  Real attack payloads via exec/eval are significantly
		// longer.  Threshold: snippets under 60 chars from <string> are
		// almost certainly interpreter internals.
		if len(snippet) < 60 {
			return true
		}

		// Unknown code from <string> — suspicious.
		return false
	}

	return false
}
