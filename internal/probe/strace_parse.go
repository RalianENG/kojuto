package probe

import (
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
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

func isSensitivePath(filePath string) bool {
	for _, pattern := range sensitivePathPatterns {
		if strings.Contains(filePath, pattern) {
			return true
		}
	}
	return false
}

func parseStraceLine(line string) (types.SyscallEvent, bool) {
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

	return types.SyscallEvent{}, false
}

// parseOpenat emits events only for sensitive file paths (credentials, keys, etc.).
// Package installs generate thousands of openat calls; pre-filtering here avoids
// overwhelming the event channel and analyzer.
func parseOpenat(line string) (types.SyscallEvent, bool) {
	matches := straceOpenatRe.FindStringSubmatch(line)
	if matches == nil {
		return types.SyscallEvent{}, false
	}

	filePath := matches[1]
	if !isSensitivePath(filePath) {
		return types.SyscallEvent{}, false
	}

	var flags string
	if len(matches) > 2 {
		flags = matches[2]
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

	// Skip failed execve calls (ENOENT, EACCES, etc.) — they are normal
	// PATH search attempts and produce false positives.
	if execveFailedRe.MatchString(line) {
		return types.SyscallEvent{}, false
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
