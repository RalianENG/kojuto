package probe

import (
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

	// listen(3, 5)
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

	// openat(AT_FDCWD, "/home/dev/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 3
	straceOpenatRe = regexp.MustCompile(
		`openat\([^,]+,\s*"([^"]+)",\s*([A-Z_|]+)`,
	)

	// rename("/tmp/evil", "/usr/local/bin/python3") = 0
	straceRenameRe = regexp.MustCompile(
		`rename\("([^"]+)",\s*"([^"]+)"\)`,
	)

	// renameat(AT_FDCWD, "old", AT_FDCWD, "new") or renameat2(...)
	straceRenameatRe = regexp.MustCompile(
		`renameat2?\([^,]+,\s*"([^"]+)",\s*[^,]+,\s*"([^"]+)"`,
	)
)

// sensitivePathPatterns are substrings that indicate access to credential or
// secret files. Only openat calls matching these patterns are emitted as events
// to avoid flooding the event channel with thousands of benign file opens
// during package installation.
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
	// .npmrc and .pypirc are intentionally excluded: npm and pip read these
	// as part of their normal operation (registry config, auth tokens).
	// Monitoring them would cause false positives on every scan.
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
