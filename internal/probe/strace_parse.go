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

	// execve("/usr/bin/curl", ["curl", "http://evil.com"], ...)
	straceExecveRe = regexp.MustCompile(
		`execve\("([^"]+)",\s*\[([^\]]+)\]`,
	)
)

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

	if evt, ok := parseExecve(line); ok {
		return evt, true
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

func parseExecve(line string) (types.SyscallEvent, bool) {
	matches := straceExecveRe.FindStringSubmatch(line)
	if matches == nil {
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
