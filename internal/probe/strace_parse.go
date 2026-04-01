package probe

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

var straceConnectRe = regexp.MustCompile(
	`connect\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet6?_addr\("([^"]+)"\)`,
)

func parseStraceLine(line string) (types.ConnectEvent, bool) {
	matches := straceConnectRe.FindStringSubmatch(line)
	if matches == nil {
		return types.ConnectEvent{}, false
	}

	port, err := strconv.ParseUint(matches[1], 10, 16)
	if err != nil {
		return types.ConnectEvent{}, false
	}
	addr := matches[2]

	var family uint16 = 2 // AF_INET
	if strings.Contains(line, "AF_INET6") {
		family = 10
	}

	// Extract PID from strace output: "[pid NNNNN] connect(...)"
	var pid uint32
	if pidIdx := strings.Index(line, "[pid "); pidIdx >= 0 {
		pidStr := line[pidIdx+5:]
		if endIdx := strings.Index(pidStr, "]"); endIdx > 0 {
			if p, err := strconv.ParseUint(pidStr[:endIdx], 10, 32); err == nil {
				pid = uint32(p)
			}
		}
	}

	return types.ConnectEvent{
		Timestamp: time.Now().UTC(),
		PID:       pid,
		Comm:      "",
		Family:    family,
		DstAddr:   addr,
		DstPort:   uint16(port),
	}, true
}
