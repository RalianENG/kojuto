package analyzer

import (
	"net"
	"path/filepath"
	"strings"

	"github.com/RalianENG/kojuto/internal/types"
)

// Analyze determines a verdict based on captured events.
// Events matching known-benign patterns are filtered out first.
func Analyze(events []types.SyscallEvent) (string, []types.SyscallEvent) {
	var suspicious []types.SyscallEvent

	for i := range events {
		if isBenign(&events[i]) {
			continue
		}

		suspicious = append(suspicious, events[i])
	}

	if len(suspicious) > 0 {
		return types.VerdictSuspicious, suspicious
	}

	return types.VerdictClean, nil
}

func isBenign(evt *types.SyscallEvent) bool {
	switch evt.Syscall {
	case types.EventConnect, types.EventSendto:
		return isBenignNetwork(evt)
	case types.EventExecve:
		return isBenignExec(evt)
	default:
		return false
	}
}

func isBenignNetwork(evt *types.SyscallEvent) bool {
	if evt.DstAddr == "" {
		return true
	}

	ip := net.ParseIP(evt.DstAddr)
	if ip == nil {
		return false
	}

	// Loopback (127.0.0.0/8, ::1).
	if ip.IsLoopback() {
		return true
	}

	// Unspecified (0.0.0.0, ::).
	if ip.IsUnspecified() {
		return true
	}

	// Link-local (169.254.x.x, fe80::).
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}

// benignBasenames are binary names commonly invoked by pip/npm during normal install.
var benignBasenames = map[string]bool{
	"python": true, "python3": true, "python3.12": true,
	"sh": true, "bash": true, "dash": true,
	"uname": true, "arch": true, "lsb_release": true,
	"dpkg-query": true, "ldconfig": true,
	"gcc": true, "cc": true, "c99": true, "ld": true,
	"install": true, "mkdir": true, "cp": true, "mv": true, "rm": true,
	"chmod": true, "chown": true, "cat": true, "ls": true, "sed": true,
	"node": true, "npm": true, "npx": true,
}

// isBenignExec filters out expected subprocess calls during pip/npm install.
func isBenignExec(evt *types.SyscallEvent) bool {
	// Check basename of the binary.
	base := filepath.Base(evt.Comm)
	if benignBasenames[base] {
		return true
	}

	// pip/setuptools internal commands.
	if strings.Contains(evt.Cmdline, "pip") && !strings.Contains(evt.Cmdline, "http") {
		return true
	}

	if strings.Contains(evt.Cmdline, "setup.py") && !strings.Contains(evt.Cmdline, "http") {
		return true
	}

	// npm lifecycle scripts that don't fetch.
	if strings.Contains(evt.Cmdline, "node_modules/.bin/") && !strings.Contains(evt.Cmdline, "http") {
		return true
	}

	return false
}
