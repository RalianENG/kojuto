package analyzer

import (
	"net"
	"path"
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
	case types.EventConnect, types.EventSendto, types.EventSendmsg:
		return isBenignNetwork(evt)
	case types.EventExecve:
		return isBenignExec(evt)
	default:
		return false
	}
}

func isBenignNetwork(evt *types.SyscallEvent) bool {
	// Empty address means the parser failed to extract the destination.
	// Treat as suspicious — a missed parse must not silence a real connection.
	if evt.DstAddr == "" {
		return false
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

// benignPaths maps binary basenames to the directories they are allowed to run from.
// Only binaries in these specific paths are considered benign — a binary named "python3"
// running from /tmp/ will NOT be whitelisted.
var benignPaths = map[string][]string{
	"python":     {"/usr/bin/", "/usr/local/bin/"},
	"python3":    {"/usr/bin/", "/usr/local/bin/"},
	"python3.12": {"/usr/local/bin/"},
	"sh":         {"/bin/", "/usr/bin/"},
	"bash":       {"/bin/", "/usr/bin/"},
	"dash":       {"/bin/", "/usr/bin/"},
	"uname":      {"/bin/", "/usr/bin/"},
	"arch":       {"/bin/", "/usr/bin/"},
	"lsb_release": {"/usr/bin/"},
	"dpkg-query": {"/usr/bin/"},
	"ldconfig":   {"/sbin/", "/usr/sbin/"},
	"gcc":        {"/usr/bin/"},
	"cc":         {"/usr/bin/"},
	"c99":        {"/usr/bin/"},
	"ld":         {"/usr/bin/"},
	"install":    {"/usr/bin/"},
	"mkdir":      {"/bin/", "/usr/bin/"},
	"cp":         {"/bin/", "/usr/bin/"},
	"mv":         {"/bin/", "/usr/bin/"},
	"rm":         {"/bin/", "/usr/bin/"},
	"chmod":      {"/bin/", "/usr/bin/"},
	"chown":      {"/bin/", "/usr/bin/"},
	"cat":        {"/bin/", "/usr/bin/"},
	"ls":         {"/bin/", "/usr/bin/"},
	"sed":        {"/bin/", "/usr/bin/"},
	"node":       {"/usr/bin/", "/usr/local/bin/"},
	"npm":        {"/usr/bin/", "/usr/local/bin/"},
	"npx":        {"/usr/bin/", "/usr/local/bin/"},
}

// interpreterExecFlags maps interpreter basenames to the flags that enable
// arbitrary inline code execution. Only interpreters where -c/-e means
// "run this code string" are listed. sh/bash -c is excluded because pip and
// setuptools routinely call `sh -c "command"` during normal installs.
var interpreterExecFlags = map[string][]string{
	"python":     {" -c "},
	"python3":    {" -c "},
	"python3.12": {" -c "},
	"node":       {" -e ", " --eval "},
}

// isBenignExec filters out expected subprocess calls during pip/npm install.
// It validates both the binary name AND its directory to prevent basename spoofing.
// Interpreter calls with inline code execution flags are always suspicious.
func isBenignExec(evt *types.SyscallEvent) bool {
	// Use path (not filepath) because these are Linux container paths,
	// and kojuto may run on Windows or macOS.
	base := path.Base(evt.Comm)
	dir := path.Dir(evt.Comm) + "/"

	// Interpreters with inline execution flags (python3 -c, node -e)
	// are always suspicious regardless of path — they can run arbitrary code.
	if flags, ok := interpreterExecFlags[base]; ok && hasInlineExecFlag(evt.Cmdline, flags) {
		return false
	}

	// Only allow binaries from known system directories.
	if allowedDirs, ok := benignPaths[base]; ok {
		for _, d := range allowedDirs {
			if dir == d {
				return true
			}
		}
	}

	// pip/setuptools internal commands: the binary itself must be pip or python,
	// not just any command with "pip" in its arguments.
	if (base == "pip" || base == "pip3") && hasAllowedDir(dir) {
		return true
	}

	return false
}

func hasInlineExecFlag(cmdline string, flags []string) bool {
	// Pad cmdline with spaces for boundary matching.
	padded := " " + cmdline + " "
	for _, flag := range flags {
		if strings.Contains(padded, flag) {
			return true
		}
	}
	return false
}

func hasAllowedDir(dir string) bool {
	return dir == "/usr/bin/" || dir == "/usr/local/bin/" || dir == "/bin/"
}
