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
	// sed is intentionally excluded: GNU sed -e with the 'e' command can
	// execute arbitrary shell commands (e.g. sed -e '1e malicious_cmd').
	"node": {"/usr/bin/", "/usr/local/bin/"},
	"npm":        {"/usr/bin/", "/usr/local/bin/"},
	"npx":        {"/usr/bin/", "/usr/local/bin/"},
}

// interpreterExecFlags maps interpreter basenames to the flags that enable
// arbitrary inline code execution.
var interpreterExecFlags = map[string][]string{
	"python":     {" -c "},
	"python3":    {" -c "},
	"python3.12": {" -c "},
	"node":       {" -e ", " --eval "},
}

// shells are interpreters where -c runs an arbitrary command string.
// Unlike python -c, shell -c is legitimate during pip install (e.g. sh -c "gcc ..."),
// so we inspect the command content rather than blocking outright.
var shells = map[string]bool{
	"sh": true, "bash": true, "dash": true,
}

// shellSafeCommands are binaries that sh -c is allowed to invoke.
// Only compiler toolchain, file manipulation, and query commands are listed.
// If sh -c invokes anything else, it is suspicious.
var shellSafeCommands = map[string]bool{
	// Compiler toolchain (C extension builds).
	"gcc": true, "cc": true, "c99": true, "c++": true, "g++": true,
	"ld": true, "as": true, "ar": true, "ranlib": true, "strip": true,
	"make": true, "cmake": true, "pkg-config": true,
	// File/dir ops.
	"cp": true, "mv": true, "rm": true, "mkdir": true, "rmdir": true,
	"chmod": true, "chown": true, "install": true, "ln": true, "touch": true,
	// Query/info (read-only).
	"echo": true, "printf": true, "test": true, "true": true, "false": true,
	"cat": true, "ls": true, "head": true, "tail": true, "wc": true,
	"uname": true, "arch": true, "which": true, "command": true,
	"id": true, "whoami": true, "basename": true, "dirname": true,
	"lsb_release": true, "dpkg-query": true, "ldconfig": true,
	"grep": true, "find": true, "sort": true, "tr": true, "cut": true,
	"expr": true, "env": true,
}

// isBenignExec filters out expected subprocess calls during pip/npm install.
// It validates the binary name, its directory, and (for shells/interpreters)
// the content of the command being executed.
func isBenignExec(evt *types.SyscallEvent) bool {
	// Use path (not filepath) because these are Linux container paths,
	// and kojuto may run on Windows or macOS.
	base := path.Base(evt.Comm)
	dir := path.Dir(evt.Comm) + "/"

	// Python/node with inline code execution flags → always suspicious.
	if flags, ok := interpreterExecFlags[base]; ok && hasInlineExecFlag(evt.Cmdline, flags) {
		return false
	}

	// Shell with -c: inspect the command content.
	if shells[base] && hasInlineExecFlag(evt.Cmdline, []string{" -c "}) {
		return isShellCmdBenign(evt.Cmdline)
	}

	// Only allow binaries from known system directories.
	if allowedDirs, ok := benignPaths[base]; ok {
		for _, d := range allowedDirs {
			if dir == d {
				return true
			}
		}
	}

	// pip/setuptools internal commands.
	if (base == "pip" || base == "pip3") && hasAllowedDir(dir) {
		return true
	}

	return false
}

// isShellCmdBenign extracts the command from "sh -c <cmd>" and checks whether
// the first invoked binary is in shellSafeCommands.
func isShellCmdBenign(cmdline string) bool {
	// Find "-c " and extract everything after it.
	idx := strings.Index(cmdline, "-c ")
	if idx < 0 {
		return false
	}

	cmd := strings.TrimSpace(cmdline[idx+3:])

	// Strip surrounding quotes if present.
	if len(cmd) >= 2 {
		if (cmd[0] == '\'' && cmd[len(cmd)-1] == '\'') ||
			(cmd[0] == '"' && cmd[len(cmd)-1] == '"') {
			cmd = cmd[1 : len(cmd)-1]
		}
	}

	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}

	// Extract the first token (the binary being invoked).
	firstToken := cmd
	for i, c := range cmd {
		if c == ' ' || c == '\t' || c == ';' || c == '|' || c == '&' || c == '>' || c == '<' || c == '(' {
			firstToken = cmd[:i]
			break
		}
	}

	// Get basename in case the command uses a full path.
	firstBase := path.Base(firstToken)

	return shellSafeCommands[firstBase]
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
