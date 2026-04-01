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
	case types.EventConnect, types.EventSendto, types.EventSendmsg, types.EventSendmmsg:
		return isBenignNetwork(evt)
	case types.EventBind, types.EventListen, types.EventAccept:
		// Server socket operations during install are never benign —
		// they indicate a backdoor listener or reverse shell.
		return false
	case types.EventExecve:
		return isBenignExec(evt)
	case types.EventOpenat:
		// Only emitted for sensitive paths (credentials, keys, etc.)
		// by the parser's pre-filter — always suspicious in install context.
		return false
	case types.EventRename:
		return isBenignRename(evt)
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
	"env":        {"/bin/", "/usr/bin/"},
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
	"grep": true, "sort": true, "tr": true, "cut": true,
	"expr": true,
	// env is excluded: it can execute arbitrary commands (e.g. env curl ...).
	// find is excluded: -exec can run arbitrary binaries (e.g. find /tmp -exec payload).
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
// every command in the pipeline/chain invokes only shellSafeCommands.
// Chains using ;, |, ||, &&, and subshells are split and each segment validated.
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

	// Split on shell command separators to get each segment.
	segments := splitShellCommands(cmd)
	if len(segments) == 0 {
		return false
	}

	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}

		firstToken := extractFirstToken(seg)
		firstBase := path.Base(firstToken)

		if !shellSafeCommands[firstBase] {
			return false
		}

		// Block file operations that target whitelisted directories.
		// e.g. "cp /tmp/payload /usr/local/bin/python3" would hijack a trusted binary.
		if isFileOpTargetingTrustedDir(firstBase, seg) {
			return false
		}
	}

	return true
}

// splitShellCommands splits a shell command string on ;, |, ||, &&, and
// parentheses to extract individual command segments.
func splitShellCommands(cmd string) []string {
	var segments []string
	var current strings.Builder

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch c {
		case ';', '(', ')':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
		case '|':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
			// Skip || (treat the second | as part of separator).
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				i++
			}
		case '&':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
			// Skip && (treat the second & as part of separator).
			if i+1 < len(cmd) && cmd[i+1] == '&' {
				i++
			}
		case '`':
			// Backtick command substitution — always suspicious.
			return nil
		case '$':
			// $(...) command substitution — always suspicious.
			if i+1 < len(cmd) && cmd[i+1] == '(' {
				return nil
			}
			current.WriteByte(c)
		default:
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		segments = append(segments, current.String())
	}

	return segments
}

// extractFirstToken returns the first whitespace-delimited token from a
// command segment, ignoring leading redirections like ">" or "<".
func extractFirstToken(seg string) string {
	seg = strings.TrimSpace(seg)

	for i, c := range seg {
		if c == ' ' || c == '\t' || c == '>' || c == '<' {
			return seg[:i]
		}
	}

	return seg
}

// trustedDirPrefixes are directories where whitelisted binaries live.
// Shell commands that copy/move/link files into these directories could hijack trusted binaries.
var trustedDirPrefixes = []string{
	"/usr/bin/", "/usr/local/bin/", "/bin/", "/usr/sbin/", "/sbin/",
}

// fileOpCommands are shell commands that can place files into directories.
var fileOpCommands = map[string]bool{
	"cp": true, "mv": true, "ln": true, "install": true,
}

// isBenignRename checks whether a rename/renameat targets a known trusted binary.
// Renaming over python3, node, sh, etc. in system dirs is a hijack attempt.
// Renames to other destinations (e.g. pip installing a new CLI script) are benign.
func isBenignRename(evt *types.SyscallEvent) bool {
	destBase := path.Base(evt.DstPath)
	destDir := path.Dir(evt.DstPath) + "/"

	if allowedDirs, ok := benignPaths[destBase]; ok {
		for _, d := range allowedDirs {
			if destDir == d {
				return false
			}
		}
	}

	return true
}

// isFileOpTargetingTrustedDir checks if a file operation targets a trusted
// binary directory, which could be used to hijack whitelisted executables.
func isFileOpTargetingTrustedDir(base, segment string) bool {
	if !fileOpCommands[base] {
		return false
	}

	// Check if any argument references a trusted directory.
	fields := strings.Fields(segment)
	for _, f := range fields[1:] { // skip the command itself
		if strings.HasPrefix(f, "-") {
			continue // skip flags
		}
		for _, prefix := range trustedDirPrefixes {
			if strings.HasPrefix(f, prefix) {
				return true
			}
		}
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
