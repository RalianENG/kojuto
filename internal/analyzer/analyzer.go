package analyzer

import (
	"math"
	"net"
	"path"
	"strconv"
	"strings"

	"github.com/RalianENG/kojuto/internal/types"
)

// sensitivePathPatterns mirrors the probe-layer patterns so that the analyzer
// can flag shell commands whose arguments reference credential files.
// Initialized to a minimal fallback; call SetSensitivePaths at startup.
var sensitivePathPatterns []string

// SetSensitivePaths configures the sensitive path patterns used by the analyzer
// to detect credential access via shell commands (e.g. "cat ~/.ssh/id_rsa").
func SetSensitivePaths(patterns []string) {
	sensitivePathPatterns = patterns
}

// Analyze determines a verdict based on captured events.
// Events matching known-benign patterns are filtered out first.
// Suspicious events are enriched with Category and Reason fields.
func Analyze(events []types.SyscallEvent) (string, []types.SyscallEvent) {
	var suspicious []types.SyscallEvent

	for i := range events {
		if isBenign(&events[i]) {
			continue
		}

		classify(&events[i])
		suspicious = append(suspicious, events[i])
	}

	if len(suspicious) > 0 {
		return types.VerdictSuspicious, suspicious
	}

	return types.VerdictClean, nil
}

// GenerateSummary creates a human-readable summary from analyzed events.
func GenerateSummary(verdict string, events []types.SyscallEvent) *types.ReportSummary {
	if verdict == types.VerdictClean {
		return &types.ReportSummary{
			RiskLevel:   "none",
			Description: "No suspicious activity detected during install or import.",
		}
	}

	if verdict == types.VerdictInconclusive {
		return &types.ReportSummary{
			RiskLevel:   "medium",
			Description: "Probe data was lost (buffer overflow). Some events may have been missed.",
			Remediation: "Re-scan with --probe-method=strace-container or increase timeout.",
		}
	}

	// Collect unique categories.
	catSet := make(map[string]bool)
	for i := range events {
		if events[i].Category != "" {
			catSet[events[i].Category] = true
		}
	}
	var categories []string
	for c := range catSet {
		categories = append(categories, c)
	}

	risk := assessRisk(categories)
	desc := buildDescription(events, categories)
	remediation := buildRemediation(categories)

	return &types.ReportSummary{
		RiskLevel:   risk,
		Categories:  categories,
		Description: desc,
		Remediation: remediation,
	}
}

func assessRisk(categories []string) string {
	for _, c := range categories {
		switch c {
		case types.CategoryC2, types.CategoryDataExfil, types.CategoryCredentialAccess,
			types.CategoryBackdoor:
			return "critical"
		}
	}
	for _, c := range categories {
		switch c {
		case types.CategoryBinaryHijack, types.CategoryDNSTunnel, types.CategoryPersistence:
			return "high"
		}
	}
	return "medium"
}

func buildDescription(_ []types.SyscallEvent, categories []string) string {
	parts := make([]string, 0, len(categories))
	for _, c := range categories {
		switch c {
		case types.CategoryC2:
			parts = append(parts, "outbound connection to external server (possible C2)")
		case types.CategoryDataExfil:
			parts = append(parts, "data exfiltration via DNS tunneling")
		case types.CategoryCredentialAccess:
			parts = append(parts, "access to credential/secret files")
		case types.CategoryCodeExecution:
			parts = append(parts, "suspicious code execution during install")
		case types.CategoryBinaryHijack:
			parts = append(parts, "attempted replacement of trusted system binary")
		case types.CategoryBackdoor:
			parts = append(parts, "server socket opened (backdoor indicator)")
		case types.CategoryPersistence:
			parts = append(parts, "write to shell startup file (persistence mechanism)")
		case types.CategoryDNSTunnel:
			parts = append(parts, "DNS tunneling detected (high-entropy subdomain queries)")
		}
	}
	return strings.Join(parts, "; ") + "."
}

func buildRemediation(categories []string) string {
	for _, c := range categories {
		switch c {
		case types.CategoryC2, types.CategoryDataExfil, types.CategoryBackdoor:
			return "Do NOT install this package. Remove it from dependencies immediately. " +
				"If previously installed, audit the host for compromised credentials and rotate secrets."
		case types.CategoryCredentialAccess:
			return "Do NOT install this package. If previously installed, rotate all credentials " +
				"that were present on the machine (SSH keys, AWS tokens, Git credentials, etc.)."
		case types.CategoryPersistence:
			return "Do NOT install this package. If previously installed, inspect shell startup files " +
				"(.bashrc, .zshrc, .profile) and crontab for injected malicious code."
		}
	}
	return "Do NOT install this package. Review the events list for details."
}

// classify assigns Category and Reason to a suspicious event.
func classify(evt *types.SyscallEvent) {
	switch evt.Syscall {
	case types.EventConnect:
		if isKnownDoHServer(evt.DstAddr) && evt.DstPort == 443 {
			evt.Category = types.CategoryDNSTunnel
			evt.Reason = "Connection to known DNS-over-HTTPS server " + evt.DstAddr + ":443" +
				" — may be used for DNS tunneling to bypass port-53 monitoring."
		} else {
			evt.Category = types.CategoryC2
			evt.Reason = "Outbound connection to " + evt.DstAddr + ":" + portStr(evt.DstPort) +
				" — packages should not make network connections during install or import."
		}

	case types.EventSendto, types.EventSendmsg, types.EventSendmmsg:
		if evt.DNSQuery != "" {
			evt.Category = types.CategoryDNSTunnel
			evt.Reason = "DNS query to " + evt.DNSQuery +
				" contains high-entropy subdomains, indicating data exfiltration via DNS tunneling."
		} else {
			evt.Category = types.CategoryC2
			evt.Reason = "Network data sent to " + evt.DstAddr + ":" + portStr(evt.DstPort) + "."
		}

	case types.EventBind, types.EventListen, types.EventAccept:
		evt.Category = types.CategoryBackdoor
		evt.Reason = "Server socket operation (" + evt.Syscall + ") detected — " +
			"indicates a backdoor listener or reverse shell."

	case types.EventExecve:
		classifyExecve(evt)

	case types.EventOpenat:
		classifyOpenat(evt)

	case types.EventRename:
		evt.Category = types.CategoryBinaryHijack
		evt.Reason = "Rename " + evt.SrcPath + " -> " + evt.DstPath +
			" — attempted replacement of trusted system binary."
	}
}

// persistenceTargets are path substrings that indicate shell startup files.
// Writing to these means the attacker is injecting persistent code.
var persistenceTargets = []string{
	"/.bashrc", "/.bash_profile", "/.zshrc", "/.profile",
	"/.bash_history", "/.zsh_history",
	"/crontab",
}

func classifyOpenat(evt *types.SyscallEvent) {
	isWrite := strings.Contains(evt.OpenFlags, "O_WRONLY") ||
		strings.Contains(evt.OpenFlags, "O_RDWR")

	// Check if this is a write to a persistence target (e.g. .bashrc).
	if isWrite {
		for _, target := range persistenceTargets {
			if strings.Contains(evt.FilePath, target) {
				evt.Category = types.CategoryPersistence
				evt.Reason = "Write to shell startup file: " + evt.FilePath +
					" — attacker may be injecting persistent backdoor code."
				return
			}
		}
	}

	// Default: credential/secret file access.
	evt.Category = types.CategoryCredentialAccess
	if isWrite {
		evt.Reason = "Write to sensitive file: " + evt.FilePath +
			" — legitimate packages do not modify credential files."
	} else {
		evt.Reason = "Read of sensitive file: " + evt.FilePath +
			" — legitimate packages do not access credential files during install."
	}
}

func classifyExecve(evt *types.SyscallEvent) {
	cmdline := evt.Cmdline
	base := path.Base(evt.Comm)
	dir := path.Dir(evt.Comm) + "/"

	// Execution from suspicious directories (fileless attack).
	for _, d := range suspiciousExecDirs {
		if strings.HasPrefix(dir, d) {
			evt.Category = types.CategoryCodeExecution
			evt.Reason = "Execution from suspicious path: " + evt.Comm +
				" — indicates fileless attack or payload staged in memory-backed filesystem."
			return
		}
	}

	// Inline code execution.
	if hasInlineExecFlag(cmdline, interpreterExecFlags[base]) {
		evt.Category = types.CategoryCodeExecution
		evt.Reason = base + " executed with inline code flag (-c/-e). " +
			"Legitimate packages use script files, not inline code injection."
		return
	}

	// Shell command analysis.
	if shells[base] && hasInlineExecFlag(cmdline, []string{" -c "}) {
		evt.Category = types.CategoryCodeExecution
		evt.Reason = "Shell command: " + truncate(cmdline, 200) +
			" — contains suspicious commands not expected during package installation."
		return
	}

	// Unknown binary.
	evt.Category = types.CategoryCodeExecution
	evt.Reason = "Unexpected process execution: " + truncate(cmdline, 200) +
		" — binary not in the allowed list for package installation."
}

// knownDoHServers are IP addresses of public DNS-over-HTTPS providers.
// Connections to these on port 443 may indicate DNS tunneling that
// bypasses traditional port-53 monitoring.
var knownDoHServers = map[string]bool{
	// Google
	"8.8.8.8": true, "8.8.4.4": true,
	"2001:4860:4860::8888": true, "2001:4860:4860::8844": true,
	// Cloudflare
	"1.1.1.1": true, "1.0.0.1": true,
	"2606:4700:4700::1111": true, "2606:4700:4700::1001": true,
	// Quad9
	"9.9.9.9": true, "149.112.112.112": true,
	// OpenDNS
	"208.67.222.222": true, "208.67.220.220": true,
	// NextDNS
	"45.90.28.0": true, "45.90.30.0": true,
}

func isKnownDoHServer(addr string) bool {
	return knownDoHServers[addr]
}

func portStr(port uint16) string {
	if port == 0 {
		return "?"
	}
	return strconv.FormatUint(uint64(port), 10)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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

	// DNS tunneling check: even if the DNS server IP is benign (e.g. 8.8.8.8),
	// the query domain itself may be carrying exfiltrated data.
	if evt.DNSQuery != "" && isDNSTunnel(evt.DNSQuery) {
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
	"python":      {"/usr/bin/", "/usr/local/bin/"},
	"python3":     {"/usr/bin/", "/usr/local/bin/"},
	"python3.12":  {"/usr/local/bin/"},
	"sh":          {"/bin/", "/usr/bin/"},
	"bash":        {"/bin/", "/usr/bin/"},
	"dash":        {"/bin/", "/usr/bin/"},
	"uname":       {"/bin/", "/usr/bin/"},
	"arch":        {"/bin/", "/usr/bin/"},
	"lsb_release": {"/usr/bin/"},
	"dpkg-query":  {"/usr/bin/"},
	"ldconfig":    {"/sbin/", "/usr/sbin/"},
	"gcc":         {"/usr/bin/"},
	"cc":          {"/usr/bin/"},
	"c99":         {"/usr/bin/"},
	"ld":          {"/usr/bin/"},
	"install":     {"/usr/bin/"},
	"mkdir":       {"/bin/", "/usr/bin/"},
	"cp":          {"/bin/", "/usr/bin/"},
	"mv":          {"/bin/", "/usr/bin/"},
	"rm":          {"/bin/", "/usr/bin/"},
	"chmod":       {"/bin/", "/usr/bin/"},
	"chown":       {"/bin/", "/usr/bin/"},
	"cat":         {"/bin/", "/usr/bin/"},
	"ls":          {"/bin/", "/usr/bin/"},
	"env":         {"/bin/", "/usr/bin/"},
	// sed is intentionally excluded: GNU sed -e with the 'e' command can
	// execute arbitrary shell commands (e.g. sed -e '1e malicious_cmd').
	"node": {"/usr/bin/", "/usr/local/bin/"},
	"npm":  {"/usr/bin/", "/usr/local/bin/"},
	"npx":  {"/usr/bin/", "/usr/local/bin/"},
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
// suspiciousExecDirs are directories where legitimate binaries should never run from.
// Execution from these paths indicates fileless attacks or payload drops.
var suspiciousExecDirs = []string{
	"/dev/shm/",      // tmpfs — fileless execution
	"/proc/self/fd/", // fd-based execution bypass
}

func isBenignExec(evt *types.SyscallEvent) bool {
	// Use path (not filepath) because these are Linux container paths,
	// and kojuto may run on Windows or macOS.
	base := path.Base(evt.Comm)
	dir := path.Dir(evt.Comm) + "/"

	// Execution from suspicious directories is always malicious.
	for _, d := range suspiciousExecDirs {
		if strings.HasPrefix(dir, d) {
			return false
		}
	}

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

		// Block commands whose arguments reference sensitive paths.
		// e.g. "cat ~/.ssh/id_rsa", "grep -r . ~/.aws/", "head ~/.git-credentials"
		if argsTouchSensitivePath(seg) {
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

// argsTouchSensitivePath returns true if any non-flag argument in the shell
// segment contains a sensitive path pattern (e.g. "/.ssh/", "/.aws/").
func argsTouchSensitivePath(segment string) bool {
	fields := strings.Fields(segment)
	for _, f := range fields[1:] { // skip the command itself
		if strings.HasPrefix(f, "-") {
			continue
		}
		for _, pattern := range sensitivePathPatterns {
			if strings.Contains(f, pattern) {
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

// DNS tunneling detection.
//
// Exfiltration via DNS encodes data in subdomain labels:
//   aGVsbG8gd29ybGQ.evil.com  (base64 in subdomain)
//   68656c6c6f.evil.com       (hex in subdomain)
//
// Heuristics:
// 1. Any single label longer than 30 chars (normal labels rarely exceed 15).
// 2. Total query length > 80 chars.
// 3. High Shannon entropy in longest label (> 3.5 bits/char = encoded data).

const (
	dnsMaxLabelLen      = 30
	dnsMaxQueryLen      = 80
	dnsEntropyThreshold = 3.5
)

// benignDNSSuffixes are domain suffixes that are expected during package installation.
// DNS queries to these are never flagged as tunneling regardless of label entropy.
var benignDNSSuffixes = []string{
	"pypi.org",
	"pythonhosted.org",
	"npmjs.org",
	"npmjs.com",
	"registry.npmjs.org",
	"googleapis.com",
	"debian.org",
	"ubuntu.com",
}

// isDNSTunnel returns true if the DNS query domain shows signs of data exfiltration.
func isDNSTunnel(query string) bool {
	// Skip known-benign package registry domains.
	lower := strings.ToLower(query)
	for _, suffix := range benignDNSSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}

	if len(query) > dnsMaxQueryLen {
		return true
	}

	labels := strings.Split(query, ".")
	// Need at least a subdomain + domain + TLD to be interesting.
	if len(labels) < 3 {
		return false
	}

	// Check subdomain labels (everything except the last two: domain + TLD).
	for _, label := range labels[:len(labels)-2] {
		if len(label) > dnsMaxLabelLen {
			return true
		}
		if shannonEntropy(label) > dnsEntropyThreshold {
			return true
		}
	}

	return false
}

// shannonEntropy calculates the Shannon entropy (bits per character) of a string.
// High entropy (> 3.5) indicates encoded/encrypted data rather than natural language.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
