package analyzer

import (
	"math"
	"net"
	"path"
	"sort"
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

// scannedPkgs is the set of packages whose own files the analyzer treats
// as legitimate write targets. Used by the library_hijacking rule to
// distinguish "scanned package writes its own build output" from
// "scanned package writes into a sibling package's source". Set via
// SetScanPkgs at scan-start; empty by default so older code paths
// (and tests) are unaffected until they opt in.
var scannedPkgs = make(map[string]bool)

// SetScanPkgs records the packages currently being scanned so the
// library_hijacking rule can identify cross-package writes. Pass the
// same list given to Sandbox.SetScanPkgs. A nil or empty list disables
// the rule (all node_modules writes flow through the default openat
// classification).
func SetScanPkgs(pkgs []string) {
	m := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		if p != "" {
			m[p] = true
		}
	}
	scannedPkgs = m
}

// Analyze determines a verdict based on captured events.
// Events matching known-benign patterns are filtered out first.
// Suspicious events are enriched with Category and Reason fields.
func Analyze(events []types.SyscallEvent) (string, []types.SyscallEvent) {
	// Pre-pass: collect paths that were executed (execve) and files that
	// were written (openat O_CREAT/O_WRONLY) to correlate with unlinks.
	executedPaths := collectExecutedPaths(events)

	// Pre-pass: build PID → comm map from execve events so later
	// syscalls (mprotect, mmap) can be attributed back to the process
	// that issued them. Strace mprotect lines do not carry the
	// process name; only the PID. This map is the missing link.
	pidComm := collectPIDComm(events)

	var suspicious []types.SyscallEvent

	for i := range events {
		// V8 JIT filter: simultaneous RWX mprotect/mmap from a Node
		// interpreter is legitimate JIT page management, not shellcode
		// injection. The detection comment in strace_parse.go has been
		// documenting this as a known false-positive source; this is
		// the implementation it pointed at.
		if isV8JITPageOp(&events[i], pidComm) {
			continue
		}

		if isBenign(&events[i]) {
			continue
		}

		classify(&events[i])

		// Anti-forensics refinement: only keep unlink events for files
		// that were also EXECUTED during this scan. This distinguishes
		// malware payload self-deletion (create→execute→delete) from
		// pip temp file cleanup (create→delete without execute).
		if events[i].Category == types.CategoryAntiForensics {
			if !executedPaths[events[i].FilePath] {
				continue
			}
			events[i].Reason = "Payload self-deletion: " + events[i].FilePath +
				" was created, executed, and deleted within the same scan — " +
				"classic anti-forensics technique to remove traces after execution."
		}

		suspicious = append(suspicious, events[i])
	}

	if len(suspicious) == 0 {
		return types.VerdictClean, nil
	}

	// Severity-aware verdict. LOW-only event sets (e.g. dynamic_code_exec
	// from `six`'s internal exec_) stay CLEAN — those patterns appear in
	// legitimate compat libraries too often to single-handedly condemn a
	// package. Events still flow into `suspicious` for forensic visibility
	// in the report.
	return decideVerdict(suspicious), suspicious
}

// decideVerdict applies the severity rules: any HIGH event → SUSPICIOUS;
// two or more MEDIUM events → SUSPICIOUS; otherwise CLEAN. An unmapped
// category is treated as HIGH so a newly added detector that someone
// forgot to weight can still trigger the verdict.
func decideVerdict(events []types.SyscallEvent) string {
	var hi, med int
	for i := range events {
		if events[i].Category == "" {
			continue
		}
		sev, known := types.CategorySeverity[events[i].Category]
		if !known {
			sev = types.SeverityHigh
		}
		switch sev {
		case types.SeverityHigh:
			hi++
		case types.SeverityMedium:
			med++
		}
		if hi >= 1 || med >= 2 {
			return types.VerdictSuspicious
		}
	}
	return types.VerdictClean
}

// jitInterpreters lists program names that run JS via the V8 engine
// (or compatible RWX-using JIT). RWX mmap/mprotect from one of these
// processes is JIT page management, not shellcode injection.
//
// node-ecosystem launchers (npm, npx, yarn, pnpm) are JS scripts with
// a `#!/usr/bin/env node` shebang. Linux's binfmt_script handles the
// shebang internally, so strace sees only the original execve (e.g.
// /usr/local/bin/npm) — the kernel-internal re-exec of node is not
// emitted as a separate syscall. The process is, in fact, running
// node code at that PID. Treating these as V8-equivalent is what
// makes the filter cover npm scan flows.
//
// CPython, Lua, Ruby are deliberately absent — they do not allocate
// simultaneous RWX pages.
var jitInterpreters = map[string]bool{
	"node":   true,
	"nodejs": true,
	"deno":   true,
	"bun":    true,
	"npm":    true,
	"npx":    true,
	"yarn":   true,
	"pnpm":   true,
}

// jitInterpreterTrustedDirs are the directories whose binaries are
// trusted to be legitimate JIT interpreters. A binary named "npm" or
// "node" launched from any other directory (e.g.
// /install/node_modules/<pkg>/bin/npm) is NOT trusted — that path is
// attacker-controlled and could host a payload that does real
// shellcode injection while masquerading as a JIT interpreter.
var jitInterpreterTrustedDirs = map[string]bool{
	"/usr/bin/":       true,
	"/usr/local/bin/": true,
	"/bin/":           true,
}

// collectPIDComm builds a PID → execve binary path map. Used to
// retroactively identify which process emitted a syscall whose
// parser did not populate the comm field (strace mprotect/mmap lines
// carry the PID but not the process name).
//
// Single streaming pass over the temporally-ordered event list:
//
//   - On execve, set m[PID] = full binary path. The path (not just
//     the basename) is stored so the V8 JIT filter can require both
//     name match AND a trusted directory before suppressing an event.
//
//   - On clone, mark the child as a known descendant and copy the
//     parent's current comm if the child has no entry. A child that
//     later does its own execve overrides the propagated value.
//
//   - On any other event at PID ≠ 0 that has NOT appeared as a clone
//     child, treat that PID as the current strace phase's "main
//     target alias" and copy m[0] to m[PID]. This is the inverse of
//     strace's prefix convention: the main target's syscalls are
//     printed WITHOUT `[pid X]` (so they extract as PID=0) until
//     ambiguity forces strace to add one — from then on those
//     syscalls extract as a non-zero PID. The two are the same
//     process; without this aliasing, every V8 worker thread cloned
//     by the disambiguated main target had no parent attribution
//     in m and the JIT filter missed them, leaving the verdict
//     suspicious on every clean npm scan.
//
// PID = 0 is intentionally tracked across exec replacements (sh →
// env → node during the import phase). Phases run in sequence and
// events arrive in temporal order, so m[0] evolves correctly:
// install-phase main-target aliases inherit the install-phase
// m[0] value, import-phase aliases inherit node.
func collectPIDComm(events []types.SyscallEvent) map[uint32]string {
	m := make(map[uint32]string)
	known := make(map[uint32]bool) // PIDs already attributed (clone child or main-target alias)

	for i := range events {
		evt := &events[i]
		switch evt.Syscall {
		case types.EventExecve:
			if evt.Comm == "" {
				continue
			}
			m[evt.PID] = evt.Comm
			if evt.PID != 0 {
				known[evt.PID] = true
			}
		case types.EventClone:
			if evt.ChildPID == 0 {
				continue
			}
			known[evt.ChildPID] = true
			if _, exists := m[evt.ChildPID]; exists {
				continue
			}
			if parentComm, ok := m[evt.PID]; ok {
				m[evt.ChildPID] = parentComm
			}
		default:
			// Main-target alias: a PID ≠ 0 that emits a non-clone
			// non-execve event without having been seen as a clone
			// child is the phase's main target showing up with its
			// disambiguated PID. Copy m[0] (the current main-target
			// comm) into m[PID] so subsequent attribution lookups
			// hit. Mark known so we don't redo this on every event.
			if evt.PID == 0 || known[evt.PID] {
				continue
			}
			known[evt.PID] = true
			if mainComm, ok := m[0]; ok {
				if _, exists := m[evt.PID]; !exists {
					m[evt.PID] = mainComm
				}
			}
		}
	}

	return m
}

// isV8JITPageOp returns true if the event is a simultaneous RWX
// mprotect or mmap call from a known JIT-using interpreter PID.
// Such calls are JIT page management, not shellcode injection.
//
// Three safety properties:
//  1. The PID must appear as the target of a prior execve in this
//     same scan — kojuto observed the interpreter launch. An
//     attacker cannot inject fake PIDs into the strace stream.
//  2. The execve binary's basename must match jitInterpreters.
//  3. The execve binary's directory must be in
//     jitInterpreterTrustedDirs. A binary named "npm" placed under
//     /install/<pkg>/bin/ does NOT get the filter — that path is
//     attacker-controlled and would otherwise let a malicious
//     package launch real shellcode and have it suppressed.
//
// PIDs that did not produce an execve (PID = 0 from the main strace
// target, or parser misses) fall through to the existing detection,
// preserving the original behavior for shellcode injection.
func isV8JITPageOp(evt *types.SyscallEvent, pidComm map[uint32]string) bool {
	if evt.Syscall != types.EventMprotect && evt.Syscall != types.EventMmap {
		return false
	}
	if evt.PID == 0 {
		return false
	}
	binPath, ok := pidComm[evt.PID]
	if !ok {
		return false
	}
	if !jitInterpreters[path.Base(binPath)] {
		return false
	}
	return jitInterpreterTrustedDirs[path.Dir(binPath)+"/"]
}

// collectExecutedPaths builds a set of file paths that appeared as the
// binary in execve events, including FAILED execve (EACCES, ENOENT on
// specific paths). This also scans the RAW event stream (pre-filter)
// because failed execve events are filtered out by isBenign.
//
// Additionally collects paths from code_execution events (interpreter
// invocations like "python3 /tmp/payload.py") where the payload is an
// argument, not the execve binary itself.
func collectExecutedPaths(events []types.SyscallEvent) map[string]bool {
	paths := make(map[string]bool)
	for i := range events {
		evt := &events[i]

		if evt.Syscall == types.EventExecve {
			// The Comm field contains the binary path.
			if evt.Comm != "" {
				paths[evt.Comm] = true
			}
			// Check cmdline for paths in suspicious dirs
			// (e.g. "python3 /tmp/payload.py", "sh /tmp/dropper.sh").
			for _, token := range strings.Fields(evt.Cmdline) {
				if isInSuspiciousDir(token) {
					paths[token] = true
				}
			}
		}

		// Unlink events also carry the deleted path — track the
		// anti-forensics correlation from the other direction: if we
		// see a path in BOTH openat(O_CREAT) and unlink, the create→delete
		// pair is established by the parser. Here we only need to confirm
		// execution happened between create and delete.
	}
	return paths
}

// isInSuspiciousDir checks if a path is in a directory associated with
// payload staging (same dirs as the unlink detector).
func isInSuspiciousDir(filePath string) bool {
	return strings.HasPrefix(filePath, "/tmp/") ||
		strings.HasPrefix(filePath, "/dev/shm/") ||
		strings.HasPrefix(filePath, "/var/tmp/") ||
		strings.HasPrefix(filePath, "/run/")
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

	// Collect unique categories. Sorting here makes every downstream
	// consumer (assessRisk, buildDescription, the report's JSON
	// `categories` field) deterministic — Go map iteration is randomized,
	// so without this the same event set could yield different summary
	// text from one run to the next.
	catSet := make(map[string]bool)
	for i := range events {
		if events[i].Category != "" {
			catSet[events[i].Category] = true
		}
	}
	categories := make([]string, 0, len(catSet))
	for c := range catSet {
		categories = append(categories, c)
	}
	sort.Strings(categories)

	risk := assessRisk(categories)
	desc := buildDescription(events, categories)
	remediation := buildRemediation(catSet)
	breakdown := buildBreakdown(events)

	return &types.ReportSummary{
		RiskLevel:   risk,
		Categories:  categories,
		Breakdown:   breakdown,
		Description: desc,
		Remediation: remediation,
	}
}

// categoryShortDesc returns a terse phrase suitable for a single
// table row in the CLI verdict breakdown. Distinct from
// buildDescription() which assembles a full grammatical sentence.
func categoryShortDesc(c string) string {
	switch c {
	case types.CategoryC2:
		return "outbound to non-loopback addresses"
	case types.CategoryDataExfil:
		return "DNS to known exfil services (Discord/Telegram/Pastebin)"
	case types.CategoryCredentialAccess:
		return "~/.ssh, ~/.aws, ~/.git-credentials, etc."
	case types.CategoryCodeExecution:
		return "execve from /tmp or inline -c/-e"
	case types.CategoryBinaryHijack:
		return "rename onto trusted system binary"
	case types.CategoryBackdoor:
		return "bind/listen/accept during install"
	case types.CategoryPersistence:
		return ".bashrc / shell startup / home directory write"
	case types.CategoryDNSTunnel:
		return "high-entropy subdomains, DoH connect"
	case types.CategoryEvasion:
		return "ptrace self-check, sandbox detection"
	case types.CategoryMemExec:
		return "shellcode injection (mmap+mprotect RWX)"
	case types.CategoryAntiForensics:
		return "create-execute-delete chain"
	case types.CategoryDynamicExec:
		return "eval / Function() / vm.runIn*Context (audit hook)"
	case types.CategoryUnknownBinary:
		return "execve without positive attack signature (info)"
	case types.CategoryDNSLookup:
		return "isolated name resolution (info; C2 fires on the follow-up connect)"
	}
	return c
}

// buildBreakdown counts events per category and returns the result
// sorted by count descending (ties broken alphabetically by category
// name for deterministic output).
func buildBreakdown(events []types.SyscallEvent) []types.CategoryHit {
	counts := make(map[string]int)
	for i := range events {
		if events[i].Category == "" {
			continue
		}
		counts[events[i].Category]++
	}
	if len(counts) == 0 {
		return nil
	}
	hits := make([]types.CategoryHit, 0, len(counts))
	for cat, n := range counts {
		hits = append(hits, types.CategoryHit{
			Category:    cat,
			Count:       n,
			Description: categoryShortDesc(cat),
		})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Count != hits[j].Count {
			return hits[i].Count > hits[j].Count
		}
		return hits[i].Category < hits[j].Category
	})
	return hits
}

func assessRisk(categories []string) string {
	for _, c := range categories {
		switch c {
		case types.CategoryC2, types.CategoryDataExfil, types.CategoryCredentialAccess,
			types.CategoryBackdoor, types.CategoryMemExec:
			return "critical"
		}
	}
	for _, c := range categories {
		switch c {
		case types.CategoryBinaryHijack, types.CategoryDNSTunnel, types.CategoryPersistence,
			types.CategoryEvasion, types.CategoryAntiForensics:
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
			parts = append(parts, "data exfiltration via known exfiltration service (Discord/Telegram/Pastebin)")
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
		case types.CategoryEvasion:
			parts = append(parts, "anti-debugging evasion detected (ptrace self-check)")
		case types.CategoryMemExec:
			parts = append(parts, "writable+executable memory allocation (shellcode injection indicator)")
		case types.CategoryAntiForensics:
			parts = append(parts, "file deletion in temporary directory (anti-forensics/payload self-cleanup)")
		}
	}
	return strings.Join(parts, "; ") + "."
}

// buildRemediation picks the most severe remediation message that applies
// to the detected categories. Tiers are checked in fixed order so the
// output is deterministic regardless of map iteration; the previous
// implementation walked categories sequentially and returned on first
// match, which meant the message text could flip between runs.
func buildRemediation(catSet map[string]bool) string {
	if catSet[types.CategoryC2] || catSet[types.CategoryDataExfil] ||
		catSet[types.CategoryBackdoor] || catSet[types.CategoryMemExec] {
		return "Do NOT install this package. Remove it from dependencies immediately. " +
			"If previously installed, audit the host for compromised credentials and rotate secrets."
	}
	if catSet[types.CategoryCredentialAccess] {
		return "Do NOT install this package. If previously installed, rotate all credentials " +
			"that were present on the machine (SSH keys, AWS tokens, Git credentials, etc.)."
	}
	if catSet[types.CategoryPersistence] {
		return "Do NOT install this package. If previously installed, inspect shell startup files " +
			"(.bashrc, .zshrc, .profile) and crontab for injected malicious code."
	}
	return "Do NOT install this package. Review the events list for details."
}

// classify assigns Category and Reason to a suspicious event.
func classify(evt *types.SyscallEvent) {
	switch evt.Syscall {
	case types.EventConnect:
		classifyConnect(evt)

	case types.EventSendto, types.EventSendmsg, types.EventSendmmsg:
		classifySend(evt)

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

	case types.EventPtrace:
		evt.Category = types.CategoryEvasion
		evt.Reason = "ptrace(PTRACE_TRACEME) detected — anti-debugging technique " +
			"used to detect tracing and suppress malicious behavior."

	case types.EventMmap:
		evt.Category = types.CategoryMemExec
		evt.Reason = "mmap with PROT_WRITE|PROT_EXEC (" + evt.MemProt + ", " + evt.MemFlags +
			") — writable+executable memory allocation. " +
			"Used by shellcode injection (ctypes/ffi-napi) to execute arbitrary " +
			"native code without touching the filesystem."

	case types.EventMprotect:
		evt.Category = types.CategoryMemExec
		evt.Reason = "mprotect with PROT_WRITE|PROT_EXEC (" + evt.MemProt +
			") — memory permissions changed to writable+executable. " +
			"Classic shellcode injection pattern: write payload, then make it executable."

	case types.EventUnlink:
		evt.Category = types.CategoryAntiForensics
		evt.Reason = "File deleted from suspicious directory: " + evt.FilePath +
			" — anti-forensics technique to remove payload traces after execution."

	case types.EventDynamicExec:
		evt.Category = types.CategoryDynamicExec
		evt.Reason = "Dynamic code execution detected via audit hook (" + evt.AuditEvent +
			") — eval/exec/compile/Function generates no execve syscall, " +
			"commonly used by supply chain malware to execute obfuscated payloads."
	}
}

// persistenceTargets are path substrings that indicate shell startup files.
// Writing to these means the attacker is injecting persistent code.
var persistenceTargets = []string{
	"/.bashrc", "/.bash_profile", "/.zshrc", "/.profile",
	"/.bash_history", "/.zsh_history",
	"/crontab",
}

// classifyConnect handles TCP/UDP connect events. Split out from
// classify() so the growth of DNS-specific branches doesn't push the
// parent function over the linter's cognitive-complexity budget.
func classifyConnect(evt *types.SyscallEvent) {
	switch {
	case isKnownDoHServer(evt.DstAddr) && evt.DstPort == 443:
		evt.Category = types.CategoryDNSTunnel
		evt.Reason = "Connection to known DNS-over-HTTPS server " + evt.DstAddr + ":443" +
			" — may be used for DNS tunneling to bypass port-53 monitoring."
	case evt.DstPort == 53:
		// Isolated name resolution is NOT C2. Under --network=none
		// the lookup never completes, and legitimate defensive
		// probes (getaddrinfo at import, glibc NSS lookups) fire
		// this syscall unconditionally. The real C2 signal is the
		// follow-up connect() to the resolved IP, which the default
		// branch catches at HIGH. Recording DNS lookups at LOW
		// preserves the forensic chain but keeps the verdict honest.
		evt.Category = types.CategoryDNSLookup
		evt.Reason = "DNS resolver connection to " + evt.DstAddr + ":53" +
			" — name resolution attempt. Recorded for forensic chain visibility; " +
			"the follow-up connect to the resolved IP is the actual C2 signal."
	default:
		evt.Category = types.CategoryC2
		evt.Reason = "Outbound connection to " + evt.DstAddr + ":" + portStr(evt.DstPort) +
			" — packages should not make network connections during install or import."
	}
}

// classifySend handles sendto/sendmsg/sendmmsg events. Same rationale
// as classifyConnect — keeps classify() below the complexity budget.
func classifySend(evt *types.SyscallEvent) {
	switch {
	case evt.DNSQuery != "" && matchExfilService(evt.DNSQuery) != "":
		svc := matchExfilService(evt.DNSQuery)
		evt.Category = types.CategoryDataExfil
		evt.Reason = "DNS resolution of known exfiltration service (" + svc +
			"): " + evt.DNSQuery +
			" — commonly used by threat actors to exfiltrate stolen data."
	case evt.DNSQuery != "" && isDNSTunnel(evt.DNSQuery):
		evt.Category = types.CategoryDNSTunnel
		evt.Reason = "DNS query to " + evt.DNSQuery +
			" contains high-entropy subdomains, indicating data exfiltration via DNS tunneling."
	case evt.DNSQuery != "":
		// Benign-looking DNS query that reached this branch because
		// the resolver IP is external (not loopback, which
		// isBenignNetwork already filters). Not tunneling and not a
		// known exfil service — record at LOW so the query domain is
		// visible in the forensic report without flipping the verdict
		// on legit lookups.
		evt.Category = types.CategoryDNSLookup
		evt.Reason = "DNS query to " + evt.DNSQuery +
			" via " + evt.DstAddr + ":" + portStr(evt.DstPort) +
			" — recorded for forensic chain visibility; benign-looking query, " +
			"no tunneling or exfil-service pattern detected."
	case evt.DstPort == 53:
		// sendto/sendmsg to :53 with no parsed DNS query is still a
		// DNS packet — the parser just failed to extract the query
		// name from the message payload. Attributing to dns_lookup
		// LOW instead of C2 HIGH prevents parser-miss FPs on every
		// DNS resolution the sandbox observes.
		evt.Category = types.CategoryDNSLookup
		evt.Reason = "DNS packet to " + evt.DstAddr + ":53" +
			" — query name not extracted by parser. Recorded at LOW for forensic " +
			"chain visibility; the follow-up connect to the resolved IP is the C2 signal."
	default:
		evt.Category = types.CategoryC2
		evt.Reason = "Network data sent to " + evt.DstAddr + ":" + portStr(evt.DstPort) + "."
	}
}

func classifyOpenat(evt *types.SyscallEvent) {
	isWrite := strings.Contains(evt.OpenFlags, "O_WRONLY") ||
		strings.Contains(evt.OpenFlags, "O_RDWR") ||
		strings.Contains(evt.OpenFlags, "O_CREAT")

	// Library-hijack checks (npm + PyPI). Extracted to keep
	// classifyOpenat under the gocyclo budget. If the file path matches
	// either shape, classification is terminal (either fires library_hijack
	// or returns clean without falling through to credential_access, which
	// would misclassify legit self-writes and pip's own extraction).
	if handled := classifyLibraryHijack(evt, isWrite); handled {
		return
	}

	// Binary hijack: overwriting a system binary that benignPaths trusts.
	// Attacker writes /usr/local/bin/python3 → subsequent execve passes
	// the whitelist check → arbitrary code runs as "trusted" binary.
	if isWrite && isSystemBinaryTarget(evt.FilePath) {
		evt.Category = types.CategoryBinaryHijack
		evt.Reason = "Write to trusted system binary: " + evt.FilePath +
			" — overwriting a whitelisted binary to bypass execve detection. " +
			"Subsequent execution of this path would be treated as benign."
		return
	}

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

	// Write to user home directory — sandbox structural whitelist check.
	// pip/npm write to site-packages, /usr/local/bin, /tmp, /install only.
	// Any write to /home/ is illegitimate regardless of the specific path.
	// This catches systemd persistence, LaunchAgent injection, IMDS token
	// caching, and any other home-directory attack without maintaining a
	// blacklist of individual paths.
	if isWrite && isHomeDir(evt.FilePath) {
		evt.Category = types.CategoryPersistence
		evt.Reason = "Write to user home directory: " + evt.FilePath +
			" — packages do not write to the user's home directory during " +
			"install or import. This may indicate persistence, config " +
			"injection, or credential tampering."
		return
	}

	// Sandbox/environment detection — reading system introspection paths
	// that reveal tracing, container environment, or network isolation.
	// This is evasion, not credential access.
	if isSandboxDetectionPath(evt.FilePath) {
		evt.Category = types.CategoryEvasion
		evt.Reason = "Sandbox detection attempt: " + evt.FilePath +
			" — package is probing the execution environment to detect " +
			"analysis tools (strace, Docker, network isolation). " +
			"This is a common evasion technique to suppress malicious " +
			"behavior when being analyzed."
		return
	}

	// Default: credential/secret file access (read from sensitive path).
	evt.Category = types.CategoryCredentialAccess
	if isWrite {
		evt.Reason = "Write to sensitive file: " + evt.FilePath +
			" — legitimate packages do not modify credential files."
	} else {
		evt.Reason = "Read of sensitive file: " + evt.FilePath +
			" — legitimate packages do not access credential files during install."
	}
}

// isSandboxDetectionPath returns true if the path is commonly used to
// detect sandboxes, tracers, or container environments.
func isSandboxDetectionPath(filePath string) bool {
	// /proc/self/status — TracerPid reveals strace
	// /proc/self/maps — loaded libraries reveal libfaketime
	// /proc/self/cgroup — reveals Docker/k8s
	// /proc/self/mountinfo — reveals overlay filesystem
	// /proc/<pid>/comm — reveals tracer process name
	// /sys/class/net — reveals network namespace isolation
	sandboxPaths := []string{
		"/proc/self/status",
		"/proc/self/maps",
		"/proc/self/cgroup",
		"/proc/self/mountinfo",
		"/sys/class/net",
	}
	for _, p := range sandboxPaths {
		if strings.Contains(filePath, p) {
			return true
		}
	}
	// /proc/<pid>/comm (numeric PID, not /proc/self/)
	if strings.HasPrefix(filePath, "/proc/") && strings.HasSuffix(filePath, "/comm") {
		return true
	}
	return false
}

// systemBinaryNames are binaries trusted by benignPaths.  A write to any
// of these in a system directory is a binary hijack attempt.
var systemBinaryNames = map[string]bool{
	"python": true, "python3": true, "python3.12": true,
	"node": true, "npm": true, "npx": true,
	"pip": true, "pip3": true,
	"sh": true, "bash": true, "dash": true,
	"env": true,
}

// isSystemBinaryTarget returns true if filePath is a write target for a
// known system binary in a trusted directory.
func isSystemBinaryTarget(filePath string) bool {
	base := path.Base(filePath)
	if !systemBinaryNames[base] {
		return false
	}
	dir := path.Dir(filePath) + "/"
	return dir == "/usr/local/bin/" || dir == "/usr/bin/" || dir == "/bin/" || dir == "/sbin/"
}

// isHomeDir returns true if the path is inside a user home directory.
func isHomeDir(filePath string) bool {
	return strings.HasPrefix(filePath, "/home/") || strings.HasPrefix(filePath, "/root/")
}

// isBenignInstalledPackageWrite filters openat events whose target is
// either (a) a directory belonging to one of the scanned packages
// themselves (self-write — legitimate build output, native compile
// artifacts) or (b) npm's own bookkeeping under
// /install/node_modules/.<x> (.package-lock.json, .bin/, .cache/).
//
// Cross-package writes — the target package is NOT in scannedPkgs —
// fall through to classifyOpenat where the library_hijacking rule
// classifies them HIGH. Sensitive-path, home-dir, and system-binary
// writes never match the node_modules prefix and remain suspicious.
func isBenignInstalledPackageWrite(evt *types.SyscallEvent) bool {
	if !strings.HasPrefix(evt.FilePath, "/install/node_modules/") {
		// Not a node_modules write — sensitive/home/system-binary
		// event, unconditionally suspicious.
		return false
	}
	// npm bookkeeping under .<x> — never an attacker-installed package.
	rest := evt.FilePath[len("/install/node_modules/"):]
	if rest == "" || rest[0] == '.' {
		return true
	}
	// Self-write: the target package is in the scan set.
	if pkg := extractNpmInstalledPkg(evt.FilePath); pkg != "" && scannedPkgs[pkg] {
		return true
	}
	// Cross-package write — let classifyOpenat handle it.
	return false
}

// classifyLibraryHijack handles both npm and PyPI library-hijack
// patterns. Returns true when the file path is under an installed
// package directory (in which case classification is terminal — the
// caller should return without falling through to
// classifyOpenat's default rules). Returns false when the path is
// not a library-hijack candidate.
//
// npm shape: /install/node_modules/<other_pkg>/... — any write from
// the scanned package into another package's source tree fires
// CategoryLibraryHijack HIGH.
//
// PyPI shape: /usr/local/lib/python*/site-packages/<other_pkg>/... —
// only append writes (O_APPEND) fire. pip's own wheel extraction uses
// fresh-file writes (O_WRONLY|O_CREAT|O_TRUNC, never O_APPEND) so the
// O_APPEND gate cleanly excludes pip. The parser layer additionally
// pre-filters PyPI events to O_APPEND only; the check here is
// defensive.
//
// When SetScanPkgs has not been called (scannedPkgs empty), the rule
// is inert — a candidate path still returns true so classifyOpenat
// doesn't misfire, but no category is set.
func classifyLibraryHijack(evt *types.SyscallEvent, isWrite bool) bool {
	if !isWrite {
		return false
	}
	if pkg := extractNpmInstalledPkg(evt.FilePath); pkg != "" {
		if len(scannedPkgs) > 0 && !scannedPkgs[pkg] {
			evt.Category = types.CategoryLibraryHijack
			evt.Reason = "Cross-package write into installed sibling: " + evt.FilePath +
				" — scanned package wrote into " + pkg + "'s source tree. " +
				"Backdoor placement targeting a sibling dependency; harm fires when " +
				"a later workflow imports the hijacked package."
		}
		return true
	}
	if pkg := extractPyPISitePackage(evt.FilePath); pkg != "" {
		if strings.Contains(evt.OpenFlags, "O_APPEND") &&
			len(scannedPkgs) > 0 && !scannedPkgs[pkg] {
			evt.Category = types.CategoryLibraryHijack
			evt.Reason = "Append-write into sibling package's site-packages: " + evt.FilePath +
				" — scanned package appended to " + pkg + "'s installed source. " +
				"pip's own wheel extraction uses fresh-file writes (no O_APPEND); " +
				"append into a sibling is a backdoor-placement pattern that harms " +
				"later workflows importing the hijacked package."
		}
		return true
	}
	return false
}

// extractPyPISitePackage returns the site-packages directory name
// written into when filePath is under a PyPI site-packages tree, or
// "" otherwise. Mirrors probe.isPyPISitePackageWrite in shape but
// returns the extracted package name for the library_hijack rule.
//
// Examples (SandboxPythonVersion = "3.12" — pinned to the sandbox
// image; the "python<ver>" segment tolerates future version bumps
// so the rule doesn't silently break):
//
//	/usr/local/lib/python3.12/site-packages/pip/__init__.py       -> "pip"
//	/usr/local/lib/python3.12/site-packages/urllib3/util/x.py     -> "urllib3"
//	/usr/local/lib/python3.12/site-packages/pip-24.0.dist-info/x  -> ""
//	/usr/local/lib/python3.12/site-packages/__pycache__/x         -> ""
//	/usr/local/lib/python3.12/site-packages/_distutils_hack/x.py  -> "_distutils_hack"
//	/usr/local/lib/python3.12/site-packages/pip                   -> ""  (no trailing content)
//	/tmp/site-packages/x                                          -> ""  (wrong prefix)
func extractPyPISitePackage(filePath string) string {
	const rootPrefix = "/usr/local/lib/python"
	if !strings.HasPrefix(filePath, rootPrefix) {
		return ""
	}
	afterVersion := filePath[len(rootPrefix):]
	slash := strings.IndexByte(afterVersion, '/')
	if slash <= 0 {
		return ""
	}
	const sp = "/site-packages/"
	rest := afterVersion[slash:]
	if !strings.HasPrefix(rest, sp) {
		return ""
	}
	after := rest[len(sp):]
	end := strings.IndexByte(after, '/')
	if end <= 0 {
		return ""
	}
	pkg := after[:end]
	if pkg == "__pycache__" {
		return ""
	}
	if strings.HasSuffix(pkg, ".dist-info") || strings.HasSuffix(pkg, ".egg-info") {
		return ""
	}
	return pkg
}

// extractNpmInstalledPkg returns the npm package name written into when
// filePath is under /install/node_modules/, or "" otherwise.
//
// Examples:
//
//	/install/node_modules/lodash/index.js          -> "lodash"
//	/install/node_modules/@babel/core/lib/index.js -> "@babel/core"
//	/install/node_modules/.package-lock.json       -> ""  (npm bookkeeping)
//	/install/node_modules/.bin/foo                 -> ""  (npm internal)
//	/install/node_modules/                         -> ""  (no package)
//	/install/node_modules                          -> ""  (no trailing slash content)
//	/install/foo                                   -> ""  (not under node_modules)
//
// Scoped packages (`@scope/name`) are returned with the `@scope/` prefix
// so the caller can match against scan-target names that retain the
// scope, which is the convention npm and yarn use throughout.
//
// `.`-prefixed entries (`/install/node_modules/.package-lock.json`,
// `/install/node_modules/.bin/foo`, `/install/node_modules/.cache/...`)
// are npm's own bookkeeping and never represent attacker-installed
// packages, so they return "" rather than being treated as either self
// or a hijack target. An attacker who placed a malicious binary under
// `.bin/` would be caught by the system-binary write rule when the
// install eventually places it on PATH.
func extractNpmInstalledPkg(filePath string) string {
	const prefix = "/install/node_modules/"
	if !strings.HasPrefix(filePath, prefix) {
		return ""
	}
	rest := filePath[len(prefix):]
	if rest == "" {
		return ""
	}
	// Scoped package: @scope/name/...
	if rest[0] == '@' {
		// Need at least "@scope/name" — two segments separated by /.
		first := strings.IndexByte(rest, '/')
		if first <= 0 || first == len(rest)-1 {
			return ""
		}
		second := strings.IndexByte(rest[first+1:], '/')
		if second < 0 {
			// `/install/node_modules/@scope/name` with no trailing slash
			// is still a valid package directory write target.
			return rest
		}
		return rest[:first+1+second]
	}
	// Regular package: name/... or just "name" with no trailing slash.
	end := strings.IndexByte(rest, '/')
	pkg := rest
	if end >= 0 {
		pkg = rest[:end]
	}
	// npm internal entries always start with `.` (`.package-lock.json`,
	// `.bin/`, `.cache/`, etc.). Real package names cannot start with `.`.
	if pkg == "" || pkg[0] == '.' {
		return ""
	}
	return pkg
}

// classifyExecve categorizes an execve event that survived isBenignExec.
//
// Design decision (2026-05): the residual "default" branch — execve of
// any binary that doesn't match a positive attack signature — is
// recorded as CategoryUnknownBinary / LOW rather than HIGH. The change
// addresses two problems surfaced by clean-corpus FP measurement:
//
//  1. There is no closed positive definition of "legitimate execve
//     during install" — the legitimate set spans coreutils, language
//     runtimes, compiler toolchains (gcc/cc/ld/as/ar/make/cmake/ninja/
//     autoconf/...), VCS tools, and arbitrary preinstall hook commands.
//     Maintaining an allowlist of binary names would be open-ended and
//     brittle; every new ecosystem or build tool would force a list
//     update.
//
//  2. The harm-firing syscalls of every meaningful execve-driven attack
//     (network connect, sensitive-path openat, persistence write,
//     mprotect RWX, /tmp exec, bind/listen) are observed independently
//     and carry their own HIGH categories. Treating "execve of an
//     unrecognized binary" as suspicious by itself produces noise
//     (build toolchain, package-manager scaffolding) without unique
//     signal — the actual harm, if any, is caught by other rules when
//     the binary actually does something.
//
// What stays HIGH (the cmdline shape itself names an attack):
//   - execve from /dev/shm or /proc/self/fd  -> fileless attack
//   - interpreter with inline -c/-e flag     -> inline code injection
//
// What is now LOW (CategoryUnknownBinary):
//   - unrecognized binary execve             -> the binary's behavior
//     decides the verdict, not the cmdline string.
//   - sh -c that fails isShellCmdBenign      -> originally HIGH because
//     the benign-check failure was treated as an attack signature.
//     Demoted in 2026-05 after clean-corpus measurement showed every
//     legitimate native-module package (argon2/bcrypt/sharp/...) fires
//     this branch via cross-env / node-gyp-build / prebuild-install
//     preinstall hooks. Expanding the safe-list to cover ecosystem
//     build tools recreates the open-ended allowlist problem the
//     default-branch demotion was designed to avoid. Each previously-
//     caught attack pattern has a downstream harm-firing rule:
//   - curl/wget execve  -> connect to remote -> c2_communication
//   - env curl X        -> same
//   - $() / “ substitution -> spawned process's syscalls
//   - find -exec /tmp/payload -> /tmp execve fires fileless rule
//   - cp /tmp/x /usr/local/bin/python3 -> openat write fires
//     binary_hijacking (parser emits openat specifically for
//     system-binary targets)
//   - sh -c "cat ~/.ssh/id_rsa" -> openat sensitive fires
//     credential_access
//
// Static-analysis tooling (GuardDog and similar) covers orthogonal
// gaps that kojuto cannot reach at runtime: time-bombed payloads
// beyond the scan timeout, function-call-gated logic that import does
// not exercise, typosquatting, and registry metadata anomalies. The
// dynamic/static split is intentional; this decision keeps dynamic
// detection focused on what only dynamic can see.
//
// What is lost: "execve a native binary that performs only
// undetectable computation" (mining without a pool, local fork-bombs,
// time-delay only). These are out of scope per SECURITY.md known
// limitations and are addressed by sandbox containment
// (--network=none, --read-only, pids-limit) rather than by detection
// rules.
//
// Probe-scaffolding handling: kojuto's own outer shell that drives
// the install will be invoked by a file path rather than `sh -c
// <inline>`, so the outer event is filtered as benign at isBenignExec
// time. That refactor is tracked as a separate change in sandbox.go
// and is NOT covered by this rule — see InstallCommand for the launch
// contract.
func classifyExecve(evt *types.SyscallEvent) {
	cmdline := evt.Cmdline
	base := path.Base(evt.Comm)
	dir := path.Dir(evt.Comm) + "/"

	// Execution from suspicious directories (fileless attack). HIGH.
	for _, d := range suspiciousExecDirs {
		if strings.HasPrefix(dir, d) {
			evt.Category = types.CategoryCodeExecution
			evt.Reason = "Execution from suspicious path: " + evt.Comm +
				" — indicates fileless attack or payload staged in memory-backed filesystem."
			return
		}
	}

	// Inline code execution via interpreter -c/-e flag. HIGH.
	if hasInlineExecFlag(cmdline, interpreterExecFlags[base]) {
		evt.Category = types.CategoryCodeExecution
		evt.Reason = base + " executed with inline code flag (-c/-e). " +
			"Legitimate packages use script files, not inline code injection."
		return
	}

	// Shell command analysis. Reaching here means isShellCmdBenign
	// already returned false — the command failed the negative-space
	// check (non-shellSafe token, sensitive-path arg, binary-hijack
	// file op, or substitution construct). Recorded for forensic
	// chain visibility; the verdict is driven by the downstream
	// syscall-level rules that catch the actual harm — see the
	// rationale block above for the mapping from each attack pattern
	// to its dedicated HIGH-severity rule.
	if shells[base] && hasInlineExecFlag(cmdline, []string{" -c "}) {
		evt.Category = types.CategoryUnknownBinary
		evt.Reason = "Shell command: " + truncate(cmdline, 200) +
			" — recorded for forensic chain visibility. Verdict-flipping " +
			"signals (network, credential read, persistence, binary hijack, RWX) " +
			"are emitted by their own syscall-level rules when the command runs."
		return
	}

	// Residual execve. Recorded for chain visibility; verdict decided by
	// the syscall-level rules that observe the binary's actual behavior.
	evt.Category = types.CategoryUnknownBinary
	evt.Reason = "Unrecognized binary execution: " + truncate(cmdline, 200) +
		" — recorded for forensic chain visibility. No positive attack " +
		"signature in the execve itself; verdict is decided by the " +
		"syscall-level rules that observe the binary's runtime behavior."
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
		// Parser emits openat for sensitive paths, home writes, system
		// binary writes, and installed-package writes. The first three
		// are unconditionally suspicious in install context. Installed-
		// package writes split: self-pkg writes are legitimate build
		// output (e.g. argon2/build/Release/argon2.node), npm
		// bookkeeping (.package-lock.json, .bin/) is also legitimate,
		// and only cross-package writes flow on to classifyOpenat
		// where the library_hijacking rule fires.
		return isBenignInstalledPackageWrite(evt)
	case types.EventRename:
		return isBenignRename(evt)
	case types.EventMmap, types.EventMprotect:
		// RWX memory is never benign in package install/import context.
		return false
	case types.EventUnlink:
		// Parser already filters to only emit deletions from suspicious dirs.
		return false
	case types.EventClone:
		// Clone events are pure PID-correlation signal consumed by
		// collectPIDComm; they carry no harm and never flip the verdict
		// even if they reach the report. Drop them here.
		return true
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

	// DNS query checks: even if the DNS server IP is benign (e.g. 8.8.8.8),
	// the query domain itself may be carrying exfiltrated data or resolving
	// a known exfiltration service (Discord webhooks, Telegram bots, etc.).
	if evt.DNSQuery != "" {
		if matchExfilService(evt.DNSQuery) != "" || isDNSTunnel(evt.DNSQuery) {
			return false
		}
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
	"/tmp/",          // world-writable tmpfs — classic payload drop target
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
	allowedDirs, ok := benignPaths[destBase]
	if !ok {
		return true
	}

	// Basename-only DstPath (no leading "/") means the probe captured
	// only the dentry name and not the parent directory — the eBPF
	// probe takes this shape because vfs_rename's renamedata gives us
	// d_name (a qstr basename) rather than a full path. Without the
	// parent we cannot prove the rename targets a trusted directory,
	// so fail-safe: a rename whose basename matches a tracked binary
	// (python3, node, sh, ...) stays suspicious. Strace mode emits
	// absolute paths and falls through to the directory check below.
	if !strings.HasPrefix(evt.DstPath, "/") {
		return false
	}

	destDir := path.Dir(evt.DstPath) + "/"
	for _, d := range allowedDirs {
		if destDir == d {
			return false
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

// knownExfilDomains maps domain suffixes to human-readable service names.
// These are legitimate services frequently abused by threat actors to exfiltrate
// stolen credentials, wallet keys, and environment variables.
var knownExfilDomains = []struct {
	suffix  string
	service string
}{
	// Chat platforms (primary info-stealer exfil channel).
	{"discord.com", "Discord"},
	{"discordapp.com", "Discord"},
	{"discord.gg", "Discord"},
	// Telegram Bot API.
	{"api.telegram.org", "Telegram"},
	{"telegram.org", "Telegram"},
	// Paste / code sharing services.
	{"pastebin.com", "Pastebin"},
	{"hastebin.com", "Hastebin"},
	{"paste.ee", "Paste.ee"},
	{"dpaste.org", "dpaste"},
	{"ghostbin.com", "Ghostbin"},
	{"rentry.co", "Rentry"},
	{"paste.rs", "paste.rs"},
	// Webhook relay services.
	{"webhook.site", "Webhook.site"},
	{"pipedream.net", "Pipedream"},
	{"hookbin.com", "Hookbin"},
	{"requestbin.com", "RequestBin"},
	// File hosting (used for stage-2 download AND exfil upload).
	{"transfer.sh", "transfer.sh"},
	{"file.io", "file.io"},
	{"0x0.st", "0x0.st"},
	// IP / geo lookup (recon before exfil).
	{"ipinfo.io", "ipinfo.io"},
	{"ifconfig.me", "ifconfig.me"},
	{"ipapi.co", "ipapi.co"},
	{"ip-api.com", "ip-api.com"},
	{"checkip.amazonaws.com", "checkip.amazonaws.com"},
}

// matchExfilService checks whether a DNS query domain matches a known
// data exfiltration service. Returns the service name or "" if no match.
func matchExfilService(query string) string {
	lower := strings.ToLower(query)
	for _, d := range knownExfilDomains {
		if lower == d.suffix || strings.HasSuffix(lower, "."+d.suffix) {
			return d.service
		}
	}
	return ""
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

// isDNSTunnel returns true if the DNS query domain shows signs of data exfiltration.
//
// No whitelist. The entropy heuristic alone distinguishes legitimate domains
// from encoded exfil payloads. Whitelists are a liability — if this repo is
// compromised, an attacker could add their exfil domain to bypass detection.
//
// Legitimate package registry domains (pypi.org, npmjs.org) have short,
// low-entropy labels that never trigger the heuristic:
//
//	files.pythonhosted.org      → "files" entropy ≈ 2.3 bits/char  (< 3.5)
//	registry.npmjs.org          → "registry" entropy ≈ 2.8 bits/char (< 3.5)
//
// Encoded exfil payloads have high-entropy labels:
//
//	aGVsbG8gd29ybGQ.evil.com   → "aGVsbG8gd29ybGQ" entropy ≈ 3.8 bits/char (> 3.5)
func isDNSTunnel(query string) bool {
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
