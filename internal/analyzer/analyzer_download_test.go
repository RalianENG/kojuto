package analyzer

import (
	"strings"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

// The download phase runs `pip download` / `npm install --ignore-scripts`
// inside the network-enabled download sandbox. Its events are stamped with
// types.PhaseDownload and routed through classifyDownloadEvent, which differs
// from the install/import rules in two ways: network egress is expected (the
// phase fetches from the registry), and no package code should execute.

// --- network egress -------------------------------------------------------

// TestAnalyze_DownloadConnectIsLow pins Option A: a plain outbound connect
// during the download phase is recorded for forensic visibility but never
// flips the verdict — the download phase legitimately reaches the registry
// and its CDN, and a bare-IP destination cannot be condemned without a
// trusted resolver.
func TestAnalyze_DownloadConnectIsLow(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "151.101.0.223", DstPort: 443, Family: 2, Phase: types.PhaseDownload},
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("verdict = %s, want clean (a registry connect must not flip the verdict)", verdict)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected the connect recorded for forensics, got %d events", len(filtered))
	}
	if filtered[0].Category != types.CategoryDownloadEgress {
		t.Errorf("category = %q, want %q", filtered[0].Category, types.CategoryDownloadEgress)
	}
	if !strings.Contains(filtered[0].Reason, "151.101.0.223") {
		t.Errorf("reason should name the destination, got %q", filtered[0].Reason)
	}
}

// TestAnalyze_DownloadEgressOnlyStaysClean confirms a download that only
// fetches packages — many connects, nothing else — stays clean. download_egress
// is LOW and never flips the verdict on its own, no matter how many fire.
func TestAnalyze_DownloadEgressOnlyStaysClean(t *testing.T) {
	var events []types.SyscallEvent
	for _, ip := range []string{"151.101.0.223", "104.16.1.35", "151.101.64.223", "104.16.2.35"} {
		events = append(events, types.SyscallEvent{
			Syscall: types.EventConnect, DstAddr: ip, DstPort: 443, Family: 2, Phase: types.PhaseDownload,
		})
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("verdict = %s, want clean (registry-egress-only download)", verdict)
	}
	if len(filtered) != len(events) {
		t.Errorf("expected all %d connects recorded for forensics, got %d", len(events), len(filtered))
	}
}

// TestAnalyze_DownloadConnectLoopbackDropped — loopback/link-local connects
// are never interesting, in any phase.
func TestAnalyze_DownloadConnectLoopbackDropped(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "127.0.0.1", DstPort: 80, Family: 2, Phase: types.PhaseDownload},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean || len(filtered) != 0 {
		t.Errorf("loopback download connect: verdict=%s events=%d, want clean/0", verdict, len(filtered))
	}
}

// TestAnalyze_DownloadExfilServiceStillHigh — the whitelist-free heuristics
// still fire during download. A connect whose DNS query resolves a known
// exfil service keeps its data_exfiltration (HIGH) category.
func TestAnalyze_DownloadExfilServiceStillHigh(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventSendto, DstAddr: "162.159.128.233", DstPort: 443, Family: 2,
			DNSQuery: "discord.com", Phase: types.PhaseDownload},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (exfil-service connect during download)", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryDataExfil {
		t.Fatalf("expected 1 data_exfiltration event, got %+v", filtered)
	}
}

// TestAnalyze_DownloadDNSTunnelStillFlagged — high-entropy DNS subdomains
// during download keep the dns_tunneling category.
func TestAnalyze_DownloadDNSTunnelStillFlagged(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventSendto, DstAddr: "8.8.8.8", DstPort: 53, Family: 2,
			DNSQuery: "aGVsbG8gd29ybGQgZXhmaWw.attacker.example.com", Phase: types.PhaseDownload},
	}
	_, filtered := Analyze(events)
	if len(filtered) != 1 || filtered[0].Category != types.CategoryDNSTunnel {
		t.Fatalf("expected 1 dns_tunneling event, got %+v", filtered)
	}
}

// --- execve ---------------------------------------------------------------

// TestAnalyze_DownloadExecveFromStagingDirIsHigh — the core download-phase
// rule. `--ignore-scripts` / `--only-binary` mean nothing in the staging
// directory should ever execute; a binary running from /out/ is a
// freshly-downloaded artifact executing mid-download (an unpacking-time
// exploit).
func TestAnalyze_DownloadExecveFromStagingDirIsHigh(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/out/node_modules/evil/postinstall-payload",
			Cmdline: "postinstall-payload", PID: 4242, Phase: types.PhaseDownload},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (execve from the staging dir)", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryCodeExecution {
		t.Fatalf("expected 1 code_execution event, got %+v", filtered)
	}
	if !strings.Contains(filtered[0].Reason, "/out/node_modules/evil/postinstall-payload") {
		t.Errorf("reason should name the executed path, got %q", filtered[0].Reason)
	}
}

// TestAnalyze_DownloadExecveBenignPackageManager — pip/npm/node from trusted
// system directories are the download phase doing its job.
func TestAnalyze_DownloadExecveBenignPackageManager(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/usr/local/bin/pip", Cmdline: "pip download requests", Phase: types.PhaseDownload},
		{Syscall: types.EventExecve, Comm: "/usr/local/bin/npm", Cmdline: "npm install --ignore-scripts", Phase: types.PhaseDownload},
		{Syscall: types.EventExecve, Comm: "/usr/local/bin/node", Cmdline: "node", Phase: types.PhaseDownload},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean || len(filtered) != 0 {
		t.Errorf("benign package-manager execve: verdict=%s events=%d, want clean/0", verdict, len(filtered))
	}
}

// TestAnalyze_DownloadExecveFromTmpIsHigh — the install/import suspicious-dir
// rule still applies to non-staging paths during download.
func TestAnalyze_DownloadExecveFromTmpIsHigh(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventExecve, Comm: "/tmp/dropper", Cmdline: "/tmp/dropper", PID: 99, Phase: types.PhaseDownload},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (execve from /tmp during download)", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryCodeExecution {
		t.Fatalf("expected 1 code_execution event, got %+v", filtered)
	}
}

// --- staging-dir escapes (the "展開挙動" the user asked to watch) -----------

// TestAnalyze_DownloadHomeWriteIsHigh — a write that escapes the staging dir
// into $HOME is a tarball path-traversal; the install/import persistence rule
// applies unchanged.
func TestAnalyze_DownloadHomeWriteIsHigh(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/home/dev/.bashrc", OpenFlags: "O_WRONLY|O_CREAT", Phase: types.PhaseDownload},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (download write escaping into $HOME)", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryPersistence {
		t.Fatalf("expected 1 persistence event, got %+v", filtered)
	}
}

// TestAnalyze_DownloadSystemBinaryWriteIsHigh — overwriting a trusted system
// binary during download is a binary hijack; the rule applies unchanged.
func TestAnalyze_DownloadSystemBinaryWriteIsHigh(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, FilePath: "/usr/local/bin/python3", OpenFlags: "O_WRONLY|O_TRUNC", Phase: types.PhaseDownload},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (download write onto a system binary)", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryBinaryHijack {
		t.Fatalf("expected 1 binary_hijacking event, got %+v", filtered)
	}
}

// TestAnalyze_DownloadBindIsHigh — pip/npm never open server sockets; a
// bind/listen during download is a backdoor regardless of phase.
func TestAnalyze_DownloadBindIsHigh(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventBind, DstPort: 4444, Phase: types.PhaseDownload},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (bind during download)", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryBackdoor {
		t.Fatalf("expected 1 backdoor event, got %+v", filtered)
	}
}

// TestAnalyze_DownloadCloneDropped — clone is pure PID-correlation signal,
// dropped in every phase.
func TestAnalyze_DownloadCloneDropped(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventClone, PID: 1, ChildPID: 2, Phase: types.PhaseDownload},
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean || len(filtered) != 0 {
		t.Errorf("download clone: verdict=%s events=%d, want clean/0", verdict, len(filtered))
	}
}

// --- phase isolation ------------------------------------------------------

// TestAnalyze_DownloadProfileDoesNotLeakIntoInstall is the regression guard
// for the phase routing: the same connect syscall is LOW download_egress
// when stamped PhaseDownload and HIGH c2_communication when it is not.
func TestAnalyze_DownloadProfileDoesNotLeakIntoInstall(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventConnect, DstAddr: "203.0.113.50", DstPort: 443, Family: 2, Phase: types.PhaseDownload},
		{Syscall: types.EventConnect, DstAddr: "203.0.113.99", DstPort: 443, Family: 2}, // install phase (Phase unset)
	}
	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (the install-phase connect is C2)", verdict)
	}
	if len(filtered) != 2 {
		t.Fatalf("expected both connects recorded, got %d", len(filtered))
	}
	byAddr := map[string]string{}
	for _, e := range filtered {
		byAddr[e.DstAddr] = e.Category
	}
	if byAddr["203.0.113.50"] != types.CategoryDownloadEgress {
		t.Errorf("download connect category = %q, want %q", byAddr["203.0.113.50"], types.CategoryDownloadEgress)
	}
	if byAddr["203.0.113.99"] != types.CategoryC2 {
		t.Errorf("install connect category = %q, want %q", byAddr["203.0.113.99"], types.CategoryC2)
	}
}

// TestCategoryShortDesc_DownloadEgress — the new category has a terse CLI
// breakdown label rather than falling through to the raw category string.
func TestCategoryShortDesc_DownloadEgress(t *testing.T) {
	desc := categoryShortDesc(types.CategoryDownloadEgress)
	if desc == types.CategoryDownloadEgress || desc == "" {
		t.Errorf("categoryShortDesc(%q) = %q, want a human-readable label", types.CategoryDownloadEgress, desc)
	}
}

// --- environment probes ---------------------------------------------------

// TestAnalyze_DownloadProcSelfReadsStayClean is the regression test for the
// npm false positive that made npm scanning unusable: node reads
// /proc/self/cgroup and /proc/self/maps on every startup, and during download
// those reads belong to npm, not to the scanned package — `--ignore-scripts`
// means no package code runs at all in this phase. Classifying them as MEDIUM
// evasion put exactly two MEDIUM events on every npm scan, landing precisely
// on the "2+ MEDIUM → suspicious" threshold: a 96-package measurement of
// popular npm packages reported 94 suspicious, every one of them carrying
// `evasion: 2` and nothing else above LOW.
func TestAnalyze_DownloadProcSelfReadsStayClean(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, PID: 100, FilePath: "/proc/self/cgroup", OpenFlags: "O_RDONLY", Phase: types.PhaseDownload},
		{Syscall: types.EventOpenat, PID: 100, FilePath: "/proc/self/maps", OpenFlags: "O_RDONLY", Phase: types.PhaseDownload},
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("verdict = %s, want clean (the package manager's own /proc reads)", verdict)
	}
	if len(filtered) != 2 {
		t.Fatalf("expected both reads recorded for forensics, got %d events", len(filtered))
	}
	for i := range filtered {
		if filtered[i].Category != types.CategoryEnvProbe {
			t.Errorf("event %d category = %q, want %q", i, filtered[i].Category, types.CategoryEnvProbe)
		}
	}
	if !strings.Contains(filtered[0].Reason, "/proc/self/cgroup") {
		t.Errorf("reason should name the probed path, got %q", filtered[0].Reason)
	}
}

// TestAnalyze_ProcSelfReadsOutsideDownloadStayEvasion guards the other half of
// the phase split. The download exemption rests entirely on "no package code
// executes during download"; during install and import package code IS
// running, so the identical reads remain a sandbox-detection cluster.
func TestAnalyze_ProcSelfReadsOutsideDownloadStayEvasion(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, PID: 100, FilePath: "/proc/self/cgroup", OpenFlags: "O_RDONLY"},
		{Syscall: types.EventOpenat, PID: 100, FilePath: "/proc/self/maps", OpenFlags: "O_RDONLY"},
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (two distinct sandbox-detection paths)", verdict)
	}
	for i := range filtered {
		if filtered[i].Category != types.CategoryEvasion {
			t.Errorf("event %d category = %q, want %q", i, filtered[i].Category, types.CategoryEvasion)
		}
	}
}

// TestAnalyze_DownloadSensitiveReadStillHigh confirms the download-phase
// openat branch exempts environment probes only: a credential read during
// download is still HIGH, because nothing about `pip download` explains
// opening the user's SSH key.
func TestAnalyze_DownloadSensitiveReadStillHigh(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, PID: 100, FilePath: "/home/dev/.ssh/id_rsa", OpenFlags: "O_RDONLY", Phase: types.PhaseDownload},
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (credential read during download)", verdict)
	}
	if len(filtered) != 1 || filtered[0].Category != types.CategoryCredentialAccess {
		t.Fatalf("expected one credential_access event, got %+v", filtered)
	}
}

// TestAnalyze_EnvProbeBaselineCarriesIntoInstall is the npm scan shape end to
// end. node reads /proc/self/cgroup and /proc/self/maps when npm starts during
// download, and reads them again when the install phase drives the lifecycle
// hooks. The download reads prove those paths are the tooling's own, so the
// install-phase repeat is baseline noise too — otherwise every npm scan lands
// on exactly the "2+ MEDIUM" threshold with no package behavior behind it.
func TestAnalyze_EnvProbeBaselineCarriesIntoInstall(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, PID: 15, FilePath: "/proc/self/cgroup", OpenFlags: "O_RDONLY", Phase: types.PhaseDownload},
		{Syscall: types.EventOpenat, PID: 15, FilePath: "/proc/self/maps", OpenFlags: "O_RDONLY", Phase: types.PhaseDownload},
		// Install phase: npm again, different PID, same two paths.
		{Syscall: types.EventOpenat, PID: 156, FilePath: "/proc/self/cgroup", OpenFlags: "O_RDONLY"},
		{Syscall: types.EventOpenat, PID: 156, FilePath: "/proc/self/maps", OpenFlags: "O_RDONLY"},
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictClean {
		t.Errorf("verdict = %s, want clean (npm's own startup reads in both phases)", verdict)
	}
	for i := range filtered {
		if filtered[i].Category != types.CategoryEnvProbe {
			t.Errorf("event %d category = %q, want %q", i, filtered[i].Category, types.CategoryEnvProbe)
		}
	}
	// Deduped per path, so the four reads collapse to two breadcrumbs.
	if len(filtered) != 2 {
		t.Errorf("expected 2 deduped env_probe events, got %d: %+v", len(filtered), filtered)
	}
}

// TestAnalyze_EvasionOutsideBaselineStillFires bounds the exemption: only the
// paths the package manager demonstrably touched are excused. /proc/self/status
// (TracerPid — the read that reveals strace) and /proc/self/mountinfo are not in
// npm's baseline, so probing them is still a sandbox-detection cluster.
func TestAnalyze_EvasionOutsideBaselineStillFires(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, PID: 15, FilePath: "/proc/self/cgroup", OpenFlags: "O_RDONLY", Phase: types.PhaseDownload},
		{Syscall: types.EventOpenat, PID: 15, FilePath: "/proc/self/maps", OpenFlags: "O_RDONLY", Phase: types.PhaseDownload},
		{Syscall: types.EventOpenat, PID: 156, FilePath: "/proc/self/status", OpenFlags: "O_RDONLY"},
		{Syscall: types.EventOpenat, PID: 156, FilePath: "/proc/self/mountinfo", OpenFlags: "O_RDONLY"},
	}

	verdict, filtered := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Fatalf("verdict = %s, want suspicious (two probed paths outside the baseline)", verdict)
	}
	var evasion int
	for i := range filtered {
		if filtered[i].Category == types.CategoryEvasion {
			evasion++
		}
	}
	if evasion != 2 {
		t.Errorf("expected 2 evasion events, got %d: %+v", evasion, filtered)
	}
}

// TestAnalyze_EnvProbeBaselineIsPerScan confirms the exemption is measured, not
// assumed: with no download phase in the event stream (a --local scan of a file
// already on disk), the same two reads are ordinary sandbox detection.
func TestAnalyze_EnvProbeBaselineIsPerScan(t *testing.T) {
	events := []types.SyscallEvent{
		{Syscall: types.EventOpenat, PID: 156, FilePath: "/proc/self/cgroup", OpenFlags: "O_RDONLY"},
		{Syscall: types.EventOpenat, PID: 156, FilePath: "/proc/self/maps", OpenFlags: "O_RDONLY"},
	}

	verdict, _ := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %s, want suspicious (no download phase, so no baseline)", verdict)
	}
}
