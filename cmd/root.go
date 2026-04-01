package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/RalianENG/kojuto/internal/analyzer"
	"github.com/RalianENG/kojuto/internal/depfile"
	"github.com/RalianENG/kojuto/internal/downloader"
	"github.com/RalianENG/kojuto/internal/probe"
	"github.com/RalianENG/kojuto/internal/report"
	"github.com/RalianENG/kojuto/internal/sandbox"
	"github.com/RalianENG/kojuto/internal/types"
)

const (
	methodAuto            = "auto"
	methodEBPF            = "ebpf"
	methodStrace          = "strace"
	methodStraceContainer = "strace-container"
	eventDrainDelay       = 500 * time.Millisecond

	exitCodeSuspicious = 2
)

var (
	flagVersion     string
	flagOutput      string
	flagProbeMethod string
	flagEcosystem   string
	flagFile        string
	flagPin         string
	flagTimeout     time.Duration
)

var rootCmd = &cobra.Command{
	Use:   "kojuto",
	Short: "Supply chain attack detection tool",
	Long:  "Detect suspicious network activity during package installation by running packages in an isolated sandbox with syscall monitoring.",
}

var scanCmd = &cobra.Command{
	Use:          "scan [package]",
	Short:        "Scan a package or dependency file for suspicious syscall activity",
	Args:         cobra.MaximumNArgs(1),
	RunE:         runScan,
	SilenceUsage: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("kojuto v0.3.0")
	},
}

func init() {
	scanCmd.Flags().StringVarP(&flagVersion, "version", "v", "", "package version to scan")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "output file path (default: stdout)")
	scanCmd.Flags().StringVarP(&flagEcosystem, "ecosystem", "e", types.EcosystemPyPI, "ecosystem: pypi, npm")
	scanCmd.Flags().StringVarP(&flagFile, "file", "f", "", "dependency file to scan (requirements.txt or package.json)")
	scanCmd.Flags().StringVar(&flagPin, "pin", "", "output pinned dependency file after all-clean scan (requires -f)")
	scanCmd.Flags().StringVar(&flagProbeMethod, "probe-method", methodAuto, "probe method: auto, ebpf, strace, strace-container")
	scanCmd.Flags().DurationVar(&flagTimeout, "timeout", 5*time.Minute, "scan timeout per package")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

// VerdictError is returned when the scan verdict is not clean.
type VerdictError struct {
	Verdict  string
	ExitCode int
}

func (e *VerdictError) Error() string {
	return "verdict: " + e.Verdict
}

// Execute runs the root command.
func Execute() {
	err := rootCmd.Execute()
	if err == nil {
		return
	}

	var ve *VerdictError
	if errors.As(err, &ve) {
		os.Exit(ve.ExitCode)
	}

	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

type scanResult struct {
	method      string
	events      []types.SyscallEvent
	lostSamples uint64
}

func runScan(_ *cobra.Command, args []string) error {
	// Batch mode: scan all packages from a dependency file.
	if flagFile != "" {
		return runBatchScan(args)
	}

	// Single package mode.
	if len(args) == 0 {
		return errors.New("either provide a package name or use -f <file>")
	}

	_, err := scanSinglePackage(args[0], flagVersion, flagEcosystem)
	return err
}

// pinnedDep holds a resolved package name and version after a clean scan.
type pinnedDep struct {
	Name    string
	Version string
}

func scanSinglePackage(pkg, version, ecosystem string) (*pinnedDep, error) {
	if err := downloader.ValidatePackage(pkg, version); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if ecosystem != types.EcosystemPyPI && ecosystem != types.EcosystemNpm {
		return nil, fmt.Errorf("unsupported ecosystem: %s (use pypi or npm)", ecosystem)
	}

	ctx, cancel := context.WithTimeout(context.Background(), flagTimeout)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	go func() {
		<-sigCh
		cancel()
	}()

	flagVersion = version
	flagEcosystem = ecosystem

	dlDir, err := downloadPackage(ctx, pkg)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(filepath.Dir(dlDir))

	// Capture resolved version after download (may have been detected from filename).
	resolvedVersion := flagVersion

	method := selectProbeMethod()

	sb, err := startSandbox(ctx, dlDir, pkg, method)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if cleanupErr := sb.Cleanup(cleanupCtx); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Cleanup warning: %v\n", cleanupErr)
		}
	}()

	result, err := runProbeAndInstall(ctx, sb, pkg, method)
	if err != nil {
		return nil, err
	}

	if err := outputReport(pkg, result); err != nil {
		return nil, err
	}

	return &pinnedDep{Name: pkg, Version: resolvedVersion}, nil
}

func runBatchScan(_ []string) error {
	deps, ecosystem, err := depfile.Parse(flagFile)
	if err != nil {
		return err
	}

	if len(deps) == 0 {
		return fmt.Errorf("no dependencies found in %s", flagFile)
	}

	// Allow ecosystem override from -e flag if explicitly set.
	if flagEcosystem != types.EcosystemPyPI {
		ecosystem = flagEcosystem
	}

	if flagPin != "" && flagFile == "" {
		return errors.New("--pin requires -f <file>")
	}

	fmt.Fprintf(os.Stderr, "[*] Scanning %d packages from %s (%s)...\n", len(deps), flagFile, ecosystem)

	var suspicious []string
	var scanErrors []string
	var pinned []pinnedDep

	for i, dep := range deps {
		fmt.Fprintf(os.Stderr, "\n[%d/%d] Scanning %s", i+1, len(deps), dep.Name)
		if dep.Version != "" {
			fmt.Fprintf(os.Stderr, " (%s)", dep.Version)
		}
		fmt.Fprintln(os.Stderr)

		resolved, scanErr := scanSinglePackage(dep.Name, dep.Version, ecosystem)
		if scanErr != nil {
			var ve *VerdictError
			if errors.As(scanErr, &ve) {
				suspicious = append(suspicious, dep.Name)
			} else {
				fmt.Fprintf(os.Stderr, "[!] Error scanning %s: %v\n", dep.Name, scanErr)
				scanErrors = append(scanErrors, dep.Name)
			}
		} else if resolved != nil {
			pinned = append(pinned, *resolved)
		}
	}

	// Summary.
	fmt.Fprintf(os.Stderr, "\n=== Batch scan complete ===\n")
	fmt.Fprintf(os.Stderr, "  Total:      %d\n", len(deps))
	fmt.Fprintf(os.Stderr, "  Clean:      %d\n", len(deps)-len(suspicious)-len(scanErrors))
	fmt.Fprintf(os.Stderr, "  Suspicious: %d\n", len(suspicious))
	fmt.Fprintf(os.Stderr, "  Errors:     %d\n", len(scanErrors))

	if len(suspicious) > 0 {
		fmt.Fprintf(os.Stderr, "  Flagged:    %s\n", strings.Join(suspicious, ", "))
		if flagPin != "" {
			fmt.Fprintf(os.Stderr, "[!] --pin refused: suspicious packages detected\n")
		}
		return &VerdictError{Verdict: types.VerdictSuspicious, ExitCode: exitCodeSuspicious}
	}

	if len(scanErrors) > 0 {
		if flagPin != "" {
			fmt.Fprintf(os.Stderr, "[!] --pin refused: scan errors occurred\n")
		}
		return fmt.Errorf("scan failed for: %s", strings.Join(scanErrors, ", "))
	}

	// All clean — generate pinned dependency file if requested.
	if flagPin != "" {
		if err := writePinnedFile(flagPin, pinned, ecosystem); err != nil {
			return fmt.Errorf("writing pinned file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[+] Pinned %d packages to %s\n", len(pinned), flagPin)
	}

	return nil
}

// writePinnedFile writes a locked dependency file with exact versions.
// For PyPI: requirements.txt format (pkg==version).
// For npm: package.json format with pinned dependencies.
func writePinnedFile(path string, deps []pinnedDep, ecosystem string) error {
	switch ecosystem {
	case types.EcosystemPyPI:
		return writePinnedPyPI(path, deps)
	case types.EcosystemNpm:
		return writePinnedNpm(path, deps)
	default:
		return fmt.Errorf("unsupported ecosystem for pin: %s", ecosystem)
	}
}

func writePinnedPyPI(path string, deps []pinnedDep) error {
	var b strings.Builder
	b.WriteString("# Pinned by kojuto — all packages scanned clean\n")
	for _, dep := range deps {
		if dep.Version != "" {
			fmt.Fprintf(&b, "%s==%s\n", dep.Name, dep.Version)
		} else {
			fmt.Fprintf(&b, "%s\n", dep.Name)
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writePinnedNpm(path string, deps []pinnedDep) error {
	pinned := make(map[string]string, len(deps))
	for _, dep := range deps {
		if dep.Version != "" {
			pinned[dep.Name] = dep.Version
		} else {
			pinned[dep.Name] = "*"
		}
	}

	data := map[string]interface{}{
		"name":         "pinned-by-kojuto",
		"private":      true,
		"dependencies": pinned,
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling pinned package.json: %w", err)
	}
	jsonBytes = append(jsonBytes, '\n')

	return os.WriteFile(path, jsonBytes, 0o644)
}

func downloadPackage(ctx context.Context, pkg string) (string, error) {
	fmt.Fprintf(os.Stderr, "[*] Downloading %s (%s)...\n", pkg, flagEcosystem)

	tmpDir, err := os.MkdirTemp("", "kojuto-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	dlDir := filepath.Join(tmpDir, "packages")
	if mkErr := os.MkdirAll(dlDir, 0o755); mkErr != nil {
		return "", fmt.Errorf("creating download dir: %w", mkErr)
	}

	if _, dlErr := downloader.Download(ctx, pkg, flagVersion, dlDir, flagEcosystem); dlErr != nil {
		return "", fmt.Errorf("downloading package: %w", dlErr)
	}

	if flagVersion == "" {
		flagVersion = downloader.DetectVersion(dlDir, pkg)
	}

	return dlDir, nil
}

func selectProbeMethod() string {
	method := flagProbeMethod
	if method != methodAuto {
		return method
	}

	// Prefer strace-container for broadest syscall coverage (connect, sendto,
	// sendmsg, execve). eBPF only hooks connect — it is faster but has blind
	// spots for sendto/sendmsg/execve. Only use eBPF when explicitly requested.
	switch {
	case runtime.GOOS == "linux":
		fmt.Fprintf(os.Stderr, "[*] Using in-container strace for full syscall coverage\n")

		return methodStraceContainer
	default:
		fmt.Fprintf(os.Stderr, "[*] Non-Linux host, using in-container strace\n")

		return methodStraceContainer
	}
}

func startSandbox(ctx context.Context, dlDir, pkg, method string) (*sandbox.Sandbox, error) {
	fmt.Fprintf(os.Stderr, "[*] Preparing sandbox...\n")

	dockerfilePath := findDockerfile()
	if err := sandbox.EnsureImage(ctx, dockerfilePath); err != nil {
		return nil, fmt.Errorf("ensuring sandbox image: %w", err)
	}

	needsPtrace := method == methodStraceContainer
	sb := sandbox.New(dlDir, pkg, needsPtrace, flagEcosystem)

	if method == methodEBPF || method == methodStrace {
		// Create then start-paused to minimize the TOCTOU window
		// between container start and probe attachment.
		if err := sb.Create(ctx); err != nil {
			return nil, fmt.Errorf("creating sandbox: %w", err)
		}
		if err := sb.StartPaused(ctx); err != nil {
			return nil, fmt.Errorf("starting sandbox paused: %w", err)
		}
	} else {
		// strace-container mode doesn't need the pause-before-probe pattern.
		if err := sb.Start(ctx); err != nil {
			return nil, fmt.Errorf("starting sandbox: %w", err)
		}
	}

	return sb, nil
}

func runProbeAndInstall(ctx context.Context, sb *sandbox.Sandbox, pkg, method string) (*scanResult, error) {
	fmt.Fprintf(os.Stderr, "[*] Starting %s probe...\n", method)

	switch method {
	case methodEBPF:
		return runEBPFProbe(ctx, sb, pkg)
	case methodStrace:
		return runStraceProbe(ctx, sb, pkg)
	case methodStraceContainer:
		return runContainerStraceProbe(ctx, sb, pkg)
	default:
		return nil, fmt.Errorf("unknown probe method: %s", method)
	}
}

func runEBPFProbe(ctx context.Context, sb *sandbox.Sandbox, pkg string) (*scanResult, error) {
	containerPID, err := sb.PID(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting container PID: %w", err)
	}

	pidnsInode, err := getPIDNSInode(containerPID)
	if err != nil {
		return nil, fmt.Errorf("getting pidns inode: %w", err)
	}

	ep := probe.NewEBPF()
	if startErr := ep.Start(pidnsInode); startErr != nil {
		return nil, fmt.Errorf("starting eBPF probe: %w", startErr)
	}
	fmt.Fprintf(os.Stderr, "[!] eBPF probe monitors connect() only — sendto/sendmsg/execve are not covered. Consider --probe-method=strace-container for full coverage.\n")
	defer func() { _ = ep.Close() }()

	if unpauseErr := sb.Unpause(ctx); unpauseErr != nil {
		return nil, fmt.Errorf("unpausing container: %w", unpauseErr)
	}

	events, err := installAndCollect(ctx, sb, pkg, ep)
	if err != nil {
		return nil, err
	}

	return &scanResult{
		events:      events,
		method:      ep.Method(),
		lostSamples: ep.LostSamples,
	}, nil
}

func runStraceProbe(ctx context.Context, sb *sandbox.Sandbox, pkg string) (*scanResult, error) {
	containerPID, err := sb.PID(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting container PID: %w", err)
	}

	sp := probe.NewStrace()
	if startErr := sp.StartWithPID(containerPID); startErr != nil {
		return nil, fmt.Errorf("starting strace probe: %w", startErr)
	}
	defer func() { _ = sp.Close() }()

	if unpauseErr := sb.Unpause(ctx); unpauseErr != nil {
		return nil, fmt.Errorf("unpausing container: %w", unpauseErr)
	}

	events, err := installAndCollect(ctx, sb, pkg, sp)
	if err != nil {
		return nil, err
	}

	return &scanResult{
		events: events,
		method: sp.Method(),
	}, nil
}

func runContainerStraceProbe(ctx context.Context, sb *sandbox.Sandbox, pkg string) (*scanResult, error) {
	// Phase 1: Install with strace monitoring.
	cp := probe.NewContainerStrace()
	fmt.Fprintf(os.Stderr, "[*] Phase 1/2: Installing %s in sandbox (with strace)...\n", pkg)

	installOut, err := cp.StartAndInstall(ctx, sb.ContainerID(), sb.InstallCommand())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Install output:\n%s\n", string(installOut))

		return nil, fmt.Errorf("install failed: %w", err)
	}

	var events []types.SyscallEvent
	for evt := range cp.Events() {
		events = append(events, evt)
	}

	// Phase 2: Import under each simulated OS to defeat platform-gated payloads.
	// Write probe scripts to /tmp first (outside strace), then execute them.
	sb.WriteProbeScripts(ctx)

	importCmds := sb.ImportCommands()
	osNames := []string{"Linux", "Windows", "macOS"}

	for i, cmd := range importCmds {
		label := osNames[i%len(osNames)]
		fmt.Fprintf(os.Stderr, "[*] Phase 2/2: Importing %s (simulating %s)...\n", pkg, label)

		ip := probe.NewContainerStrace()
		importOut, importErr := ip.StartAndInstall(ctx, sb.ContainerID(), cmd)
		if importErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Import (%s) failed (non-fatal): %v\n", label, importErr)
			_ = importOut
		}

		for evt := range ip.Events() {
			events = append(events, evt)
		}
	}

	return &scanResult{
		events: events,
		method: cp.Method(),
	}, nil
}

func installAndCollect(ctx context.Context, sb *sandbox.Sandbox, pkg string, p probe.Probe) ([]types.SyscallEvent, error) {
	fmt.Fprintf(os.Stderr, "[*] Installing %s in sandbox...\n", pkg)

	installOut, err := sb.InstallPackage(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Install output:\n%s\n", string(installOut))

		return nil, fmt.Errorf("install failed: %w", err)
	}

	time.Sleep(eventDrainDelay)
	_ = p.Close()

	var events []types.SyscallEvent
	for evt := range p.Events() {
		events = append(events, evt)
	}

	return events, nil
}

func outputReport(pkg string, result *scanResult) error {
	verdict, filtered := analyzer.Analyze(result.events)
	if result.lostSamples > 0 {
		verdict = types.VerdictInconclusive
	}

	r := report.Generate(pkg, flagVersion, flagEcosystem, verdict, result.method, filtered, result.lostSamples)
	printVerdict(verdict, len(filtered), result.lostSamples)

	w, err := openOutput()
	if err != nil {
		return err
	}

	if w != os.Stdout {
		defer w.Close()
	}

	if writeErr := report.WriteJSON(&r, w); writeErr != nil {
		return fmt.Errorf("writing report: %w", writeErr)
	}

	switch verdict {
	case types.VerdictSuspicious:
		return &VerdictError{Verdict: verdict, ExitCode: exitCodeSuspicious}
	case types.VerdictInconclusive:
		// Treat inconclusive as failure — lost events may hide real attacks.
		// CI pipelines should block on this just like suspicious.
		return &VerdictError{Verdict: verdict, ExitCode: exitCodeSuspicious}
	default:
		return nil
	}
}

func printVerdict(verdict string, eventCount int, lostSamples uint64) {
	switch verdict {
	case types.VerdictSuspicious:
		fmt.Fprintf(os.Stderr, "[!] SUSPICIOUS: %d suspicious event(s) detected\n", eventCount)
	case types.VerdictInconclusive:
		fmt.Fprintf(os.Stderr, "[!] INCONCLUSIVE: %d event(s) lost — probe buffer overflow, possible evasion attempt. Treating as failure.\n", lostSamples)
	default:
		fmt.Fprintf(os.Stderr, "[+] CLEAN: No suspicious activity detected\n")
	}
}

func openOutput() (*os.File, error) {
	if flagOutput == "" {
		return os.Stdout, nil
	}

	f, err := os.Create(flagOutput)
	if err != nil {
		return nil, fmt.Errorf("creating output file: %w", err)
	}

	return f, nil
}

func findDockerfile() string {
	candidates := []string{
		"Dockerfile.sandbox",
		filepath.Join("..", "Dockerfile.sandbox"),
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	return "Dockerfile.sandbox"
}
