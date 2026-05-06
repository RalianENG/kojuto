package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/RalianENG/kojuto/internal/analyzer"
	"github.com/RalianENG/kojuto/internal/config"
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
	flagLocal       string
	flagRuntime     string
	flagTimeout     time.Duration
	flagConfig      string
	flagStrict      bool
	flagNoColor     bool
	flagQuiet       bool
)

// Replaceable dependencies for testing.
var (
	downloaderDownload      = downloader.Download
	downloaderValidate      = downloader.ValidatePackage
	downloaderDetectVersion = downloader.DetectVersion
	sandboxNew              = sandbox.New
	sandboxEnsureImage      = sandbox.EnsureImage
	depfileParse            = depfile.Parse
	execCommandCmd          = exec.CommandContext
)

var rootCmd = &cobra.Command{
	Use:   "kojuto",
	Short: "Supply chain attack detection tool",
	Long:  "Detect suspicious network activity during package installation by running packages in an isolated sandbox with syscall monitoring.",
}

var scanCmd = &cobra.Command{
	Use:   "scan [package]",
	Short: "Scan a package or dependency file for suspicious syscall activity",
	Long: `Scan a package for suspicious syscall activity during installation and import.

The target package is installed inside an isolated Docker container while
syscalls (connect, sendto, execve, openat, rename, etc.) are recorded via
strace or eBPF. Import is then repeated under three simulated OS identities
(Linux, Windows, macOS) with the clock shifted +30 days to trigger
platform-gated and date-gated payloads.

Prerequisites:
  - Docker must be installed and running
  - pip (for PyPI) or npm (for npm) must be available on the host
  - Run 'make sandbox-image' at least once to build the sandbox image`,
	Example: `  # Scan a PyPI package
  kojuto scan requests

  # Scan an npm package
  kojuto scan lodash -e npm

  # Scan a specific version
  kojuto scan requests --version 2.31.0

  # Scan all dependencies from a file
  kojuto scan -f requirements.txt
  kojuto scan -f package.json

  # Output report to file
  kojuto scan requests -o report.json

  # Scan a local package file
  kojuto scan --local ./malware-1.0.0.whl

  # Use gVisor runtime for stronger isolation (auto-detected by default)
  kojuto scan requests --runtime runsc`,
	Args:          cobra.MaximumNArgs(1),
	RunE:          runScan,
	PreRunE:       preRunLoadConfig,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var (
	appVersion = "dev"
	appCommit  = "none"
	appDate    = "unknown"
)

// SetVersionInfo is called from main to inject build-time version info.
func SetVersionInfo(version, commit, date string) {
	appVersion = version
	appCommit = commit
	appDate = date
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("kojuto %s (commit: %s, built: %s)\n", appVersion, appCommit, appDate)
	},
}

func init() {
	scanCmd.Flags().StringVarP(&flagVersion, "version", "v", "", "package version to scan")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "output file path (default: stdout)")
	scanCmd.Flags().StringVarP(&flagEcosystem, "ecosystem", "e", types.EcosystemPyPI, "ecosystem: pypi, npm")
	scanCmd.Flags().StringVarP(&flagFile, "file", "f", "", "dependency file to scan (requirements.txt or package.json)")
	scanCmd.Flags().StringVar(&flagPin, "pin", "", "output pinned dependency file after all-clean scan (requires -f)")
	scanCmd.Flags().StringVar(&flagLocal, "local", "", "scan a local package file (.whl, .tgz) or directory instead of downloading")
	scanCmd.Flags().StringVar(&flagRuntime, "runtime", "auto", "container runtime: auto (use gVisor if available), runsc, or runc")
	scanCmd.Flags().StringVar(&flagProbeMethod, "probe-method", methodAuto, "probe method: auto, ebpf, strace, strace-container")
	scanCmd.Flags().DurationVar(&flagTimeout, "timeout", 5*time.Minute, "scan timeout per package")
	scanCmd.Flags().StringVar(&flagConfig, "config", "", "config file path (default: kojuto.yml in current directory)")
	scanCmd.Flags().BoolVar(&flagStrict, "strict", false, "ignore sensitive_paths.exclude from config (recommended for CI)")

	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable colored output (NO_COLOR env is also respected)")
	rootCmd.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", false, "suppress phase progress output; emit only the final verdict block")
	rootCmd.PersistentPreRun = func(_ *cobra.Command, _ []string) {
		configureColor(flagNoColor)
	}

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

func preRunLoadConfig(_ *cobra.Command, _ []string) error {
	cfgPath := flagConfig
	if cfgPath == "" {
		cfgPath = "kojuto.yml"
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config %s: %w", cfgPath, err)
	}

	if flagStrict && len(cfg.SensitivePaths.Exclude) > 0 {
		fmt.Fprintf(os.Stderr, "warning: --strict ignoring %d excluded path(s) from config: %v\n",
			len(cfg.SensitivePaths.Exclude), cfg.SensitivePaths.Exclude)
		cfg.SensitivePaths.Exclude = nil
	}

	paths := config.MergeSensitivePaths(cfg)
	probe.SetSensitivePaths(paths)
	analyzer.SetSensitivePaths(paths)
	return nil
}

// VerdictError is returned when the scan verdict is not clean.
//
// Categories carries the unique attack-category list from the scan's
// summary, populated only on `suspicious` verdicts. The batch
// summary uses it to show per-package category attribution without
// re-reading the report JSON from disk.
type VerdictError struct {
	Verdict    string
	ExitCode   int
	Categories []string
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

	// Add actionable hints for common errors.
	errMsg := err.Error()
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	if strings.Contains(errMsg, "context deadline exceeded") {
		fmt.Fprintf(os.Stderr, "\nHint: scan timed out. Increase with --timeout (e.g. --timeout 10m)\n")
	}
	os.Exit(1)
}

type scanResult struct {
	method      string
	events      []types.SyscallEvent
	lostSamples uint64
	dropped     uint64
}

func runScan(_ *cobra.Command, args []string) error {
	// Local mode: scan a local package file or directory.
	if flagLocal != "" {
		return runLocalScan(args)
	}

	// Batch mode: scan all packages from a dependency file.
	if flagFile != "" {
		return runBatchScan(args)
	}

	// Single package mode.
	if len(args) == 0 {
		return errors.New("no package specified\n\nUsage:\n  kojuto scan <package>        scan a single package\n  kojuto scan -f <file>        scan all dependencies from a file\n  kojuto scan --local <path>   scan a local .whl or .tgz file\n\nRun 'kojuto scan --help' for more options")
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
	if err := downloaderValidate(pkg, version); err != nil {
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
	deps, ecosystem, err := depfileParse(flagFile)
	if err != nil {
		return err
	}

	if len(deps) == 0 {
		return fmt.Errorf("no dependencies found in %s\n\nSupported formats:\n  - requirements.txt (one package per line)\n  - package.json (reads dependencies and devDependencies)", flagFile)
	}

	// Allow ecosystem override from -e flag if explicitly set.
	if flagEcosystem != types.EcosystemPyPI {
		ecosystem = flagEcosystem
	}

	if flagPin != "" && flagFile == "" {
		return errors.New("--pin requires -f <file>")
	}

	// Phase 1: Fast batch screening — install all packages in a single sandbox.
	phaseInfo("screening", fmt.Sprintf("%d packages from %s (%s)", len(deps), flagFile, ecosystem))

	verdict, batchErr := runBatchScreening(deps, ecosystem)
	if batchErr != nil {
		// Batch screening failed (download/sandbox error). Fall back to per-package scan.
		fmt.Fprintf(os.Stderr, "  %s batch screening failed: %v\n", styleYellowBold("!"), batchErr)
		phaseInfo("fallback", "per-package scan")
		return runPerPackageScan(deps, ecosystem)
	}

	if verdict == types.VerdictClean {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "  %s  all %d packages passed batch screening\n",
			styleGreenBold("✓ CLEAN"), len(deps))

		if flagPin != "" {
			pinned := make([]pinnedDep, 0, len(deps))
			for _, dep := range deps {
				pinned = append(pinned, pinnedDep{Name: dep.Name, Version: dep.Version})
			}
			if err := writePinnedFile(flagPin, pinned, ecosystem); err != nil {
				return fmt.Errorf("writing pinned file: %w", err)
			}
			fmt.Fprintf(os.Stderr, "  %s pinned %d packages to %s\n",
				styleGreenBold("✓"), len(pinned), flagPin)
		}
		return nil
	}

	// Phase 2: Suspicious activity detected — re-scan individually to find the culprit.
	fmt.Fprintf(os.Stderr, "  %s suspicious activity in batch scan, attributing per-package\n",
		styleYellowBold("!"))
	return runPerPackageScan(deps, ecosystem)
}

// runBatchScreening installs all packages in a single sandbox and monitors for suspicious activity.
func runBatchScreening(deps []depfile.Dep, ecosystem string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), flagTimeout)
	defer cancel()

	// Download all packages into one directory.
	tmpDir, err := os.MkdirTemp("", "kojuto-batch-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dlDir := filepath.Join(tmpDir, "packages")
	if mkErr := os.MkdirAll(dlDir, 0o755); mkErr != nil {
		return "", fmt.Errorf("creating download dir: %w", mkErr)
	}

	var pkgNames []string
	var targets []string // pip download targets (name or name==version)
	for _, dep := range deps {
		pkgNames = append(pkgNames, dep.Name)
		if dep.Version != "" {
			targets = append(targets, dep.Name+"=="+dep.Version)
		} else {
			targets = append(targets, dep.Name)
		}
	}

	flagEcosystem = ecosystem
	phaseInfo("download", fmt.Sprintf("%d packages", len(pkgNames)))
	downloadBatchPackages(ctx, deps, targets, dlDir, ecosystem)

	// Start a single sandbox with all packages.
	method := selectProbeMethod()
	// Use the first package name as the sandbox label.
	sb, err := startSandbox(ctx, dlDir, pkgNames[0], method)
	if err != nil {
		return "", err
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if cleanupErr := sb.Cleanup(cleanupCtx); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Cleanup warning: %v\n", cleanupErr)
		}
	}()

	// Install all packages at once with strace.
	installPhase := startPhase("install", fmt.Sprintf("%d packages", len(pkgNames)))
	cp := probe.NewContainerStrace()
	installOut, installErr := cp.StartAndInstall(ctx, sb.ContainerID(), sb.InstallAllCommand(pkgNames))
	if installErr != nil {
		fmt.Fprintf(os.Stderr, "[!] Install output:\n%s\n", string(installOut))
		return "", fmt.Errorf("batch install failed: %w", installErr)
	}
	installPhase.end()

	var events []types.SyscallEvent
	for evt := range cp.Events() {
		events = append(events, evt)
	}

	// Import all packages under simulated OS identities (3 scripts total).
	sb.WriteProbeScriptsMulti(ctx, pkgNames)
	importCmds := sb.ImportCommandsMulti(pkgNames)
	osNames := []string{"Linux", "Windows", "macOS"}

	for i, cmd := range importCmds {
		importPhase := startPhase("import", fmt.Sprintf("%d packages, %s", len(pkgNames), osNames[i]))

		ip := probe.NewContainerStrace()
		importOut, importErr := ip.StartAndInstall(ctx, sb.ContainerID(), cmd)
		if importErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Import (%s) failed (non-fatal): %v\n", osNames[i], importErr)
			_ = importOut
		}
		for evt := range ip.Events() {
			events = append(events, evt)
		}
		importPhase.end()
	}

	verdict, filtered := analyzer.Analyze(events)
	phaseInfo("screening", fmt.Sprintf("verdict=%s (%d events)", verdict, len(filtered)))

	return verdict, nil
}

// downloadBatchPackages downloads all packages using the appropriate batch method.
// Falls back to individual downloads if the batch method fails.
func downloadBatchPackages(ctx context.Context, deps []depfile.Dep, pipTargets []string, dlDir, ecosystem string) {
	if ecosystem == types.EcosystemNpm {
		npmDeps := make(map[string]string, len(deps))
		for _, dep := range deps {
			if dep.Version != "" {
				npmDeps[dep.Name] = dep.Version
			} else {
				npmDeps[dep.Name] = "*"
			}
		}
		if dlErr := downloader.DownloadAllNpm(ctx, npmDeps, dlDir); dlErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Batch npm download failed, downloading individually...\n")
			downloadIndividually(ctx, deps, dlDir, ecosystem)
		}
		return
	}

	if dlErr := downloader.DownloadAll(ctx, pipTargets, dlDir); dlErr != nil {
		fmt.Fprintf(os.Stderr, "[!] Batch pip download failed, downloading individually...\n")
		downloadIndividually(ctx, deps, dlDir, ecosystem)
	}
}

func downloadIndividually(ctx context.Context, deps []depfile.Dep, dlDir, ecosystem string) {
	for _, dep := range deps {
		if _, dlErr := downloaderDownload(ctx, dep.Name, dep.Version, dlDir, ecosystem); dlErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to download %s: %v\n", dep.Name, dlErr)
		}
	}
}

// runPerPackageScan falls back to the original per-package scanning approach.
func runPerPackageScan(deps []depfile.Dep, ecosystem string) error {
	t0 := time.Now()
	var suspicious []batchSuspicious
	var scanErrors []string
	var pinned []pinnedDep

	for i, dep := range deps {
		fmt.Fprintln(os.Stderr)
		coord := dep.Name
		if dep.Version != "" {
			coord = dep.Name + "@" + dep.Version
		}
		phaseInfo("scan", fmt.Sprintf("[%d/%d] %s", i+1, len(deps), coord))

		resolved, scanErr := scanSinglePackage(dep.Name, dep.Version, ecosystem)
		if scanErr != nil {
			var ve *VerdictError
			if errors.As(scanErr, &ve) {
				suspicious = append(suspicious, batchSuspicious{
					name:       dep.Name,
					categories: ve.Categories,
				})
			} else {
				fmt.Fprintf(os.Stderr, "  %s error scanning %s: %v\n",
					styleYellowBold("!"), dep.Name, scanErr)
				scanErrors = append(scanErrors, dep.Name)
			}
		} else if resolved != nil {
			pinned = append(pinned, *resolved)
		}
	}

	// Summary block (renderer respects --quiet via shared progressOut wrapper —
	// but since the summary is the verdict-equivalent for batch mode, we always
	// write to stderr regardless of flagQuiet).
	renderBatchSummary(os.Stderr, len(deps), len(scanErrors), suspicious, time.Since(t0))

	if len(suspicious) > 0 {
		if flagPin != "" {
			fmt.Fprintf(os.Stderr, "  %s --pin refused: suspicious packages detected\n",
				styleYellowBold("!"))
		}
		return &VerdictError{Verdict: types.VerdictSuspicious, ExitCode: exitCodeSuspicious}
	}

	if len(scanErrors) > 0 {
		if flagPin != "" {
			fmt.Fprintf(os.Stderr, "  %s --pin refused: scan errors occurred\n",
				styleYellowBold("!"))
		}
		return fmt.Errorf("scan failed for: %s", strings.Join(scanErrors, ", "))
	}

	if flagPin != "" {
		if err := writePinnedFile(flagPin, pinned, ecosystem); err != nil {
			return fmt.Errorf("writing pinned file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "  %s pinned %d packages to %s\n",
			styleGreenBold("✓"), len(pinned), flagPin)
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

// runLocalScan scans a local package file (.whl, .tgz) or directory.
// This allows scanning malware samples obtained from external datasets
// (e.g. Datadog GuardDog) without requiring them to be on PyPI/npm.
func runLocalScan(_ []string) error {
	localPath, err := filepath.Abs(flagLocal)
	if err != nil {
		return fmt.Errorf("resolving local path: %w", err)
	}

	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("local path not found: %s\n\nProvide a .whl (PyPI) or .tgz (npm) file, or a directory containing them", localPath)
	}

	// Determine package directory and name.
	var dlDir, pkg string
	if info.IsDir() {
		dlDir = localPath
		pkg = detectPackageFromDir(localPath)
	} else {
		// Single file: copy to temp directory.
		tmpDir, tmpErr := os.MkdirTemp("", "kojuto-local-*")
		if tmpErr != nil {
			return fmt.Errorf("creating temp dir: %w", tmpErr)
		}
		defer os.RemoveAll(tmpDir)

		dlDir = filepath.Join(tmpDir, "packages")
		// 0o755 (not 0o750): the sandbox container runs pip as the
		// unprivileged `dev` user (UID 1000) but the host process is
		// usually root or a different UID. Without world-execute on the
		// directory, the in-container user cannot list the bind-mounted
		// package files and pip's glob expansion silently empties.
		if mkErr := os.MkdirAll(dlDir, 0o755); mkErr != nil {
			return fmt.Errorf("creating package dir: %w", mkErr)
		}

		src, readErr := os.ReadFile(localPath)
		if readErr != nil {
			return fmt.Errorf("reading local file: %w", readErr)
		}
		if writeErr := os.WriteFile(filepath.Join(dlDir, filepath.Base(localPath)), src, 0o644); writeErr != nil {
			return fmt.Errorf("copying local file: %w", writeErr)
		}

		pkg = detectPackageName(filepath.Base(localPath))
	}

	// Auto-detect ecosystem from file extension, but only if -e was not explicitly set.
	// .tgz is always npm; .tar.gz is ambiguous (could be PyPI sdist), so only
	// override to npm for .tgz, not .tar.gz.
	ecosystem := flagEcosystem
	if !info.IsDir() {
		name := filepath.Base(localPath)
		if strings.HasSuffix(name, ".tgz") {
			ecosystem = types.EcosystemNpm
		}
	}

	phaseInfo("scanning", fmt.Sprintf("%s (%s)", pkg, ecosystem))

	flagEcosystem = ecosystem
	flagVersion = downloaderDetectVersion(dlDir, pkg)

	// For npm local packages, we need to create a node_modules structure
	// from the .tgz so the sandbox can run npm install with lifecycle scripts.
	if ecosystem == types.EcosystemNpm {
		npmDir, npmErr := prepareLocalNpm(dlDir, pkg)
		if npmErr != nil {
			return fmt.Errorf("preparing local npm package: %w", npmErr)
		}
		defer os.RemoveAll(npmDir)
		dlDir = npmDir
	}

	ctx, cancel := context.WithTimeout(context.Background(), flagTimeout)
	defer cancel()

	method := selectProbeMethod()

	sb, err := startSandbox(ctx, dlDir, pkg, method)
	if err != nil {
		return err
	}
	sb.SetLocalMode(true)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if cleanupErr := sb.Cleanup(cleanupCtx); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Cleanup warning: %v\n", cleanupErr)
		}
	}()

	result, err := runProbeAndInstall(ctx, sb, pkg, method)
	if err != nil {
		return err
	}

	return outputReport(pkg, result)
}

// detectPackageFromDir looks at files inside a directory to determine the package name.
func detectPackageFromDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return filepath.Base(dir)
	}

	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".whl") || strings.HasSuffix(name, ".tgz") || strings.HasSuffix(name, ".tar.gz") {
			return detectPackageName(name)
		}
	}

	return filepath.Base(dir)
}

// detectPackageName extracts a package name from a filename.
// e.g. "malware-1.0.0-py3-none-any.whl" → "malware"
// e.g. "evil-pkg-2.0.0.tgz" → "evil-pkg".
func detectPackageName(filename string) string {
	// Strip common extensions.
	name := filename
	for _, ext := range []string{".whl", ".tgz", ".tar.gz", ".zip"} {
		name = strings.TrimSuffix(name, ext)
	}

	// Split on "-" and take parts before the version number.
	parts := strings.Split(name, "-")
	var nameParts []string
	for _, p := range parts {
		if p != "" && p[0] >= '0' && p[0] <= '9' {
			break
		}
		nameParts = append(nameParts, p)
	}

	if len(nameParts) == 0 {
		return name
	}

	return strings.Join(nameParts, "-")
}

// prepareLocalNpm creates a staging directory with node_modules from
// a local .tgz file. This mirrors what downloadNpm does for registry
// packages: npm install --ignore-scripts on the host, then the sandbox
// fires lifecycle scripts under strace.
func prepareLocalNpm(sourceDir, pkg string) (string, error) {
	stagingDir, err := os.MkdirTemp("", "kojuto-local-npm-*")
	if err != nil {
		return "", fmt.Errorf("creating npm staging dir: %w", err)
	}
	// MkdirTemp creates with 0o700 — the sandbox container's `dev` user
	// (UID 1000) is not the host UID, so without world-execute on this
	// directory the in-container user cannot traverse the bind-mounted
	// node_modules tree. find returns nothing, the lifecycle hooks never
	// fire, and the scan silently misses every install-time payload.
	// Mirrors the explicit 0o755 used in runLocalScan's PyPI path.
	if chmodErr := os.Chmod(stagingDir, 0o755); chmodErr != nil {
		return "", fmt.Errorf("relaxing staging dir perms: %w", chmodErr)
	}

	// Find .tgz in source directory.
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return "", fmt.Errorf("reading source dir: %w", err)
	}

	var tgzPath string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tgz") {
			tgzPath = filepath.Join(sourceDir, e.Name())
			break
		}
	}
	if tgzPath == "" {
		return "", fmt.Errorf("no .tgz file found in %s\n\nFor npm local scans, provide a tarball (.tgz) created by 'npm pack'", sourceDir)
	}

	// Create package.json that references the local tarball.
	pkgJSON := map[string]interface{}{
		"name":         "kojuto-local-staging",
		"private":      true,
		"dependencies": map[string]string{pkg: "file:" + tgzPath},
	}
	jsonBytes, err := json.Marshal(pkgJSON)
	if err != nil {
		return "", fmt.Errorf("marshaling staging package.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "package.json"), jsonBytes, 0o644); err != nil {
		return "", fmt.Errorf("writing staging package.json: %w", err)
	}

	// Install without scripts on host to resolve deps and create node_modules.
	cmd := execCommandCmd(context.Background(), "npm", "install", "--ignore-scripts")
	cmd.Dir = stagingDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("npm install (local staging) failed: %w", err)
	}

	return stagingDir, nil
}

func downloadPackage(ctx context.Context, pkg string) (string, error) {
	phaseInfo("download", fmt.Sprintf("%s (%s)", pkg, flagEcosystem))

	tmpDir, err := os.MkdirTemp("", "kojuto-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	dlDir := filepath.Join(tmpDir, "packages")
	if mkErr := os.MkdirAll(dlDir, 0o755); mkErr != nil {
		return "", fmt.Errorf("creating download dir: %w", mkErr)
	}

	if _, dlErr := downloaderDownload(ctx, pkg, flagVersion, dlDir, flagEcosystem); dlErr != nil {
		return "", fmt.Errorf("downloading package: %w\n\n%s", dlErr, downloadHint(flagEcosystem, dlErr))
	}

	if flagVersion == "" {
		flagVersion = downloaderDetectVersion(dlDir, pkg)
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
		phaseInfo("probe", "using in-container strace for full syscall coverage")

		return methodStraceContainer
	default:
		phaseInfo("probe", "non-Linux host, using in-container strace")

		return methodStraceContainer
	}
}

func startSandbox(ctx context.Context, dlDir, pkg, method string) (*sandbox.Sandbox, error) {
	phaseInfo("sandbox", "preparing isolated container")

	dockerfilePath := findDockerfile()
	if err := sandboxEnsureImage(ctx, dockerfilePath); err != nil {
		return nil, fmt.Errorf("ensuring sandbox image: %w%s", err, dockerHint(err))
	}

	needsPtrace := method == methodStraceContainer
	sb := sandboxNew(dlDir, pkg, needsPtrace, flagEcosystem, flagRuntime)

	if method == methodEBPF || method == methodStrace {
		// Create then start-paused to minimize the TOCTOU window
		// between container start and probe attachment.
		if err := sb.Create(ctx); err != nil {
			return nil, fmt.Errorf("creating sandbox: %w%s", err, dockerHint(err))
		}
		if err := sb.StartPaused(ctx); err != nil {
			return nil, fmt.Errorf("starting sandbox paused: %w%s", err, dockerHint(err))
		}
	} else {
		// strace-container mode doesn't need the pause-before-probe pattern.
		if err := sb.Start(ctx); err != nil {
			return nil, fmt.Errorf("starting sandbox: %w%s", err, dockerHint(err))
		}
	}

	return sb, nil
}

func runProbeAndInstall(ctx context.Context, sb *sandbox.Sandbox, pkg, method string) (*scanResult, error) {
	phaseInfo("probe", "starting "+method)

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

func runEBPFProbe(ctx context.Context, sb *sandbox.Sandbox, _ string) (*scanResult, error) {
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

	if unpauseErr := sb.Unpause(ctx); unpauseErr != nil {
		_ = ep.Close()
		return nil, fmt.Errorf("unpausing container: %w", unpauseErr)
	}

	// Phase 1: install. The eBPF probe is host-side, so a single Start()
	// covers every phase below — no need to recreate the probe per phase
	// the way runContainerStraceProbe must.
	installPhase := startPhase("install", "")
	installOut, installErr := sb.InstallPackage(ctx)
	if installErr != nil {
		_ = ep.Close()
		fmt.Fprintf(os.Stderr, "[!] Install output:\n%s\n", string(installOut))
		return nil, fmt.Errorf("install failed: %w", installErr)
	}
	installPhase.end()

	// Phase 2: import under each simulated OS identity to trigger
	// platform-gated payloads. Without this, eBPF mode misses every
	// __init__.py-resident attack — most pypi malware lives here, not
	// in setup.py.
	sb.WriteProbeScripts(ctx)
	importCmds := sb.ImportCommands()
	osNames := []string{"Linux", "Windows", "macOS"}
	for i, cmd := range importCmds {
		label := osNames[i%len(osNames)]
		importPhase := startPhase("import", label)
		if out, importErr := sb.Exec(ctx, cmd); importErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Import (%s) failed (non-fatal): %v\n%s\n", label, importErr, string(out))
		}
		importPhase.end()
	}

	// Allow the perf buffer + reader goroutines to drain in-flight events
	// before closing. Mirrors installAndCollect's eventDrainDelay.
	time.Sleep(eventDrainDelay)
	_ = ep.Close()

	var events []types.SyscallEvent
	for evt := range ep.Events() {
		events = append(events, evt)
	}

	return &scanResult{
		events:      events,
		method:      ep.Method(),
		lostSamples: ep.LostSamples,
		dropped:     ep.Dropped(),
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
		events:  events,
		method:  sp.Method(),
		dropped: sp.Dropped(),
	}, nil
}

func runContainerStraceProbe(ctx context.Context, sb *sandbox.Sandbox, _ string) (*scanResult, error) {
	// Phase 1: Install with strace monitoring.
	cp := probe.NewContainerStrace()
	installPhase := startPhase("install", "")

	installOut, err := cp.StartAndInstall(ctx, sb.ContainerID(), sb.InstallCommand())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Install output:\n%s\n", string(installOut))

		return nil, fmt.Errorf("install failed: %w", err)
	}
	installPhase.end()

	var events []types.SyscallEvent
	for evt := range cp.Events() {
		events = append(events, evt)
	}
	dropped := cp.Dropped()

	// Phase 2: Import under each simulated OS to defeat platform-gated payloads.
	// Write probe scripts to /tmp first (outside strace), then execute them.
	sb.WriteProbeScripts(ctx)

	importCmds := sb.ImportCommands()
	osNames := []string{"Linux", "Windows", "macOS"}

	for i, cmd := range importCmds {
		label := osNames[i%len(osNames)]
		importPhase := startPhase("import", label)

		ip := probe.NewContainerStrace()
		importOut, importErr := ip.StartAndInstall(ctx, sb.ContainerID(), cmd)
		if importErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Import (%s) failed (non-fatal): %v\n", label, importErr)
			_ = importOut
		}
		importPhase.end()

		for evt := range ip.Events() {
			events = append(events, evt)
		}
		dropped += ip.Dropped()
	}

	return &scanResult{
		events:  events,
		method:  cp.Method(),
		dropped: dropped,
	}, nil
}

func installAndCollect(ctx context.Context, sb *sandbox.Sandbox, _ string, p probe.Probe) ([]types.SyscallEvent, error) {
	phaseInfo("install", "running pip/npm in sandbox")

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
	// Either kernel-level perf buffer overflow (lostSamples) or userspace
	// events-channel overflow (dropped) means the scan lost visibility and
	// the verdict must not be "clean" — a dropped event could be the one
	// that would have flagged a malicious syscall.
	if result.lostSamples > 0 || result.dropped > 0 {
		verdict = types.VerdictInconclusive
	}

	summary := analyzer.GenerateSummary(verdict, filtered)
	r := report.Generate(pkg, flagVersion, flagEcosystem, verdict, result.method, filtered, result.lostSamples, result.dropped, summary)
	renderVerdictBlock(os.Stderr, verdict, pkg, flagVersion, len(filtered), summary, result.lostSamples, result.dropped)

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
		var cats []string
		if summary != nil {
			cats = summary.Categories
		}
		return &VerdictError{Verdict: verdict, ExitCode: exitCodeSuspicious, Categories: cats}
	case types.VerdictInconclusive:
		// Treat inconclusive as failure — lost events may hide real attacks.
		// CI pipelines should block on this just like suspicious.
		return &VerdictError{Verdict: verdict, ExitCode: exitCodeSuspicious}
	default:
		return nil
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

// downloadHint returns actionable guidance when a package download fails.
func downloadHint(ecosystem string, err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "executable file not found") || strings.Contains(msg, "not found in"):
		if ecosystem == types.EcosystemNpm {
			return "Hint: npm is not installed or not in PATH. Install Node.js from https://nodejs.org/"
		}
		return "Hint: pip is not installed or not in PATH. Install it with: python3 -m ensurepip"
	case strings.Contains(msg, "No matching distribution"):
		return "Hint: package or version not found. Check the name and version on pypi.org"
	case strings.Contains(msg, "404") || strings.Contains(msg, "not found"):
		return "Hint: package not found in the registry. Verify the package name and ecosystem (-e pypi or -e npm)"
	default:
		return ""
	}
}

// dockerHint returns actionable guidance when a Docker operation fails.
func dockerHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "executable file not found") || strings.Contains(msg, "not found in"):
		return "\n\nHint: Docker is not installed or not in PATH. Install Docker from https://docs.docker.com/get-docker/"
	case strings.Contains(msg, "Cannot connect to the Docker daemon") || strings.Contains(msg, "docker daemon") || strings.Contains(msg, "Is the docker daemon running"):
		return "\n\nHint: Docker daemon is not running. Start it with: sudo systemctl start docker (Linux) or open Docker Desktop (macOS/Windows)"
	case strings.Contains(msg, "permission denied") && strings.Contains(msg, "docker.sock"):
		return "\n\nHint: permission denied accessing Docker. Add your user to the docker group: sudo usermod -aG docker $USER (then re-login)"
	default:
		return ""
	}
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
