package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/RalianENG/kojuto/internal/analyzer"
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

	exitCodeSuspicious   = 2
	exitCodeInconclusive = 3
)

var (
	flagVersion     string
	flagOutput      string
	flagProbeMethod string
	flagEcosystem   string
	flagTimeout     time.Duration
)

var rootCmd = &cobra.Command{
	Use:   "kojuto",
	Short: "Supply chain attack detection tool",
	Long:  "Detect suspicious network activity during package installation by running packages in an isolated sandbox with syscall monitoring.",
}

var scanCmd = &cobra.Command{
	Use:          "scan <package>",
	Short:        "Scan a package for suspicious syscall activity during installation",
	Args:         cobra.ExactArgs(1),
	RunE:         runScan,
	SilenceUsage: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("kojuto v0.2.0")
	},
}

func init() {
	scanCmd.Flags().StringVarP(&flagVersion, "version", "v", "", "package version to scan")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "output file path (default: stdout)")
	scanCmd.Flags().StringVarP(&flagEcosystem, "ecosystem", "e", types.EcosystemPyPI, "ecosystem: pypi, npm")
	scanCmd.Flags().StringVar(&flagProbeMethod, "probe-method", methodAuto, "probe method: auto, ebpf, strace, strace-container")
	scanCmd.Flags().DurationVar(&flagTimeout, "timeout", 5*time.Minute, "scan timeout")

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
	pkg := args[0]

	if err := downloader.ValidatePackage(pkg, flagVersion); err != nil {
		return fmt.Errorf("invalid input: %w", err)
	}

	if flagEcosystem != types.EcosystemPyPI && flagEcosystem != types.EcosystemNpm {
		return fmt.Errorf("unsupported ecosystem: %s (use pypi or npm)", flagEcosystem)
	}

	ctx, cancel := context.WithTimeout(context.Background(), flagTimeout)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	go func() {
		<-sigCh
		cancel()
	}()

	dlDir, err := downloadPackage(ctx, pkg)
	if err != nil {
		return err
	}
	defer os.RemoveAll(filepath.Dir(dlDir))

	method := selectProbeMethod()

	sb, err := startSandbox(ctx, dlDir, pkg, method)
	if err != nil {
		return err
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
		return err
	}

	return outputReport(pkg, result)
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

	switch {
	case probe.CanUseEBPF():
		return methodEBPF
	case runtime.GOOS == "linux":
		fmt.Fprintf(os.Stderr, "[!] eBPF unavailable, falling back to host strace\n")

		return methodStrace
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
		// Create then start-paused to minimise the TOCTOU window
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
	cp := probe.NewContainerStrace()
	fmt.Fprintf(os.Stderr, "[*] Installing %s in sandbox (with strace)...\n", pkg)

	installOut, err := cp.StartAndInstall(ctx, sb.ContainerID(), sb.InstallCommand())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Install output:\n%s\n", string(installOut))

		return nil, fmt.Errorf("install failed: %w", err)
	}

	var events []types.SyscallEvent
	for evt := range cp.Events() {
		events = append(events, evt)
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
		return &VerdictError{Verdict: verdict, ExitCode: exitCodeInconclusive}
	default:
		return nil
	}
}

func printVerdict(verdict string, eventCount int, lostSamples uint64) {
	switch verdict {
	case types.VerdictSuspicious:
		fmt.Fprintf(os.Stderr, "[!] SUSPICIOUS: %d suspicious event(s) detected\n", eventCount)
	case types.VerdictInconclusive:
		fmt.Fprintf(os.Stderr, "[!] INCONCLUSIVE: %d event(s) lost, results may be incomplete\n", lostSamples)
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
