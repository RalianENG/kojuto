package cmd

import (
	"context"
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

var (
	version     string
	output      string
	probeMethod string
	timeout     time.Duration
)

var rootCmd = &cobra.Command{
	Use:   "kojuto",
	Short: "Supply chain attack detection tool",
	Long:  "Detect suspicious network activity during package installation by running packages in an isolated sandbox with syscall monitoring.",
}

var scanCmd = &cobra.Command{
	Use:   "scan <package>",
	Short: "Scan a PyPI package for suspicious network activity",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("kojuto v0.1.0")
	},
}

func init() {
	scanCmd.Flags().StringVarP(&version, "version", "v", "", "package version to scan")
	scanCmd.Flags().StringVarP(&output, "output", "o", "", "output file path (default: stdout)")
	scanCmd.Flags().StringVar(&probeMethod, "probe-method", "auto", "probe method: auto, ebpf, strace, strace-container")
	scanCmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "scan timeout")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	pkg := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Handle interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
	}()

	// Step 1: Create temp dir and download package
	fmt.Fprintf(os.Stderr, "[*] Downloading %s...\n", pkg)
	tmpDir, err := os.MkdirTemp("", "kojuto-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dlDir := filepath.Join(tmpDir, "packages")
	if err := os.MkdirAll(dlDir, 0o755); err != nil {
		return fmt.Errorf("creating download dir: %w", err)
	}

	if _, err := downloader.Download(ctx, pkg, version, dlDir); err != nil {
		return err
	}

	// Detect version from downloaded files
	if version == "" {
		version = downloader.DetectVersion(dlDir, pkg)
	}

	// Step 2: Choose probe method
	method := probeMethod
	if method == "auto" {
		if probe.CanUseEBPF() {
			method = "ebpf"
		} else if runtime.GOOS == "linux" {
			method = "strace"
			fmt.Fprintf(os.Stderr, "[!] eBPF unavailable, falling back to host strace\n")
		} else {
			method = "strace-container"
			fmt.Fprintf(os.Stderr, "[*] Non-Linux host, using in-container strace\n")
		}
	}

	// Step 3: Ensure sandbox image exists
	fmt.Fprintf(os.Stderr, "[*] Preparing sandbox...\n")
	dockerfilePath := findDockerfile()
	if err := sandbox.EnsureImage(ctx, dockerfilePath); err != nil {
		return fmt.Errorf("ensuring sandbox image: %w", err)
	}

	// Step 4: Start sandbox container
	needsPtrace := method == "strace-container"
	sb := sandbox.New(dlDir, pkg, needsPtrace)
	if err := sb.Start(ctx); err != nil {
		return err
	}
	defer sb.Cleanup(ctx)

	// Step 5+6: Probe and install (flow differs by method)
	fmt.Fprintf(os.Stderr, "[*] Starting %s probe...\n", method)

	var events []types.ConnectEvent
	var probeMethodUsed string

	switch method {
	case "ebpf":
		containerPID, err := sb.PID(ctx)
		if err != nil {
			return err
		}
		pidnsInode, err := getPIDNSInode(containerPID)
		if err != nil {
			return fmt.Errorf("getting pidns inode: %w", err)
		}
		ep := probe.NewEBPF()
		if err := ep.Start(pidnsInode); err != nil {
			return fmt.Errorf("starting eBPF probe: %w", err)
		}
		defer ep.Close()

		fmt.Fprintf(os.Stderr, "[*] Installing %s in sandbox...\n", pkg)
		installOut, err := sb.InstallPackage(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Install output:\n%s\n", string(installOut))
			return fmt.Errorf("pip install failed: %w", err)
		}

		time.Sleep(500 * time.Millisecond)
		ep.Close()
		for evt := range ep.Events() {
			events = append(events, evt)
		}
		probeMethodUsed = ep.Method()

	case "strace":
		containerPID, err := sb.PID(ctx)
		if err != nil {
			return err
		}
		sp := probe.NewStrace()
		if err := sp.StartWithPID(containerPID); err != nil {
			return fmt.Errorf("starting strace probe: %w", err)
		}
		defer sp.Close()

		fmt.Fprintf(os.Stderr, "[*] Installing %s in sandbox...\n", pkg)
		installOut, err := sb.InstallPackage(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Install output:\n%s\n", string(installOut))
			return fmt.Errorf("pip install failed: %w", err)
		}

		time.Sleep(500 * time.Millisecond)
		sp.Close()
		for evt := range sp.Events() {
			events = append(events, evt)
		}
		probeMethodUsed = sp.Method()

	case "strace-container":
		cp := probe.NewContainerStrace()
		fmt.Fprintf(os.Stderr, "[*] Installing %s in sandbox (with strace)...\n", pkg)
		installOut, err := cp.StartAndInstall(ctx, sb.ContainerID(), pkg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Install output:\n%s\n", string(installOut))
			return fmt.Errorf("pip install failed: %w", err)
		}

		for evt := range cp.Events() {
			events = append(events, evt)
		}
		probeMethodUsed = cp.Method()

	default:
		return fmt.Errorf("unknown probe method: %s", method)
	}

	// Step 7: Analyze and report
	verdict := analyzer.Analyze(events)
	r := report.Generate(pkg, version, verdict, probeMethodUsed, events)

	if verdict == types.VerdictSuspicious {
		fmt.Fprintf(os.Stderr, "[!] SUSPICIOUS: %d connection attempt(s) detected\n", len(events))
	} else {
		fmt.Fprintf(os.Stderr, "[+] CLEAN: No connection attempts detected\n")
	}

	var w *os.File
	if output != "" {
		w, err = os.Create(output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer w.Close()
	} else {
		w = os.Stdout
	}

	return report.WriteJSON(r, w)
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
