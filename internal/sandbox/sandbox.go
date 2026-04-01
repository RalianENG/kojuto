package sandbox

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/RalianENG/kojuto/internal/types"
)

//go:embed seccomp.json
var seccompProfile []byte

// SandboxImage is the Docker image used for the sandbox container.
const SandboxImage = "kojuto-sandbox:latest"

// SandboxPythonVersion must match the Python version in Dockerfile.sandbox.
const SandboxPythonVersion = "3.12"

// Sandbox manages a Docker container for isolated package installation.
type Sandbox struct {
	containerID string
	packageDir  string
	pkg         string
	ecosystem   string
	needsPtrace bool
}

// New creates a new Sandbox instance.
func New(packageDir, pkg string, needsPtrace bool, ecosystem string) *Sandbox {
	return &Sandbox{
		packageDir:  packageDir,
		pkg:         pkg,
		needsPtrace: needsPtrace,
		ecosystem:   ecosystem,
	}
}

// seccompDir holds the path to a temporary directory containing the seccomp profile.
// It is set by writeSeccompProfile and cleaned up by Cleanup.
var seccompDir string

// writeSeccompProfile writes the embedded seccomp profile to a temp file
// and returns the --security-opt flag value to pass to docker.
func writeSeccompProfile() (string, error) {
	dir, err := os.MkdirTemp("", "kojuto-seccomp-*")
	if err != nil {
		return "", fmt.Errorf("creating seccomp temp dir: %w", err)
	}
	seccompDir = dir

	path := filepath.Join(dir, "seccomp.json")
	if err := os.WriteFile(path, seccompProfile, 0o444); err != nil {
		return "", fmt.Errorf("writing seccomp profile: %w", err)
	}

	return "seccomp=" + path, nil
}

// packagesMountPoint is the in-container path where packages are mounted.
// Uses a generic name to reduce sandbox fingerprinting.
const packagesMountPoint = "/mnt/src"

// containerArgs builds the common Docker flags for both Create and Start.
func (s *Sandbox) containerArgs() ([]string, error) {
	args := []string{
		"--network=none",
		"--security-opt=no-new-privileges",
		"--read-only",
		"--cap-drop=ALL",
		"--tmpfs=/tmp:nosuid,size=100m",
		"--tmpfs=/install:nosuid,size=300m",
		"--tmpfs=/usr/local/lib/python" + SandboxPythonVersion + "/site-packages:nosuid,size=300m",
		"--tmpfs=/usr/local/bin:nosuid,size=32m",
		"--memory=512m",
		"--cpus=1",
		"--pids-limit=256",
	}
	if s.needsPtrace {
		// Re-add only SYS_PTRACE (all others remain dropped).
		args = append(args, "--cap-add=SYS_PTRACE")

		seccompOpt, err := writeSeccompProfile()
		if err != nil {
			return nil, err
		}
		args = append(args, "--security-opt="+seccompOpt)
	}

	args = append(args,
		"-v", s.packageDir+":"+packagesMountPoint+":ro",
		SandboxImage,
		"sleep", "3600",
	)

	return args, nil
}

// Create creates the sandbox container without starting it.
// The container is configured with --network=none, --no-new-privileges, and --read-only.
// Writable tmpfs mounts are provided only where needed (site-packages, /tmp, /install).
// The host filesystem is protected by Docker's copy-on-write isolation.
// When SYS_PTRACE is needed, a restrictive seccomp profile is applied to block
// process_vm_readv/writev and other dangerous syscalls.
func (s *Sandbox) Create(ctx context.Context) error {
	cArgs, err := s.containerArgs()
	if err != nil {
		return err
	}

	args := append([]string{"create"}, cArgs...)
	cmd := exec.CommandContext(ctx, "docker", args...)

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("docker create failed: %w", err)
	}

	s.containerID = strings.TrimSpace(string(out))

	return nil
}

// StartPaused starts the container and immediately pauses it.
// This minimises the TOCTOU window between container start and probe attachment.
func (s *Sandbox) StartPaused(ctx context.Context) error {
	startCmd := exec.CommandContext(ctx, "docker", "start", s.containerID)
	startCmd.Stdout = io.Discard
	startCmd.Stderr = io.Discard

	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("docker start failed: %w", err)
	}

	if err := s.Pause(ctx); err != nil {
		return fmt.Errorf("immediate pause after start: %w", err)
	}

	return nil
}

// Start creates and starts the sandbox container (convenience for strace-container mode
// which does not need the pause-before-probe pattern).
func (s *Sandbox) Start(ctx context.Context) error {
	if err := s.Create(ctx); err != nil {
		return err
	}

	startCmd := exec.CommandContext(ctx, "docker", "start", s.containerID)
	startCmd.Stdout = io.Discard
	startCmd.Stderr = io.Discard

	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("docker start failed: %w", err)
	}

	return nil
}

// Exec runs a command inside the sandbox container and returns the combined output.
func (s *Sandbox) Exec(ctx context.Context, command []string) ([]byte, error) {
	args := append([]string{"exec", s.containerID}, command...)
	cmd := exec.CommandContext(ctx, "docker", args...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("exec in container failed: %w", err)
	}

	return out, nil
}

// InstallPackage runs the install command inside the sandbox.
func (s *Sandbox) InstallPackage(ctx context.Context) ([]byte, error) {
	return s.Exec(ctx, s.InstallCommand())
}

// InstallCommand returns the install command for the ecosystem.
func (s *Sandbox) InstallCommand() []string {
	if s.ecosystem == types.EcosystemNpm {
		return []string{
			"npm", "install",
			"--offline",
			"--ignore-scripts=false",
			"--prefix=/install",
			packagesMountPoint + "/" + s.findTarball(),
		}
	}

	return []string{
		"pip", "install",
		"--no-deps",
		"--no-index",
		"--find-links=" + packagesMountPoint,
		"--", s.pkg,
	}
}

func (s *Sandbox) findTarball() string {
	// Best-effort: find .tgz file in package dir.
	entries, err := os.ReadDir(s.packageDir)
	if err != nil {
		return s.pkg + ".tgz"
	}

	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tgz") {
			return e.Name()
		}
	}

	return s.pkg + ".tgz"
}

// PID returns the init PID of the sandbox container on the host.
func (s *Sandbox) PID(ctx context.Context) (uint32, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Pid}}", s.containerID)

	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("docker inspect failed: %w", err)
	}

	pid, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parsing pid: %w", err)
	}

	return uint32(pid), nil
}

// ContainerID returns the container ID.
func (s *Sandbox) ContainerID() string {
	return s.containerID
}

// Logs returns the container logs.
func (s *Sandbox) Logs(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "logs", s.containerID)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker logs failed: %w", err)
	}

	return string(out), nil
}

// Pause freezes all processes in the container.
func (s *Sandbox) Pause(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "pause", s.containerID)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker pause failed: %w", err)
	}

	return nil
}

// Unpause resumes all processes in the container.
func (s *Sandbox) Unpause(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "unpause", s.containerID)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker unpause failed: %w", err)
	}

	return nil
}

// Cleanup stops and removes the container, and cleans up temporary files.
func (s *Sandbox) Cleanup(ctx context.Context) error {
	if seccompDir != "" {
		os.RemoveAll(seccompDir)
		seccompDir = ""
	}

	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", s.containerID)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker cleanup failed: %w", err)
	}

	return nil
}

// EnsureImage checks if the sandbox image exists, builds it if not.
func EnsureImage(ctx context.Context, dockerfilePath string) error {
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", SandboxImage)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if cmd.Run() == nil {
		return nil // image exists
	}

	buildCmd := exec.CommandContext(ctx, "docker", "build", "-f", dockerfilePath, "-t", SandboxImage, ".")
	buildCmd.Stdout = io.Discard
	buildCmd.Stderr = io.Discard

	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("building sandbox image: %w", err)
	}

	return nil
}
