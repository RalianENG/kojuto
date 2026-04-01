package sandbox

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// SandboxImage is the Docker image used for the sandbox container.
const SandboxImage = "kojuto-sandbox:latest"

// Sandbox manages a Docker container for isolated package installation.
type Sandbox struct {
	containerID string
	packageDir  string
	pkg         string
	needsPtrace bool
}

// New creates a new Sandbox instance.
// If needsPtrace is true, the container is started with --cap-add=SYS_PTRACE
// (required for in-container strace on macOS/Windows).
func New(packageDir, pkg string, needsPtrace bool) *Sandbox {
	return &Sandbox{
		packageDir:  packageDir,
		pkg:         pkg,
		needsPtrace: needsPtrace,
	}
}

// Start creates and starts the sandbox container.
// The container runs with --network=none and --no-new-privileges.
// The filesystem is writable within the ephemeral container layer only;
// the host filesystem is protected by Docker's copy-on-write isolation.
func (s *Sandbox) Start(ctx context.Context) error {
	args := []string{
		"run", "-d",
		"--network=none",
		"--security-opt=no-new-privileges",
		"--memory=512m",
		"--cpus=1",
		"--pids-limit=256",
	}
	if s.needsPtrace {
		args = append(args, "--cap-add=SYS_PTRACE")
	}

	args = append(args,
		"-v", s.packageDir+":/packages:ro",
		SandboxImage,
		"sleep", "3600",
	)

	cmd := exec.CommandContext(ctx, "docker", args...)

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("docker run failed: %w", err)
	}

	s.containerID = strings.TrimSpace(string(out))

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

// InstallPackage runs pip install inside the sandbox.
func (s *Sandbox) InstallPackage(ctx context.Context) ([]byte, error) {
	return s.Exec(ctx, []string{
		"pip", "install",
		"--no-deps",
		"--no-index",
		"--find-links=/packages",
		s.pkg,
	})
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

// Cleanup stops and removes the container.
func (s *Sandbox) Cleanup(ctx context.Context) error {
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
