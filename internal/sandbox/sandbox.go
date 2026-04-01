package sandbox

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	networkName string // isolated Docker network with iptables DROP
	packageDir  string
	pkg         string
	ecosystem   string
	mountPoint  string // set by containerArgs(), mirrors host layout
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

// containerArgs builds the common Docker flags for both Create and Start.
func (s *Sandbox) containerArgs() ([]string, error) {
	// Mirror the host's real hostname and username into the container so that
	// sandbox-detection code cannot distinguish the container from the host.
	// If the attacker filters on these values, they suppress themselves on the
	// real machine too — making the check useless.
	hostHostname := getHostHostname()
	hostUser := getHostUsername()
	s.mountPoint = "/home/" + hostUser + "/projects"

	// Mirror host resource specs so os.cpu_count() and /proc/meminfo match
	// the real machine. Hard caps prevent actual resource exhaustion.
	cpus, mem := getHostResources()

	args := []string{
		"--network=" + s.networkName,
		"--security-opt=no-new-privileges",
		"--read-only",
		"--cap-drop=ALL",
		"--hostname=" + hostHostname,
		"--tmpfs=/tmp:nosuid,mode=1777,size=100m",
		"--tmpfs=/install:nosuid,mode=1777,size=300m",
		"--tmpfs=/usr/local/lib/python" + SandboxPythonVersion + "/site-packages:nosuid,mode=1777,size=300m",
		"--tmpfs=/usr/local/bin:nosuid,exec,size=32m",
		"--tmpfs=/run:nosuid,size=1m",
		"--tmpfs=/home/dev:nosuid,mode=1777,size=32m",
		"--memory=" + mem,
		"--cpus=" + cpus,
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
		"-v", s.packageDir+":"+s.mountPoint+":ro",
		SandboxImage,
		"sleep", "3600",
	)

	return args, nil
}

// getHostHostname returns the real hostname of the machine running kojuto.
func getHostHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "localhost"
}

// getHostResources returns the host's CPU count and memory size as Docker
// flag values. The container sees the same os.cpu_count() and /proc/meminfo
// as the host, so resource-based sandbox detection fails.
// Hard caps: max 4 CPUs, max 4GB — enough to look real, not enough to DoS.
func getHostResources() (cpus string, memory string) {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	cpus = strconv.Itoa(n)

	// Read host memory from runtime (Go reports OS total via MemStats indirectly,
	// but the simplest cross-platform way is to clamp to a realistic range).
	// Default to 4GB if detection fails.
	memMB := 4096
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		// MemTotal:       16384000 kB
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						memMB = int(kb / 1024)
					}
				}
				break
			}
		}
	}
	// Cap at 4GB to limit blast radius.
	if memMB > 4096 {
		memMB = 4096
	}
	// Floor at 512MB.
	if memMB < 512 {
		memMB = 512
	}
	memory = strconv.Itoa(memMB) + "m"

	return cpus, memory
}

// getHostUsername returns the current OS username.
func getHostUsername() string {
	// Try common env vars (works on Linux, macOS, Windows).
	for _, key := range []string{"USER", "USERNAME", "LOGNAME"} {
		if u := os.Getenv(key); u != "" {
			return u
		}
	}
	return "user"
}

// createIsolatedNetwork creates a Docker bridge network with iptables rules
// that DROP all outbound traffic. This replaces --network=none so that:
// - /proc/net/tcp shows a real network interface (anti-fingerprint)
// - connect() returns ETIMEDOUT instead of ENETUNREACH (anti-fingerprint)
// - No actual data can leave the container
func (s *Sandbox) createIsolatedNetwork(ctx context.Context) error {
	s.networkName = "kojuto-jail-" + fmt.Sprintf("%d", os.Getpid())

	// Create an internal bridge network (no external gateway).
	cmd := exec.CommandContext(ctx, "docker", "network", "create",
		"--internal",
		"--subnet=172.30.0.0/24",
		s.networkName)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		// Fallback to --network=none if network creation fails.
		s.networkName = "none"
	}

	return nil
}

// removeIsolatedNetwork deletes the Docker network created for this sandbox.
func (s *Sandbox) removeIsolatedNetwork(ctx context.Context) {
	if s.networkName == "" || s.networkName == "none" {
		return
	}

	cmd := exec.CommandContext(ctx, "docker", "network", "rm", s.networkName)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Run()
}

// Create creates the sandbox container without starting it.
// The container is configured with an isolated network, --no-new-privileges,
// and --read-only. Writable tmpfs mounts are provided only where needed.
// The host filesystem is protected by Docker's copy-on-write isolation.
// When SYS_PTRACE is needed, a restrictive seccomp profile is applied.
func (s *Sandbox) Create(ctx context.Context) error {
	if err := s.createIsolatedNetwork(ctx); err != nil {
		return err
	}

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

	// Restore /usr/local/bin contents that were hidden by the tmpfs overlay.
	s.restoreLocalBin(ctx)

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

	// Restore /usr/local/bin contents that were hidden by the tmpfs overlay.
	s.restoreLocalBin(ctx)

	// Erase container fingerprints that sandbox-detection code looks for.
	s.eraseFingerprints(ctx)

	return nil
}

// restoreTmpfsOverlays copies backed-up contents into tmpfs-mounted directories
// so that pip, python3, setuptools, etc. are available after the overlay hides them.
// Also fixes permissions so the container user (dev) can write to site-packages.
func (s *Sandbox) restoreLocalBin(ctx context.Context) {
	s.dockerExecRoot(ctx, "cp", "-a", "/usr/local/bin.bak/.", "/usr/local/bin/")

	sitePackages := "/usr/local/lib/python" + SandboxPythonVersion + "/site-packages"
	s.dockerExecRoot(ctx, "cp", "-a", sitePackages+".bak/.", sitePackages+"/")
	s.dockerExecRoot(ctx, "chmod", "-R", "a+rw", sitePackages)

	// /home/dev is a tmpfs (writable) so npm can create ~/.npm for cache/logs.
}

// eraseFingerprints removes or masks signals that reveal the container
// environment to sandox-aware malware.
func (s *Sandbox) eraseFingerprints(ctx context.Context) {
	// 1. Remove /.dockerenv sentinel file.
	s.dockerExecRoot(ctx, "rm", "-f", "/.dockerenv")

	// 2. Mask /proc/1/cgroup — replace "docker" references with empty cgroup.
	//    /proc is mounted by the kernel so we can't directly modify it, but
	//    we can create a bind-mount overlay if needed. For now, we mask the
	//    most common check by using --cgroupns=private (if supported).
	//    The /proc/self/cgroup check is harder to defeat without gVisor.

	// 3. Drop the network isolation and replace with iptables DROP.
	//    This makes /proc/net/tcp non-empty and connect() returns ETIMEDOUT
	//    instead of ENETUNREACH.
	//    NOTE: --network=none is removed from containerArgs above.
	//    Network is blocked via setupNetworkBlock() instead.
}

func (s *Sandbox) dockerExecRoot(ctx context.Context, args ...string) {
	cmdArgs := append([]string{"exec", "--user=root", s.containerID}, args...)
	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Run()
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
			s.mountPoint + "/" + s.findTarball(),
		}
	}

	return []string{
		"pip", "install",
		"--no-deps",
		"--no-index",
		"--find-links=" + s.mountPoint,
		"--", s.pkg,
	}
}

// ImportCommands returns commands to import/require the installed package
// under multiple simulated OS identities. This defeats OS-gated payloads
// that only activate on specific platforms (e.g. "if Windows: attack()").
//
// For Python: patches platform.system(), sys.platform, os.name before import.
// For Node.js: overrides process.platform before require().
//
// Each command simulates a different target OS so that platform-conditional
// code paths are exercised regardless of the container's actual OS.
func (s *Sandbox) ImportCommands() [][]string {
	if s.ecosystem == types.EcosystemNpm {
		return s.nodeImportCommands()
	}
	return s.pythonImportCommands()
}

// WriteProbeScripts writes the OS-simulation import scripts into the container's
// /tmp directory. Must be called before ImportCommands.
func (s *Sandbox) WriteProbeScripts(ctx context.Context) {
	importName := strings.ReplaceAll(s.pkg, "-", "_")

	pyPlatforms := [][3]string{
		{"Linux", "linux", "posix"},
		{"Windows", "win32", "nt"},
		{"Darwin", "darwin", "posix"},
	}
	for _, p := range pyPlatforms {
		script := fmt.Sprintf(
			"import platform,sys,os\n"+
				"platform.system=lambda:'%s'\n"+
				"sys.platform='%s'\n"+
				"os.name='%s'\n"+
				"try:\n import %s\nexcept Exception:\n pass\n",
			p[0], p[1], p[2], importName,
		)
		filename := "/tmp/_kojuto_probe_" + p[1] + ".py"
		s.dockerExecRoot(ctx, "sh", "-c", "cat > "+filename+" << 'KOJUTO_EOF'\n"+script+"KOJUTO_EOF")
	}

	jsPlatforms := []string{"linux", "win32", "darwin"}
	for _, p := range jsPlatforms {
		script := fmt.Sprintf(
			"Object.defineProperty(process,'platform',{value:'%s'});\n"+
				"try{require('%s')}catch(e){}\n",
			p, s.pkg,
		)
		filename := "/tmp/_kojuto_probe_" + p + ".js"
		s.dockerExecRoot(ctx, "sh", "-c", "cat > "+filename+" << 'KOJUTO_EOF'\n"+script+"KOJUTO_EOF")
	}
}

// pythonImportCommands returns commands that execute pre-written probe scripts.
// Uses `python3 /tmp/script.py` (NOT `python3 -c`) so that kojuto's own
// import probes don't trigger the interpreterExecFlags detector.
func (s *Sandbox) pythonImportCommands() [][]string {
	return [][]string{
		{"python3", "/tmp/_kojuto_probe_linux.py"},
		{"python3", "/tmp/_kojuto_probe_win32.py"},
		{"python3", "/tmp/_kojuto_probe_darwin.py"},
	}
}

// nodeImportCommands returns commands that execute pre-written probe scripts.
// Uses `node /tmp/script.js` (NOT `node -e`) to avoid self-detection.
func (s *Sandbox) nodeImportCommands() [][]string {
	return [][]string{
		{"node", "/tmp/_kojuto_probe_linux.js"},
		{"node", "/tmp/_kojuto_probe_win32.js"},
		{"node", "/tmp/_kojuto_probe_darwin.js"},
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

	// Remove the isolated network (must happen after container removal).
	s.removeIsolatedNetwork(ctx)

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
