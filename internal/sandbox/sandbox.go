package sandbox

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

// execCommand is the function used to create exec.Cmd instances.
// Tests can replace this to avoid calling Docker.
var execCommand = exec.CommandContext

//go:embed seccomp.json
var seccompProfile []byte

// SandboxImage is the Docker image used for the sandbox container.
const SandboxImage = "kojuto-sandbox:latest"

// SandboxContainerLabel tags every container kojuto creates so
// CleanupStaleSandboxContainers can identify orphans from previous
// runs without disturbing unrelated Docker workloads on the host.
// The literal string lives here (not derived from a build flag) so a
// container created by one kojuto build is recognizable to another.
const SandboxContainerLabel = "kojuto.scan"

// SandboxPythonVersion must match the Python version in Dockerfile.sandbox.
const SandboxPythonVersion = "3.12"

// Runtime selects the container runtime.
const (
	RuntimeDefault = ""      // Docker default (runc).
	RuntimeGVisor  = "runsc" // gVisor user-space kernel.
	RuntimeAuto    = "auto"  // Use gVisor if available, else runc.
	networkNone    = "none"  // Fallback when isolated network creation fails.
)

// Sandbox manages a Docker container for isolated package installation.
type Sandbox struct {
	containerID string
	networkName string // isolated Docker network with iptables DROP
	packageDir  string
	pkg         string
	ecosystem   string
	runtime     string // container runtime (empty = default, "runsc" = gVisor).
	mountPoint  string // set by containerArgs(), mirrors host layout
	needsPtrace bool
	localMode   bool   // when true, install from local files (sdist/wheel) directly
	seccompDir  string // per-instance temp dir for seccomp profile
	// dockerenvMask is the host-side empty file bind-mounted over
	// /.dockerenv to mask the docker-injected sentinel. Lives inside
	// seccompDir so it is cleaned up by the same Cleanup path.
	dockerenvMask string
	scanPkgs      []string
}

// SetLocalMode enables local package installation mode (sdist support).
func (s *Sandbox) SetLocalMode(local bool) {
	s.localMode = local
}

// SetScanPkgs records the full list of packages being audited so the
// audit hook (sitecustomize.py) can identify which call-stack frames
// originate from the scanned package vs. its dependencies. Without
// this, every site-packages frame looks alike and dynamic_exec from
// a malicious target would be mistaken for benign library internals.
func (s *Sandbox) SetScanPkgs(pkgs []string) {
	s.scanPkgs = pkgs
}

// New creates a new Sandbox instance.
// If containerRuntime is "auto", it probes Docker for gVisor availability
// and uses runsc if registered, otherwise falls back to runc.
func New(packageDir, pkg string, needsPtrace bool, ecosystem, containerRuntime string) *Sandbox {
	rt := containerRuntime
	if rt == RuntimeAuto {
		rt = resolveRuntime()
	}
	return &Sandbox{
		packageDir:  packageDir,
		pkg:         pkg,
		needsPtrace: needsPtrace,
		ecosystem:   ecosystem,
		runtime:     rt,
	}
}

// resolveRuntime checks whether gVisor (runsc) is registered as a Docker
// runtime and returns RuntimeGVisor if available, RuntimeDefault otherwise.
func resolveRuntime() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := execCommand(ctx, "docker", "info", "--format", "{{json .Runtimes}}")
	out, err := cmd.Output()
	if err != nil {
		return RuntimeDefault
	}
	if strings.Contains(string(out), "runsc") {
		return RuntimeGVisor
	}
	return RuntimeDefault
}

// writeSeccompProfile writes the embedded seccomp profile and the empty
// /.dockerenv mask file to a per-scan temp dir, then returns the
// --security-opt flag value to pass to docker. The mask path is stashed in
// s.dockerenvMask for containerArgs to bind-mount.
//
// The mask is an empty regular file (not /dev/null) so that
// stat(/.dockerenv).S_ISREG() inside the container still returns true —
// using a char device would itself be a fingerprint that distinguishes
// kojuto's sandbox from a real Docker container.
func (s *Sandbox) writeSeccompProfile() (string, error) {
	dir, err := os.MkdirTemp("", "kojuto-seccomp-*")
	if err != nil {
		return "", fmt.Errorf("creating seccomp temp dir: %w", err)
	}
	s.seccompDir = dir

	path := filepath.Join(dir, "seccomp.json")
	if err := os.WriteFile(path, seccompProfile, 0o444); err != nil {
		return "", fmt.Errorf("writing seccomp profile: %w", err)
	}

	dockerenvMask := filepath.Join(dir, "dockerenv-mask")
	if err := os.WriteFile(dockerenvMask, nil, 0o444); err != nil {
		return "", fmt.Errorf("writing dockerenv mask: %w", err)
	}
	s.dockerenvMask = dockerenvMask

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

	args := []string{}

	// Use gVisor runtime if requested. gVisor masks /proc/1/cgroup and
	// /proc/self/mountinfo, defeating the two remaining container-detection
	// signals that Docker cannot hide.
	if s.runtime != "" {
		args = append(args, "--runtime="+s.runtime)
	}

	args = append(args,
		"--network="+s.networkName,
		// Identifies the container as kojuto-managed. CleanupStaleSandboxContainers
		// uses this label at startup to remove orphans from previous runs that
		// did not get a chance to run their Cleanup defer (SIGKILL, OOM, panic).
		// Running/paused containers from concurrent kojuto invocations are
		// filtered out at cleanup time so live scans are not disturbed.
		"--label="+SandboxContainerLabel+"=true",
		// Fake DNS: RFC 5737 TEST-NET-2 address, guaranteed unreachable.
		// Prevents fingerprinting via empty /etc/resolv.conf while ensuring
		// DNS resolution attempts generate a connect:53 event in strace
		// (connect returns ENETUNREACH — no packets leave the host).
		"--dns=198.51.100.1",
		"--security-opt=no-new-privileges",
		"--read-only",
		"--cap-drop=ALL",
		"--hostname="+hostHostname,
		"--tmpfs=/tmp:nosuid,mode=1777,size=100m",
		"--tmpfs=/usr/local/lib/python"+SandboxPythonVersion+"/site-packages:nosuid,mode=1777,size=300m",
		"--tmpfs=/usr/local/bin:nosuid,exec,mode=0755,size=32m",
		"--tmpfs=/run:nosuid,size=1m",
		"--tmpfs=/home/dev:nosuid,mode=1777,size=32m",
		// Dedicated cache tmpfs outside HOME. npm and pip are pinned here via
		// NPM_CONFIG_CACHE / PIP_CACHE_DIR so their legitimate writes (logs,
		// _cacache, wheel cache) never land under /home/ and never trip the
		// persistence backstop. Keeps the "no /home/ writes" structural
		// guarantee strict without path-based allowlists, which would let
		// malicious packages smuggle artifacts under a benign-looking prefix.
		"--tmpfs=/var/cache/kojuto:nosuid,mode=1777,size=200m",
		"--memory="+mem,
		"--cpus="+cpus,
		"--pids-limit=256",
	)

	// npm: mount packageDir directly as writable /install (skip the copy step).
	// PyPI: use tmpfs for /install and mount packages read-only at the mirror path.
	if s.ecosystem == types.EcosystemNpm {
		args = append(args, "-v", s.packageDir+":/install")
	} else {
		args = append(args, "--tmpfs=/install:nosuid,mode=1777,size=300m")
	}
	// Always apply the restrictive seccomp profile regardless of ptrace needs.
	// Without it, Docker's default seccomp allows memfd_create, userfaultfd,
	// open_by_handle_at, and other container-escape vectors.
	//
	// writeSeccompProfile also stages the host-side /.dockerenv mask file
	// (s.dockerenvMask) used by the bind mount below.
	seccompOpt, err := s.writeSeccompProfile()
	if err != nil {
		return nil, err
	}
	// Mask the docker-injected /.dockerenv sentinel by bind-mounting an
	// empty file from the host over it. We can't `rm /.dockerenv` post-
	// start because --read-only blocks rootfs writes (which is exactly
	// why the previous post-start `rm -f /.dockerenv` always returned
	// exit 1 — silently, until prepareSandboxState was made fail-loud).
	// Sandbox-aware payloads that read /.dockerenv now see an empty
	// regular file. Path-existence checks (`os.path.exists`) still see
	// something, but those are defeated by --runtime=runsc which
	// virtualizes the rootfs entirely.
	args = append(args,
		"--security-opt="+seccompOpt,
		"--mount=type=bind,src="+s.dockerenvMask+",dst=/.dockerenv,readonly",
	)

	if s.needsPtrace {
		// Re-add SYS_PTRACE for strace, CHOWN+FOWNER for tmpfs file setup.
		args = append(args, "--cap-add=SYS_PTRACE", "--cap-add=CHOWN", "--cap-add=FOWNER")
	}

	// Audit hook: load kojuto-require.js before any user code in Node.js.
	// This intercepts eval/Function/vm dynamic code execution.
	//
	// NPM_CONFIG_CACHE / PIP_CACHE_DIR pin package-manager caches to the
	// dedicated /var/cache/kojuto tmpfs. Without these, npm writes
	// /home/dev/.npm/_logs and pip writes /home/dev/.cache/pip — both
	// correctly flagged as persistence by the /home/ structural backstop
	// in the analyzer. Redirecting at the sandbox layer is preferable to
	// relaxing the detection rule: the rule stays strict, while
	// legitimate cache I/O goes to a path the analyzer never inspects.
	args = append(args,
		"--env=NODE_OPTIONS=--require /opt/kojuto/kojuto-require.js",
		"--env=NPM_CONFIG_CACHE=/var/cache/kojuto/npm",
		"--env=PIP_CACHE_DIR=/var/cache/kojuto/pip",
	)

	// Tell sitecustomize.py which packages are being audited so its
	// frame-walking logic can flag dynamic exec originating in those
	// packages while suppressing internal exec calls from compat
	// libraries (six, future, attrs) loaded as dependencies.
	pkgs := s.scanPkgs
	if len(pkgs) == 0 && s.pkg != "" {
		pkgs = []string{s.pkg}
	}
	if len(pkgs) > 0 {
		args = append(args, "--env=KOJUTO_SCAN_PKGS="+strings.Join(pkgs, ","))
	}

	// Honeypot environment variables: simulate a CI/developer machine to
	// trigger environment-gated malware (e.g. "if CI: exfiltrate()").
	// Fake tokens provoke credential-harvesting code paths.
	for _, env := range honeypotEnvVars() {
		args = append(args, "--env="+env)
	}

	// npm already has packageDir mounted as /install above.
	// PyPI needs the read-only mount for --find-links.
	if s.ecosystem != types.EcosystemNpm {
		args = append(args, "-v", s.packageDir+":"+s.mountPoint+":ro")
	}

	args = append(args, SandboxImage, "sleep", "3600")

	return args, nil
}

// getHostHostname returns the real hostname of the machine running kojuto.
// The result is sanitized to prevent Docker flag injection via hostile hostnames.
func getHostHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return sanitizeDockerArg(h, "localhost")
	}
	return "localhost"
}

// sanitizeDockerArg strips characters that could break Docker CLI
// arguments. Output is restricted to [a-zA-Z0-9._-] — the intersection
// of the Docker hostname rule and the chars that are safe to interpolate
// into shell command lines and -v <src>:<dst> volume specs without
// quoting. fallback is returned when every byte was stripped.
func sanitizeDockerArg(s, fallback string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return fallback
	}
	return b.String()
}

// getHostResources returns the host's CPU count and memory size as Docker
// flag values. The container sees the same os.cpu_count() and /proc/meminfo
// as the host, so resource-based sandbox detection fails.
// Hard caps: max 4 CPUs, max 4GB — enough to look real, not enough to DoS.
func getHostResources() (cpus, memory string) {
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

// getHostUsername returns the current OS username, sanitized to the same
// charset as getHostHostname. The result flows into mountPoint =
// "/home/<user>/projects", which is interpolated into a -v <src>:<dst>:ro
// volume spec and a `pip install ... <mountPoint>/*` shell glob. Even
// though env vars are normally trusted, mirroring the hostname sanitizer
// removes any case where a future runner sets USER to something exotic.
func getHostUsername() string {
	for _, key := range []string{"USER", "USERNAME", "LOGNAME"} {
		if u := os.Getenv(key); u != "" {
			return sanitizeDockerArg(u, "user")
		}
	}
	return "user"
}

// createIsolatedNetwork configures complete network isolation for the sandbox.
//
// Security design: --network=none ensures ZERO external communication.
// No DNS resolver, no TCP/UDP sockets, no bridge interface. The kernel
// rejects all connect()/sendto() syscalls with ENETUNREACH — there is
// no network stack to exploit.
//
// Anti-fingerprinting countermeasures:
//   - /.dockerenv masked with an empty regular file via bind mount at
//     create time (see writeSeccompProfile + containerArgs)
//   - Fake /etc/resolv.conf with a plausible nameserver IP via --dns
//   - connect() returning ENETUNREACH is indistinguishable from a firewalled
//     host for most malware (only sophisticated actors check errno values)
//   - /proc/1/cgroup, /proc/self/mountinfo, and /proc/net/tcp emptiness
//     are mitigated by gVisor (--runtime=runsc)
//
// Previous design used --internal bridge networks, which left Docker's
// embedded DNS resolver (127.0.0.11) active inside the container. While
// DNS queries couldn't reach the internet, the resolver process itself
// was a potential attack surface.
func (s *Sandbox) createIsolatedNetwork(_ context.Context) error {
	s.networkName = networkNone
	return nil
}

// removeIsolatedNetwork deletes the Docker network created for this sandbox.
func (s *Sandbox) removeIsolatedNetwork(ctx context.Context) {
	if s.networkName == "" || s.networkName == networkNone {
		return
	}

	cmd := execCommand(ctx, "docker", "network", "rm", s.networkName)
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
	cmd := execCommand(ctx, "docker", args...)

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("docker create failed: %w", err)
	}

	s.containerID = strings.TrimSpace(string(out))

	return nil
}

// StartPaused starts the container and immediately pauses it.
// This minimizes the TOCTOU window between container start and probe attachment.
//
// Errors from restoreLocalBin / plantHoneypotFiles are surfaced rather than
// swallowed: if the sandbox can't be brought to a honeypot-planted state,
// sandbox-aware malware may stay dormant and produce a false-clean verdict.
// The caller is expected to abort the scan (and surface "inconclusive") on
// any error returned here. /.dockerenv masking is handled at create time
// via bind mount (see writeSeccompProfile + containerArgs).
//
// Error-path cleanup: once `docker start` succeeds the container is in
// Up state, and CleanupStaleSandboxContainers deliberately skips Up-state
// containers to protect concurrent scans. If a subsequent prepare step
// fails and this function returns error, the caller has no *Sandbox
// pointer to Cleanup(), so the container would leak permanently. The
// defer below fires only on the error path (started stays false) and
// tears down the partial sandbox before returning.
func (s *Sandbox) StartPaused(ctx context.Context) error {
	startCmd := execCommand(ctx, "docker", "start", s.containerID)
	startCmd.Stdout = io.Discard
	startCmd.Stderr = io.Discard

	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("docker start failed: %w", err)
	}

	started := false
	// contextcheck suppressed: rollbackPartialStart deliberately uses a
	// fresh context.Background() with its own timeout because the parent
	// ctx is typically already canceled by the time the rollback fires
	// (that's what caused prepare to fail). Inheriting the canceled
	// parent would make docker rm -f fail immediately, defeating the
	// rollback.
	defer func() { //nolint:contextcheck // see comment above
		if !started {
			s.rollbackPartialStart()
		}
	}()

	if err := s.prepareSandboxState(ctx); err != nil {
		return err
	}

	if err := s.Pause(ctx); err != nil {
		return fmt.Errorf("immediate pause after start: %w", err)
	}

	started = true
	return nil
}

// Start creates and starts the sandbox container (convenience for strace-container mode
// which does not need the pause-before-probe pattern). See StartPaused for the
// rationale on surfacing prep errors AND on the error-path cleanup below.
func (s *Sandbox) Start(ctx context.Context) error {
	if err := s.Create(ctx); err != nil {
		return err
	}

	startCmd := execCommand(ctx, "docker", "start", s.containerID)
	startCmd.Stdout = io.Discard
	startCmd.Stderr = io.Discard

	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("docker start failed: %w", err)
	}

	started := false
	// contextcheck suppressed: rollbackPartialStart deliberately uses a
	// fresh context.Background() with its own timeout because the parent
	// ctx is typically already canceled by the time the rollback fires
	// (that's what caused prepare to fail). Inheriting the canceled
	// parent would make docker rm -f fail immediately, defeating the
	// rollback.
	defer func() { //nolint:contextcheck // see comment above
		if !started {
			s.rollbackPartialStart()
		}
	}()

	if err := s.prepareSandboxState(ctx); err != nil {
		return err
	}

	started = true
	return nil
}

// rollbackPartialStart removes a container that was successfully started
// but whose post-start preparation (prepareSandboxState, immediate Pause)
// failed. Runs from a deferred error path in Start / StartPaused where
// the caller does not receive a *Sandbox pointer and thus never
// registers the outer Cleanup defer. Uses its own timeout because the
// parent context that caused the failure is typically already canceled.
// Errors are logged but not returned — the original prepare error is
// what the caller needs to see.
func (s *Sandbox) rollbackPartialStart() {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rm := execCommand(cleanupCtx, "docker", "rm", "-f", s.containerID)
	rm.Stdout = io.Discard
	rm.Stderr = io.Discard
	if err := rm.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Rollback of partial sandbox %s failed: %v\n",
			s.containerID, err)
	}
}

// prepareSandboxState runs the post-start container setup that every scan
// depends on. Each step is fail-loud: a swallowed error here would let the
// scan run in a partially-prepared sandbox (e.g. honeypot files missing)
// and report "clean" for malware that simply detected the gap and stayed
// quiet.
//
// /.dockerenv masking is intentionally NOT here — it's done at create time
// via a bind mount in containerArgs (see writeSeccompProfile). The previous
// post-start `rm -f /.dockerenv` could never succeed under --read-only and
// silently failed for every scan.
func (s *Sandbox) prepareSandboxState(ctx context.Context) error {
	if err := s.restoreLocalBin(ctx); err != nil {
		return fmt.Errorf("restoring sandbox tmpfs overlays: %w", err)
	}
	if err := s.plantHoneypotFiles(ctx); err != nil {
		return fmt.Errorf("planting honeypot files: %w", err)
	}
	return nil
}

// restoreTmpfsOverlays copies backed-up contents into tmpfs-mounted directories
// so that pip, python3, setuptools, etc. are available after the overlay hides them.
// Also fixes permissions so the container user (dev) can write to site-packages.
//
// Failures are fatal: if pip/python3 are not present at the expected paths the
// install phase will fail in a confusing way, and a missing chmod can leave
// site-packages read-only so the install silently produces no events.
func (s *Sandbox) restoreLocalBin(ctx context.Context) error {
	if err := s.dockerExecRoot(ctx, "cp", "-a", "/usr/local/bin.bak/.", "/usr/local/bin/"); err != nil {
		return err
	}
	if err := s.dockerExecRoot(ctx, "chmod", "-R", "a+rw", "/usr/local/bin"); err != nil {
		return err
	}

	sitePackages := "/usr/local/lib/python" + SandboxPythonVersion + "/site-packages"
	if err := s.dockerExecRoot(ctx, "cp", "-a", sitePackages+".bak/.", sitePackages+"/"); err != nil {
		return err
	}
	if err := s.dockerExecRoot(ctx, "chmod", "-R", "a+rw", sitePackages); err != nil {
		return err
	}

	// npm: packageDir is mounted directly as writable /install,
	// so no copy is needed. Just fix ownership for the dev user.
	if s.ecosystem == types.EcosystemNpm {
		if err := s.dockerExecRoot(ctx, "chown", "-R", "1000:1000", "/install"); err != nil {
			return err
		}
	}

	return nil
}

// base62Chars is the character set used by real AWS/GitHub/npm tokens.
// Using hex-only characters makes honeypot tokens statistically detectable
// (hex has 16 chars, base62 has 62 — entropy per character differs).
const base62Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// randBase62 returns n random base62 characters, matching the character
// distribution of real cloud tokens and API keys.
func randBase62(n int) string {
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(base62Chars))))
		if err != nil {
			b[i] = base62Chars[0]
			continue
		}
		b[i] = base62Chars[idx.Int64()]
	}
	return string(b)
}

// randHex returns n random hex characters (still used for non-token values).
func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// fakeAWSKeyID generates a realistic AWS access key ID.
// Real format: AKIA + 16 base62 chars (not hex-only).
func fakeAWSKeyID() string {
	return "AKIA" + randBase62(16)
}

// fakeAWSSecret generates a realistic AWS secret access key.
// Real format: 40 base64-like chars (mixed case + digits + /+).
func fakeAWSSecret() string {
	return randBase62(40)
}

// fakeGitHubToken generates a realistic GitHub PAT.
// Real format: ghp_ + 36 base62 chars.
func fakeGitHubToken() string {
	return "ghp_" + randBase62(36)
}

// fakeNpmToken generates a realistic npm token.
// Real format: npm_ + 36 base62 chars.
func fakeNpmToken() string {
	return "npm_" + randBase62(36)
}

// honeypotEnvVars returns environment variables that simulate a CI/developer
// machine. Malware often gates execution on these signals (e.g. "if CI=true,
// exfiltrate tokens"). Tokens are randomly generated per scan so that
// static fingerprinting of known honeypot values is not possible.
func honeypotEnvVars() []string {
	return []string{
		// CI / automation signals.
		"CI=true",
		"GITHUB_ACTIONS=true",
		"GITLAB_CI=true",
		"BUILD_ID=" + randHex(8),
		// Fake cloud credentials (random per scan).
		"AWS_ACCESS_KEY_ID=" + fakeAWSKeyID(),
		"AWS_SECRET_ACCESS_KEY=" + fakeAWSSecret(),
		"AWS_DEFAULT_REGION=us-east-1",
		// Fake developer tokens (random per scan).
		"GITHUB_TOKEN=" + fakeGitHubToken(),
		"NPM_TOKEN=" + fakeNpmToken(),
	}
}

// plantHoneypotFiles writes realistic-looking but fake credential files into
// the container. All secret values are randomly generated per scan to prevent
// static fingerprinting by malware that knows kojuto's source code.
// When malware reads these via openat, the access is detected by the
// sensitive-path monitor. If it then tries to exfiltrate the contents,
// the connect/sendto monitor catches the network activity.
//
// Failure here is fatal: a partially-planted set of honeypots leaves the
// detection contract ("if you read .ssh/id_rsa, you tripped the monitor")
// unenforceable for the missing files.
func (s *Sandbox) plantHoneypotFiles(ctx context.Context) error {
	home := "/home/dev"

	// Generate random credentials for this scan.
	awsKey := fakeAWSKeyID()
	awsSecret := fakeAWSSecret()
	ghToken := fakeGitHubToken()
	sshKeyBody := randHex(64)

	steps := []func() error{
		// SSH key pair.
		func() error { return s.dockerExecRoot(ctx, "mkdir", "-p", home+"/.ssh") },
		func() error {
			return s.dockerWriteFile(ctx, home+"/.ssh/id_rsa",
				"-----BEGIN OPENSSH PRIVATE KEY-----\n"+
					"b3BlbnNzaC1rZXktdjEAAAAAFAAAAAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5\n"+
					"AAAAI"+sshKeyBody+"\n"+
					"-----END OPENSSH PRIVATE KEY-----\n")
		},
		func() error { return s.dockerExecRoot(ctx, "chmod", "600", home+"/.ssh/id_rsa") },

		// AWS credentials.
		func() error { return s.dockerExecRoot(ctx, "mkdir", "-p", home+"/.aws") },
		func() error {
			return s.dockerWriteFile(ctx, home+"/.aws/credentials",
				"[default]\n"+
					"aws_access_key_id = "+awsKey+"\n"+
					"aws_secret_access_key = "+awsSecret+"\n")
		},

		// Git credentials.
		func() error {
			return s.dockerWriteFile(ctx, home+"/.git-credentials",
				"https://dev:"+ghToken+"@github.com\n")
		},
		func() error { return s.dockerExecRoot(ctx, "chmod", "600", home+"/.git-credentials") },

		// Netrc.
		func() error {
			return s.dockerWriteFile(ctx, home+"/.netrc",
				"machine github.com\n"+
					"login dev\n"+
					"password "+ghToken+"\n")
		},
		func() error { return s.dockerExecRoot(ctx, "chmod", "600", home+"/.netrc") },

		// GitHub CLI config.
		func() error { return s.dockerExecRoot(ctx, "mkdir", "-p", home+"/.config/gh") },
		func() error {
			return s.dockerWriteFile(ctx, home+"/.config/gh/hosts.yml",
				"github.com:\n"+
					"    oauth_token: "+ghToken+"\n"+
					"    user: dev\n"+
					"    git_protocol: https\n")
		},

		// Fix ownership so the container user (dev) owns the files.
		func() error {
			return s.dockerExecRoot(ctx, "chown", "-R", "1000:1000", home+"/.ssh", home+"/.aws",
				home+"/.git-credentials", home+"/.netrc", home+"/.config")
		},
	}

	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// dockerExecRoot runs the given command inside the sandbox as root.
// Returns an error wrapped with the sandbox-internal command (not the
// container ID, which is noise for the user) so callers can surface a
// useful message when fingerprint-erasure or honeypot-planting fails.
func (s *Sandbox) dockerExecRoot(ctx context.Context, args ...string) error {
	cmdArgs := append([]string{"exec", "--user=root", s.containerID}, args...)
	cmd := execCommand(ctx, "docker", cmdArgs...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker exec %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// dockerWriteFile writes content into the container at path as root.
// The body is delivered via stdin to `cat`, which keeps it out of the
// shell command line entirely — unlike a `<< 'EOF'` heredoc, an attacker
// who controls part of the body cannot smuggle a stray terminator line
// to break out of the heredoc and execute arbitrary commands as root in
// the container. path is single-quoted as defense-in-depth even though
// every current caller passes a constant.
//
// The content is omitted from the error to avoid spilling honeypot
// credentials or large probe scripts into logs.
func (s *Sandbox) dockerWriteFile(ctx context.Context, path, content string) error {
	cmdArgs := []string{"exec", "-i", "--user=root", s.containerID, "sh", "-c", "cat > " + shQuote(path)}
	cmd := execCommand(ctx, "docker", cmdArgs...)
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker write %s: %w", path, err)
	}
	return nil
}

// Exec runs a command inside the sandbox container and returns the combined output.
func (s *Sandbox) Exec(ctx context.Context, command []string) ([]byte, error) {
	args := append([]string{"exec", s.containerID}, command...)
	cmd := execCommand(ctx, "docker", args...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("exec in container failed: %w", err)
	}

	return out, nil
}

// InstallPackage runs the install command inside the sandbox.
func (s *Sandbox) InstallPackage(ctx context.Context) ([]byte, error) {
	cmd, err := s.InstallCommand(ctx)
	if err != nil {
		return nil, err
	}
	return s.Exec(ctx, cmd)
}

// installScriptPath is the in-container location where the probe stages
// its install script before strace attaches. Sits on the dedicated
// /var/cache/kojuto tmpfs configured in containerArgs.
//
// The probe is invoked as `sh <installScriptPath>` rather than the
// previous `sh -c <inline script>`. The shape difference matters: the
// analyzer's classifyExecve treats `sh -c ...` as a positive attack
// signature when the contents fail isShellCmdBenign, which produces a
// guaranteed false positive on every npm scan because kojuto's own
// install loop (find + while + npm run ...) cannot pass the benign
// check. Switching to `sh <path>` lets isBenignExec recognize sh from
// /bin/ as benign and filter the outer probe shell entirely without
// any allowlist, marker, or PID-based filtering.
//
// Attackers cannot mimic this shape: the cmdline of a shell spawned
// from a package's preinstall hook is determined by npm/yarn/pnpm
// (`sh -c <package script>`), not by the package itself.
const installScriptPath = "/var/cache/kojuto/install.sh"

// stageInstallScript writes content to installScriptPath inside the
// running container. Used by InstallCommand/InstallAllCommand to stage
// the probe script before strace attaches. The write happens via a
// separate docker exec session, so the syscalls it produces are not
// observed by the install-phase strace.
func (s *Sandbox) stageInstallScript(ctx context.Context, content string) ([]string, error) {
	if err := s.dockerWriteFile(ctx, installScriptPath, content); err != nil {
		return nil, fmt.Errorf("stage install script: %w", err)
	}
	return []string{"sh", installScriptPath}, nil
}

// InstallCommand returns the install command for the ecosystem. For
// ecosystems that need a shell-driven install (npm lifecycle hooks,
// local-mode pip glob expansion), this method writes the install
// script to the container's tmpfs first and returns a file-path-based
// command so the outer probe shell does not trigger the analyzer's
// `sh -c` attack-signature branch. See installScriptPath for the
// design rationale.
func (s *Sandbox) InstallCommand(ctx context.Context) ([]string, error) {
	if s.ecosystem == types.EcosystemNpm {
		// The host has already resolved deps into node_modules (with
		// --ignore-scripts). Inside the sandbox we fire each package's
		// preinstall + install + postinstall hooks under strace.
		// `npm rebuild` (the previous approach) only runs the `install`
		// script and rebuilds native modules — it skips preinstall and
		// postinstall, which is exactly where most npm supply chain
		// attacks place their payload (axios, crypto-js, Shai-Hulud).
		return s.stageInstallScript(ctx, npmLifecycleScript(nil))
	}

	// Local mode: install directly from the file in the mount point.
	// Source distributions (.tar.gz) need build tools, so we allow
	// pip to use pre-installed setuptools/wheel (no network needed).
	if s.localMode {
		// Find the actual file in the mount point and install it directly.
		// This handles both wheels (.whl) and source distributions (.tar.gz).
		return s.stageInstallScript(ctx,
			"pip install --no-index --no-deps --no-build-isolation "+s.mountPoint+"/*")
	}

	// Install with dependencies — all wheels in the mount point are installed
	// together under strace monitoring. This catches compromised transitive
	// dependencies (e.g. supply chain attacks via trusted dep packages).
	return []string{
		"pip", "install",
		"--no-index",
		"--find-links=" + s.mountPoint,
		"--", s.pkg,
	}, nil
}

// InstallAllCommand returns a pip install command that installs multiple packages at once.
// All wheels must already be in the mount point directory.
//
// For npm, this writes the install script to the container tmpfs and
// returns a file-path-based command — see InstallCommand for rationale.
func (s *Sandbox) InstallAllCommand(ctx context.Context, pkgs []string) ([]string, error) {
	if s.ecosystem == types.EcosystemNpm {
		// Fire lifecycle scripts only for the target packages (not all
		// transitive deps). Transitive deps without lifecycle scripts
		// are covered by the import phase which loads them via require().
		return s.stageInstallScript(ctx, npmLifecycleScript(pkgs))
	}

	cmd := []string{
		"pip", "install",
		"--no-index",
		"--find-links=" + s.mountPoint,
		"--",
	}
	return append(cmd, pkgs...), nil
}

// npmLifecycleParallelism is the maximum number of package lifecycle
// hook chains npmLifecycleScript runs concurrently. Each chain spawns
// a small process tree (sh + npm + node + helpers), so the bound is
// driven by --pids-limit=256 and per-container CPU/memory headroom
// rather than by host parallelism — at the chosen value of 4, peak
// concurrent process count stays well under the limit even for
// native-module packages that fork compiler toolchains. Mirrors
// audit.py's worker count for consistency.
const npmLifecycleParallelism = 4

// npmLifecycleScript builds a /bin/sh script that fires preinstall +
// install + postinstall hooks for each target package directory under
// /install/node_modules. When pkgs is nil, every package directory at
// the top tier of node_modules is exercised (handles both bare names
// and scoped @scope/name layouts via find at depth 2-3).
//
// `npm run --silent --if-present <hook>` is used so that:
//   - missing hooks are no-ops (no need to inspect each package.json),
//   - npm's own status output stays out of the strace stream.
//
// Each package runs in its own subshell with `;` between hooks so a
// single failing script does not abort the whole sweep — partial
// progress is what we want for a forensic capture.
//
// xargs -P drives the parallelism. With sequential `;`-joined
// subshells the older form spent ~1 second per package on npm CLI
// startup alone (300 invocations across 100 packages, mostly no-op
// `--if-present` skips), which dominated batch scan wall time.
// Parallel execution lets the strace stream interleave events from
// up to npmLifecycleParallelism PIDs at once; the analyzer's
// streaming PID→comm pass attributes each event correctly because
// every clone/execve carries its own PID and the JIT/library-hijack
// rules look up that PID independently.
//
// xargs -I{} treats one input line as one argument. We use `\n` as
// the separator (not `\0`) because dash's printf builtin lacks
// portable `\0` support and npm package names cannot contain
// newlines (npm registry name spec: `[a-z0-9._@~/-]`). Single-
// quoting the cd target inside the inserted command is defense-in-
// depth in case a future code path bypasses depfile name validation.
func npmLifecycleScript(pkgs []string) string {
	const hooks = `npm run --silent --if-present preinstall; ` +
		`npm run --silent --if-present install; ` +
		`npm run --silent --if-present postinstall`
	parallel := strconv.Itoa(npmLifecycleParallelism)

	if len(pkgs) == 0 {
		// mindepth 2 catches /install/node_modules/<pkg>/package.json,
		// maxdepth 3 also catches /install/node_modules/@scope/<pkg>/package.json
		// while excluding nested transitive node_modules.
		//
		// `find -print0 | xargs -0` is portable across dash and bash and
		// avoids the `read -d ""` portability issue that motivated the
		// previous `find | while read` form.
		return `find /install/node_modules -mindepth 2 -maxdepth 3 -name package.json -type f -print0 ` +
			`| xargs -0 -P ` + parallel + ` -I{} sh -c 'd=$(dirname "{}") && cd "$d" && ` + hooks + `' 2>&1`
	}

	var b strings.Builder
	b.WriteString(`printf '%s\n'`)
	for _, p := range pkgs {
		b.WriteByte(' ')
		// Single-quote the full cd target so any shell metacharacters
		// in p (which originates from package.json keys, i.e. attacker-
		// controllable input) cannot break out of the argument. depfile
		// validates names at parse time; this is defense-in-depth for
		// any future code path that populates pkgs from another source.
		b.WriteString(shQuote("/install/node_modules/" + p))
	}
	b.WriteString(` | xargs -P ` + parallel + ` -I{} sh -c 'cd "{}" && `)
	b.WriteString(hooks)
	b.WriteString(`' 2>&1`)
	return b.String()
}

// shQuote wraps s in POSIX single quotes, escaping any embedded single
// quote with the standard '\” close-escape-reopen idiom. Safe for use
// in /bin/sh, dash, and bash.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// WriteProbeScriptsMulti writes one combined import probe script per OS identity.
// This reduces Python/Node process launches from N*3 to just 3.
//
// Returns an error if any script fails to land in the container. A missing
// probe script silently skips the corresponding OS-identity import phase,
// hiding platform-gated payloads — that is itself a false-clean vector.
func (s *Sandbox) WriteProbeScriptsMulti(ctx context.Context, pkgs []string) error {
	if s.ecosystem == types.EcosystemNpm {
		for _, p := range []string{"linux", "win32", "darwin"} {
			var requires strings.Builder
			for _, pkg := range pkgs {
				fmt.Fprintf(&requires, "try{require('%s')}catch(e){}\n", pkg)
			}
			script := fmt.Sprintf(
				"module.paths.unshift('/install/node_modules');\n"+
					"Object.defineProperty(process,'platform',{value:'%s'});\n"+
					"%s",
				p, requires.String(),
			)
			filename := "/tmp/_kojuto_probe_all_" + p + ".js"
			if err := s.dockerWriteFile(ctx, filename, script); err != nil {
				return err
			}
		}
		return nil
	}

	type pyPlatform struct {
		system, sysplatform, osname string
		sep, pathsep, linesep       string
	}
	// linesep is interpolated into a single-quoted Python string literal.
	// The escape sequences must be the LITERAL backslash-letter forms
	// ("\\n" / "\\r\\n") so that Python parses them — embedding a real
	// newline byte breaks the source mid-line with SyntaxError.
	pyPlatforms := []pyPlatform{
		{"Linux", "linux", "posix", "/", ":", "\\n"},
		{"Windows", "win32", "nt", "\\\\", ";", "\\r\\n"},
		{"Darwin", "darwin", "posix", "/", ":", "\\n"},
	}
	for _, p := range pyPlatforms {
		var imports strings.Builder
		for _, pkg := range pkgs {
			importName := strings.ReplaceAll(pkg, "-", "_")
			fmt.Fprintf(&imports, "try:\n __import__('%s')\nexcept Exception:\n pass\n", importName)
		}
		script := fmt.Sprintf(
			"import platform,sys,os,collections\n"+
				"for _k in ['LD_PRELOAD','FAKETIME','FAKETIME_NO_CACHE','FAKETIME_TIMESTAMP_FILE']:\n"+
				" os.environ.pop(_k,None)\n"+
				"platform.system=lambda:'%s'\n"+
				"_real_uname=platform.uname()\n"+
				"_UnameTuple=collections.namedtuple('uname_result',['system','node','release','version','machine','processor'])\n"+
				"platform.uname=lambda:_UnameTuple('%s',_real_uname.node,_real_uname.release,_real_uname.version,_real_uname.machine,_real_uname.processor)\n"+
				"sys.platform='%s'\n"+
				"os.name='%s'\n"+
				"os.sep='%s'\n"+
				"os.pathsep='%s'\n"+
				"os.linesep='%s'\n"+
				"%s",
			p.system, p.system, p.sysplatform, p.osname,
			p.sep, p.pathsep, p.linesep, imports.String(),
		)
		filename := "/tmp/_kojuto_probe_all_" + p.sysplatform + ".py"
		if err := s.dockerWriteFile(ctx, filename, script); err != nil {
			return err
		}
	}
	return nil
}

// ImportCommandsMulti returns 3 import commands (one per OS identity) that import all packages.
func (s *Sandbox) ImportCommandsMulti(pkgs []string) [][]string {
	_ = pkgs // package list is already baked into the script files
	if s.ecosystem == types.EcosystemNpm {
		return [][]string{
			wrapWithFaketime([]string{"node", "/tmp/_kojuto_probe_all_linux.js"}),
			wrapWithFaketime([]string{"node", "/tmp/_kojuto_probe_all_win32.js"}),
			wrapWithFaketime([]string{"node", "/tmp/_kojuto_probe_all_darwin.js"}),
		}
	}
	return [][]string{
		wrapWithFaketime([]string{"python3", "/tmp/_kojuto_probe_all_linux.py"}),
		wrapWithFaketime([]string{"python3", "/tmp/_kojuto_probe_all_win32.py"}),
		wrapWithFaketime([]string{"python3", "/tmp/_kojuto_probe_all_darwin.py"}),
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
// /tmp directory. Must be called before ImportCommands. Returns an error if any
// script fails to land — see WriteProbeScriptsMulti for the rationale.
func (s *Sandbox) WriteProbeScripts(ctx context.Context) error {
	importName := strings.ReplaceAll(s.pkg, "-", "_")

	// Each simulated OS must be consistent across ALL platform detection APIs.
	// Malware checks platform.system() vs platform.uname().system, os.sep vs
	// sys.platform, etc. Any inconsistency reveals the spoofing.
	type pyPlatform struct {
		system, sysplatform, osname string
		sep, pathsep, linesep       string
	}
	// linesep is interpolated into a single-quoted Python string literal.
	// The escape sequences must be the LITERAL backslash-letter forms
	// ("\\n" / "\\r\\n") so that Python parses them — embedding a real
	// newline byte breaks the source mid-line with SyntaxError.
	pyPlatforms := []pyPlatform{
		{"Linux", "linux", "posix", "/", ":", "\\n"},
		{"Windows", "win32", "nt", "\\\\", ";", "\\r\\n"},
		{"Darwin", "darwin", "posix", "/", ":", "\\n"},
	}
	for _, p := range pyPlatforms {
		script := fmt.Sprintf(
			"import platform,sys,os,collections\n"+
				// Erase faketime traces from the environment BEFORE importing
				// the target package. libfaketime is already loaded via LD_PRELOAD
				// and continues to work even after we remove these variables.
				"for _k in ['LD_PRELOAD','FAKETIME','FAKETIME_NO_CACHE','FAKETIME_TIMESTAMP_FILE']:\n"+
				" os.environ.pop(_k,None)\n"+
				// Patch platform.system() — the obvious one.
				"platform.system=lambda:'%s'\n"+
				// Patch platform.uname() — returns a named tuple.
				// Must match platform.system() or the spoof is detectable.
				"_real_uname=platform.uname()\n"+
				"_UnameTuple=collections.namedtuple('uname_result',['system','node','release','version','machine','processor'])\n"+
				"platform.uname=lambda:_UnameTuple('%s',_real_uname.node,_real_uname.release,_real_uname.version,_real_uname.machine,_real_uname.processor)\n"+
				// Patch sys.platform and os.name.
				"sys.platform='%s'\n"+
				"os.name='%s'\n"+
				// Patch os.sep, os.pathsep, os.linesep for consistency.
				"os.sep='%s'\n"+
				"os.pathsep='%s'\n"+
				"os.linesep='%s'\n"+
				"try:\n import %s\nexcept Exception:\n pass\n",
			p.system, p.system, p.sysplatform, p.osname,
			p.sep, p.pathsep, p.linesep, importName,
		)
		filename := "/tmp/_kojuto_probe_" + p.sysplatform + ".py"
		if err := s.dockerWriteFile(ctx, filename, script); err != nil {
			return err
		}
	}

	jsPlatforms := []string{"linux", "win32", "darwin"}
	for _, p := range jsPlatforms {
		script := fmt.Sprintf(
			"module.paths.unshift('/install/node_modules');\n"+
				"Object.defineProperty(process,'platform',{value:'%s'});\n"+
				"try{require('%s')}catch(e){}\n",
			p, s.pkg,
		)
		filename := "/tmp/_kojuto_probe_" + p + ".js"
		if err := s.dockerWriteFile(ctx, filename, script); err != nil {
			return err
		}
	}
	return nil
}

// faketimeEnv returns environment variable prefix that activates libfaketime.
// The clock is advanced by a random offset between 30 and 180 days so that:
// - Absolute date checks (e.g. "if date > May 1st: attack()") trigger immediately
// - Relative sleeps (e.g. sleep(300)) complete in ~3 seconds
// - The random offset prevents malware from hardcoding a bypass for a fixed shift
// The upper bound of 180 days avoids TLS certificate expiry issues that could
// break pip/npm operations (certificates are valid for up to 398 days).
// libfaketime intercepts gettimeofday/clock_gettime at the libc level, which
// covers Python's datetime.now(), time.time(), and Node's Date.now().
func faketimeEnv() []string {
	days := faketimeShiftDays()
	return []string{
		"LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
		fmt.Sprintf("FAKETIME=+%dd", days),
		"FAKETIME_NO_CACHE=1",
		"FAKETIME_TIMESTAMP_FILE=",
	}
}

// faketimeShiftDays returns a random number of days between 30 and 180.
func faketimeShiftDays() int {
	n, err := rand.Int(rand.Reader, big.NewInt(151)) // [0, 150]
	if err != nil {
		return 30 // fallback to minimum on error
	}
	return int(n.Int64()) + 30 // [30, 180]
}

// wrapWithFaketime prepends env command with faketime environment variables
// to the given command, so the process sees a clock advanced by a random offset.
func wrapWithFaketime(cmd []string) []string {
	envArgs := []string{"env"}
	envArgs = append(envArgs, faketimeEnv()...)
	return append(envArgs, cmd...)
}

// pythonImportCommands returns commands that execute pre-written probe scripts.
// Uses `python3 /tmp/script.py` (NOT `python3 -c`) so that kojuto's own
// import probes don't trigger the interpreterExecFlags detector.
// Commands are wrapped with libfaketime to trigger date-gated payloads.
func (s *Sandbox) pythonImportCommands() [][]string {
	return [][]string{
		wrapWithFaketime([]string{"python3", "/tmp/_kojuto_probe_linux.py"}),
		wrapWithFaketime([]string{"python3", "/tmp/_kojuto_probe_win32.py"}),
		wrapWithFaketime([]string{"python3", "/tmp/_kojuto_probe_darwin.py"}),
	}
}

// nodeImportCommands returns commands that execute pre-written probe scripts.
// Uses `node /tmp/script.js` (NOT `node -e`) to avoid self-detection.
// Commands are wrapped with libfaketime to trigger date-gated payloads.
func (s *Sandbox) nodeImportCommands() [][]string {
	return [][]string{
		wrapWithFaketime([]string{"node", "/tmp/_kojuto_probe_linux.js"}),
		wrapWithFaketime([]string{"node", "/tmp/_kojuto_probe_win32.js"}),
		wrapWithFaketime([]string{"node", "/tmp/_kojuto_probe_darwin.js"}),
	}
}

// PID returns the init PID of the sandbox container on the host.
func (s *Sandbox) PID(ctx context.Context) (uint32, error) {
	cmd := execCommand(ctx, "docker", "inspect", "-f", "{{.State.Pid}}", s.containerID)

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
	cmd := execCommand(ctx, "docker", "logs", s.containerID)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker logs failed: %w", err)
	}

	return string(out), nil
}

// Pause freezes all processes in the container.
func (s *Sandbox) Pause(ctx context.Context) error {
	cmd := execCommand(ctx, "docker", "pause", s.containerID)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker pause failed: %w", err)
	}

	return nil
}

// Unpause resumes all processes in the container.
func (s *Sandbox) Unpause(ctx context.Context) error {
	cmd := execCommand(ctx, "docker", "unpause", s.containerID)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker unpause failed: %w", err)
	}

	return nil
}

// CleanupStaleSandboxContainers removes kojuto-labeled containers that
// are no longer running. Called at scan startup to mop up orphans from
// prior invocations whose Cleanup defer did not get a chance to fire
// (SIGKILL, OOM, panic, parent-process kill).
//
// Filters by label and status only:
//
//   - `label=kojuto.scan` restricts the sweep to containers kojuto
//     itself created; unrelated Docker workloads on the host are
//     left alone.
//   - The `status=exited|created|dead` triple matches every non-live
//     state a stopped container can be in, and excludes `running` /
//     `paused` so concurrent kojuto invocations are not disturbed.
//
// Failures are logged but do not abort scan startup — the caller is
// scanning a package; container hygiene is best-effort cleanup, not a
// hard precondition. Returns the count of removed containers so the
// caller can surface a one-line summary if any were swept.
//
// Implementation note: a single `docker ps -aq --filter label=...
// --filter status=...` call cannot OR multiple statuses (Docker
// applies multiple --filter as AND), so the three states are queried
// independently and concatenated before `docker rm -f`.
func CleanupStaleSandboxContainers(ctx context.Context) (int, error) {
	var ids []string
	for _, status := range []string{"exited", "created", "dead"} {
		cmd := execCommand(ctx, "docker", "ps", "-aq",
			"--filter", "label="+SandboxContainerLabel,
			"--filter", "status="+status,
		)
		out, err := cmd.Output()
		if err != nil {
			// Docker daemon down or unreachable. Skip cleanup; the
			// scan itself will fail with a clearer error if Docker
			// is genuinely unavailable.
			return 0, fmt.Errorf("listing stale kojuto containers (status=%s): %w", status, err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			id := strings.TrimSpace(line)
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}

	args := append([]string{"rm", "-f"}, ids...)
	cmd := execCommand(ctx, "docker", args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("removing %d stale kojuto containers: %w", len(ids), err)
	}
	return len(ids), nil
}

// Cleanup stops and removes the container, and cleans up temporary files.
func (s *Sandbox) Cleanup(ctx context.Context) error {
	if s.seccompDir != "" {
		os.RemoveAll(s.seccompDir)
		s.seccompDir = ""
	}

	cmd := execCommand(ctx, "docker", "rm", "-f", s.containerID)
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
	cmd := execCommand(ctx, "docker", "image", "inspect", SandboxImage)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if cmd.Run() == nil {
		return nil // image exists
	}

	buildCmd := execCommand(ctx, "docker", "build", "-f", dockerfilePath, "-t", SandboxImage, ".")
	buildCmd.Stdout = io.Discard
	buildCmd.Stderr = io.Discard

	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("building sandbox image: %w", err)
	}

	return nil
}
