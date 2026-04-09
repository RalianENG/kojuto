package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

const fakeContainerID = "fake-id"

// fakeExecCommand returns an *exec.Cmd that re-invokes the test binary
// with TestHelperProcess as the entry point instead of calling Docker.
func fakeExecCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", name}
	cs = append(cs, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

// withFakeExec swaps execCommand for tests and restores on cleanup.
func withFakeExec(t *testing.T) {
	t.Helper()
	orig := execCommand
	execCommand = fakeExecCommand
	t.Cleanup(func() { execCommand = orig })
}

// TestHelperProcess is the fake subprocess spawned by fakeExecCommand.
// It inspects the arguments after "--" and prints appropriate output.
func TestHelperProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}

	if len(args) == 0 {
		return
	}

	// Only handle "docker" commands.
	if args[0] != "docker" {
		return
	}

	if len(args) < 2 {
		return
	}

	sub := args[1]

	switch sub {
	case "create":
		fmt.Print("fake-container-id-12345")
	case "inspect":
		fmt.Print("12345")
	case "logs":
		fmt.Print("fake log output")
	case "image":
		// "docker image inspect" — succeed (image exists).
	case "build":
		// succeed
	case "start", "pause", "unpause", "rm", "exec":
		// succeed silently
	case "network":
		// "docker network create" or "docker network rm" — succeed silently
	}
}

// newTestSandbox creates a sandbox with a real temp packageDir.
func newTestSandbox(t *testing.T, eco string) *Sandbox {
	t.Helper()
	dir := t.TempDir()
	return New(dir, "testpkg", true, eco, "")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestWriteSeccompProfile(t *testing.T) {
	sb := newTestSandbox(t, types.EcosystemPyPI)

	opt, err := sb.writeSeccompProfile()
	if err != nil {
		t.Fatalf("writeSeccompProfile: %v", err)
	}

	if !strings.HasPrefix(opt, "seccomp=") {
		t.Errorf("expected seccomp= prefix, got %q", opt)
	}

	path := strings.TrimPrefix(opt, "seccomp=")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading seccomp file: %v", err)
	}

	// Must be valid JSON.
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("seccomp profile is not valid JSON: %v", err)
	}

	// Cleanup.
	if sb.seccompDir != "" {
		os.RemoveAll(sb.seccompDir)
	}
}

func TestContainerArgs(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.networkName = "test-net"

	args, err := sb.containerArgs()
	if err != nil {
		t.Fatalf("containerArgs: %v", err)
	}

	if len(args) == 0 {
		t.Fatal("containerArgs returned empty slice")
	}

	// Check key flags are present.
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--network=test-net",
		"--read-only",
		"--cap-drop=ALL",
		"--cap-add=SYS_PTRACE", // needsPtrace=true
		SandboxImage,
		"sleep",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("containerArgs missing %q in:\n%s", want, joined)
		}
	}

	// Cleanup seccomp temp dir.
	if sb.seccompDir != "" {
		os.RemoveAll(sb.seccompDir)
	}
}

func TestContainerArgs_NoPtrace(t *testing.T) {
	withFakeExec(t)
	sb := New(t.TempDir(), "pkg", false, types.EcosystemPyPI, "")
	sb.networkName = "net"

	args, err := sb.containerArgs()
	if err != nil {
		t.Fatalf("containerArgs: %v", err)
	}

	joined := strings.Join(args, " ")
	if strings.Contains(joined, "SYS_PTRACE") {
		t.Error("SYS_PTRACE should not be present when needsPtrace=false")
	}

	if sb.seccompDir != "" {
		os.RemoveAll(sb.seccompDir)
	}
}

func TestContainerArgs_GVisor(t *testing.T) {
	withFakeExec(t)
	sb := New(t.TempDir(), "pkg", false, types.EcosystemPyPI, RuntimeGVisor)
	sb.networkName = "net"

	args, err := sb.containerArgs()
	if err != nil {
		t.Fatalf("containerArgs: %v", err)
	}

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--runtime=runsc") {
		t.Error("expected --runtime=runsc for gVisor runtime")
	}

	if sb.seccompDir != "" {
		os.RemoveAll(sb.seccompDir)
	}
}

func TestCreateIsolatedNetwork(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)

	err := sb.createIsolatedNetwork(context.Background())
	if err != nil {
		t.Fatalf("createIsolatedNetwork: %v", err)
	}

	// --network=none: complete network isolation, no Docker bridge network.
	if sb.networkName != networkNone {
		t.Errorf("networkName = %q, expected %q (--network=none)", sb.networkName, networkNone)
	}
}

func TestRemoveIsolatedNetwork(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.networkName = "kojuto-jail-test"

	// Should not panic or error.
	sb.removeIsolatedNetwork(context.Background())
}

func TestRemoveIsolatedNetwork_None(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.networkName = networkNone

	// Should return early without calling docker.
	sb.removeIsolatedNetwork(context.Background())
}

func TestRemoveIsolatedNetwork_Empty(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.networkName = ""

	sb.removeIsolatedNetwork(context.Background())
}

func TestCreate(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)

	err := sb.Create(context.Background())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if sb.containerID == "" {
		t.Error("containerID should be set after Create")
	}

	if sb.containerID != "fake-container-id-12345" {
		t.Errorf("containerID = %q, want %q", sb.containerID, "fake-container-id-12345")
	}

	// Cleanup seccomp dir.
	if sb.seccompDir != "" {
		os.RemoveAll(sb.seccompDir)
	}
}

func TestStartPaused(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID
	sb.networkName = "test-net"

	err := sb.StartPaused(context.Background())
	if err != nil {
		t.Fatalf("StartPaused: %v", err)
	}
}

func TestStart(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)

	err := sb.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if sb.containerID == "" {
		t.Error("containerID should be set after Start")
	}

	if sb.seccompDir != "" {
		os.RemoveAll(sb.seccompDir)
	}
}

func TestDockerExecRoot(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID

	// Should not panic or error (errors are silently discarded).
	sb.dockerExecRoot(context.Background(), "ls", "-la")
}

func TestExec(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID

	out, err := sb.Exec(context.Background(), []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}

	// Output may be empty since the helper process just succeeds for exec.
	_ = out
}

func TestInstallPackage(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID
	sb.mountPoint = testMountPoint

	_, err := sb.InstallPackage(context.Background())
	if err != nil {
		t.Fatalf("InstallPackage: %v", err)
	}
}

func TestInstallPackage_Npm(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemNpm)
	sb.containerID = fakeContainerID
	sb.mountPoint = testMountPoint

	_, err := sb.InstallPackage(context.Background())
	if err != nil {
		t.Fatalf("InstallPackage (npm): %v", err)
	}
}

func TestWriteProbeScripts(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID

	// Should not panic.
	sb.WriteProbeScripts(context.Background())
}

func TestWriteProbeScripts_Npm(t *testing.T) {
	withFakeExec(t)
	sb := New(t.TempDir(), "lodash", false, types.EcosystemNpm, "")
	sb.containerID = fakeContainerID

	sb.WriteProbeScripts(context.Background())
}

func TestPID(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID

	pid, err := sb.PID(context.Background())
	if err != nil {
		t.Fatalf("PID: %v", err)
	}

	if pid != 12345 {
		t.Errorf("PID = %d, want 12345", pid)
	}
}

func TestLogs(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID

	out, err := sb.Logs(context.Background())
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}

	if !strings.Contains(out, "fake log output") {
		t.Errorf("Logs = %q, want it to contain %q", out, "fake log output")
	}
}

func TestPause(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID

	if err := sb.Pause(context.Background()); err != nil {
		t.Fatalf("Pause: %v", err)
	}
}

func TestUnpause(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID

	if err := sb.Unpause(context.Background()); err != nil {
		t.Fatalf("Unpause: %v", err)
	}
}

func TestCleanup(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID
	sb.networkName = "kojuto-jail-test"

	// Create a seccomp temp dir to verify cleanup removes it.
	dir := t.TempDir()
	sb.seccompDir = dir

	if err := sb.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if sb.seccompDir != "" {
		t.Error("seccompDir should be cleared after Cleanup")
	}
}

func TestCleanup_NoSeccomp(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID
	sb.networkName = networkNone

	if err := sb.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

func TestEnsureImage_Exists(t *testing.T) {
	withFakeExec(t)

	// The helper process succeeds for "docker image inspect", so image "exists".
	err := EnsureImage(context.Background(), "Dockerfile.sandbox")
	if err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
}

func TestEraseFingerprints(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID

	// Should not panic.
	sb.eraseFingerprints(context.Background())
}

func TestPlantHoneypotFiles(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID

	// Should not panic.
	sb.plantHoneypotFiles(context.Background())
}

func TestRestoreLocalBin_PyPI(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID
	sb.mountPoint = testMountPoint

	sb.restoreLocalBin(context.Background())
}

func TestRestoreLocalBin_Npm(t *testing.T) {
	withFakeExec(t)
	sb := New(t.TempDir(), "lodash", false, types.EcosystemNpm, "")
	sb.containerID = fakeContainerID
	sb.mountPoint = testMountPoint

	// For npm, restoreLocalBin also copies node_modules.
	sb.restoreLocalBin(context.Background())
}

func TestStart_Npm(t *testing.T) {
	withFakeExec(t)
	sb := New(t.TempDir(), "lodash", false, types.EcosystemNpm, "")

	err := sb.Start(context.Background())
	if err != nil {
		t.Fatalf("Start (npm): %v", err)
	}

	if sb.seccompDir != "" {
		os.RemoveAll(sb.seccompDir)
	}
}
