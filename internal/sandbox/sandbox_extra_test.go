package sandbox

import (
	"context"
	"strings"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

const (
	testMountPoint = "/home/dev/projects"
	envCmd         = "env"
	python3Bin     = "python3"
	nodeBin        = "node"
)

func TestNew(t *testing.T) {
	sb := New("/tmp/pkg", "testpkg", true, types.EcosystemPyPI, "")

	if sb.pkg != "testpkg" {
		t.Errorf("pkg = %q, want %q", sb.pkg, "testpkg")
	}
	if sb.packageDir != "/tmp/pkg" {
		t.Errorf("packageDir = %q, want %q", sb.packageDir, "/tmp/pkg")
	}
	if !sb.needsPtrace {
		t.Error("expected needsPtrace=true")
	}
	if sb.ecosystem != types.EcosystemPyPI {
		t.Errorf("ecosystem = %q, want %q", sb.ecosystem, types.EcosystemPyPI)
	}
	if sb.runtime != "" {
		t.Errorf("runtime = %q, want empty", sb.runtime)
	}
}

func TestNew_GVisor(t *testing.T) {
	sb := New("/tmp/pkg", "pkg", false, types.EcosystemNpm, RuntimeGVisor)

	if sb.runtime != RuntimeGVisor {
		t.Errorf("runtime = %q, want %q", sb.runtime, RuntimeGVisor)
	}
	if sb.needsPtrace {
		t.Error("expected needsPtrace=false")
	}
}

func TestInstallCommand_PyPI(t *testing.T) {
	sb := New("/mnt/packages", "requests", false, types.EcosystemPyPI, "")
	sb.mountPoint = testMountPoint

	cmd := sb.InstallCommand()
	if len(cmd) == 0 {
		t.Fatal("InstallCommand returned empty")
	}

	if cmd[0] != "pip" {
		t.Errorf("expected pip, got %s", cmd[0])
	}
	if cmd[1] != "install" {
		t.Errorf("expected install, got %s", cmd[1])
	}

	// Verify --no-index and --find-links are present.
	found := false
	for _, arg := range cmd {
		if arg == "--no-index" {
			found = true
		}
	}
	if !found {
		t.Error("expected --no-index in pip command")
	}

	// Last arg should be the package name.
	if cmd[len(cmd)-1] != "requests" {
		t.Errorf("expected package name at end, got %s", cmd[len(cmd)-1])
	}
}

func TestInstallCommand_Npm(t *testing.T) {
	sb := New("/mnt/packages", "lodash", false, types.EcosystemNpm, "")

	cmd := sb.InstallCommand()
	if len(cmd) == 0 {
		t.Fatal("InstallCommand returned empty")
	}

	if cmd[0] != "npm" {
		t.Errorf("expected npm, got %s", cmd[0])
	}
	if cmd[1] != "rebuild" {
		t.Errorf("expected rebuild, got %s", cmd[1])
	}
}

func TestImportCommands_PyPI(t *testing.T) {
	sb := New("/tmp/pkg", "requests", false, types.EcosystemPyPI, "")
	cmds := sb.ImportCommands()

	if len(cmds) != 3 {
		t.Fatalf("expected 3 import commands, got %d", len(cmds))
	}

	// Each should start with "env" (faketime wrapper).
	for i, cmd := range cmds {
		if cmd[0] != envCmd {
			t.Errorf("cmd[%d] should start with 'env', got %q", i, cmd[0])
		}
		// Should contain python3.
		hasPython := false
		for _, arg := range cmd {
			if arg == python3Bin {
				hasPython = true
			}
		}
		if !hasPython {
			t.Errorf("cmd[%d] should contain python3", i)
		}
	}
}

func TestImportCommands_Npm(t *testing.T) {
	sb := New("/tmp/pkg", "lodash", false, types.EcosystemNpm, "")
	cmds := sb.ImportCommands()

	if len(cmds) != 3 {
		t.Fatalf("expected 3 import commands, got %d", len(cmds))
	}

	for i, cmd := range cmds {
		if cmd[0] != envCmd {
			t.Errorf("cmd[%d] should start with 'env', got %q", i, cmd[0])
		}
		hasNode := false
		for _, arg := range cmd {
			if arg == nodeBin {
				hasNode = true
			}
		}
		if !hasNode {
			t.Errorf("cmd[%d] should contain node", i)
		}
	}
}

func TestContainerID(t *testing.T) {
	sb := New("/tmp/pkg", "test", false, types.EcosystemPyPI, "")
	sb.containerID = "abc123"

	if sb.ContainerID() != "abc123" {
		t.Errorf("ContainerID() = %q, want %q", sb.ContainerID(), "abc123")
	}
}

func TestGetHostHostname(t *testing.T) {
	h := getHostHostname()
	if h == "" {
		t.Error("getHostHostname returned empty string")
	}
}

func TestGetHostUsername(t *testing.T) {
	u := getHostUsername()
	if u == "" {
		t.Error("getHostUsername returned empty string")
	}
}

func TestGetHostResources(t *testing.T) {
	cpus, mem := getHostResources()

	if cpus == "" || cpus == "0" {
		t.Errorf("cpus = %q, expected positive value", cpus)
	}

	if mem == "" {
		t.Error("mem is empty")
	}
	// Memory should end with "m".
	if mem[len(mem)-1] != 'm' {
		t.Errorf("mem = %q, expected to end with 'm'", mem)
	}
}

func TestFaketimeEnv(t *testing.T) {
	env := faketimeEnv()
	if len(env) == 0 {
		t.Fatal("faketimeEnv returned empty")
	}

	hasPreload := false
	hasFaketime := false
	for _, e := range env {
		if strings.HasPrefix(e, "FAKETIME=+") && strings.HasSuffix(e, "d") {
			hasFaketime = true
		}
		if strings.HasPrefix(e, "LD_PRELOAD") {
			hasPreload = true
		}
	}

	if !hasPreload {
		t.Error("expected LD_PRELOAD in faketimeEnv")
	}
	if !hasFaketime {
		t.Error("expected FAKETIME=+Nd in faketimeEnv")
	}
}

func TestFaketimeShiftDays(t *testing.T) {
	for range 100 {
		d := faketimeShiftDays()
		if d < 30 || d > 180 {
			t.Errorf("faketimeShiftDays() = %d, want [30, 180]", d)
		}
	}
}

func TestWrapWithFaketime(t *testing.T) {
	cmd := []string{"python3", "/tmp/script.py"}
	wrapped := wrapWithFaketime(cmd)

	if wrapped[0] != envCmd {
		t.Errorf("expected first arg 'env', got %q", wrapped[0])
	}

	// Should end with original command.
	if wrapped[len(wrapped)-2] != "python3" {
		t.Errorf("expected python3 near end, got %q", wrapped[len(wrapped)-2])
	}
	if wrapped[len(wrapped)-1] != "/tmp/script.py" {
		t.Errorf("expected script path at end, got %q", wrapped[len(wrapped)-1])
	}
}

func TestRuntimeConstants(t *testing.T) {
	if RuntimeDefault != "" {
		t.Errorf("RuntimeDefault = %q, want empty", RuntimeDefault)
	}
	if RuntimeGVisor != "runsc" {
		t.Errorf("RuntimeGVisor = %q, want 'runsc'", RuntimeGVisor)
	}
}

func TestSandboxImage(t *testing.T) {
	if SandboxImage != "kojuto-sandbox:latest" {
		t.Errorf("SandboxImage = %q, want 'kojuto-sandbox:latest'", SandboxImage)
	}
}

func TestSandboxPythonVersion(t *testing.T) {
	if SandboxPythonVersion != "3.12" {
		t.Errorf("SandboxPythonVersion = %q, want '3.12'", SandboxPythonVersion)
	}
}

// ---------------------------------------------------------------------------
// SetLocalMode + InstallCommand
// ---------------------------------------------------------------------------

func TestSetLocalMode_InstallCommand(t *testing.T) {
	sb := New("/mnt/packages", "requests", false, types.EcosystemPyPI, "")
	sb.mountPoint = testMountPoint
	sb.SetLocalMode(true)

	cmd := sb.InstallCommand()
	if len(cmd) == 0 {
		t.Fatal("InstallCommand returned empty")
	}

	// Local mode uses "sh -c pip install ..."
	if cmd[0] != "sh" {
		t.Errorf("expected sh, got %s", cmd[0])
	}
	if cmd[1] != "-c" {
		t.Errorf("expected -c, got %s", cmd[1])
	}
	if !strings.Contains(cmd[2], "pip install") {
		t.Errorf("expected pip install in command, got %q", cmd[2])
	}
}

// ---------------------------------------------------------------------------
// InstallAllCommand
// ---------------------------------------------------------------------------

func TestInstallAllCommand_PyPI(t *testing.T) {
	sb := New("/mnt/packages", "requests", false, types.EcosystemPyPI, "")
	sb.mountPoint = testMountPoint

	pkgs := []string{"requests", "flask", "numpy"}
	cmd := sb.InstallAllCommand(pkgs)

	if len(cmd) == 0 {
		t.Fatal("InstallAllCommand returned empty")
	}
	if cmd[0] != "pip" {
		t.Errorf("expected pip, got %s", cmd[0])
	}
	if cmd[1] != "install" {
		t.Errorf("expected install, got %s", cmd[1])
	}
	// The last 3 args should be the package names.
	tail := cmd[len(cmd)-3:]
	for i, want := range pkgs {
		if tail[i] != want {
			t.Errorf("arg[%d] = %q, want %q", i, tail[i], want)
		}
	}
}

func TestInstallAllCommand_Npm(t *testing.T) {
	sb := New("/mnt/packages", "lodash", false, types.EcosystemNpm, "")

	pkgs := []string{"lodash", "express"}
	cmd := sb.InstallAllCommand(pkgs)

	if len(cmd) == 0 {
		t.Fatal("InstallAllCommand returned empty")
	}
	if cmd[0] != "npm" {
		t.Errorf("expected npm, got %s", cmd[0])
	}
	if cmd[1] != "rebuild" {
		t.Errorf("expected rebuild, got %s", cmd[1])
	}
	// Last 2 args should be package names.
	tail := cmd[len(cmd)-2:]
	for i, want := range pkgs {
		if tail[i] != want {
			t.Errorf("arg[%d] = %q, want %q", i, tail[i], want)
		}
	}
}

// ---------------------------------------------------------------------------
// WriteProbeScriptsMulti
// ---------------------------------------------------------------------------

func TestWriteProbeScriptsMulti_PyPI(t *testing.T) {
	withFakeExec(t)
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = fakeContainerID

	// Should not panic.
	sb.WriteProbeScriptsMulti(context.Background(), []string{"requests", "flask"})
}

func TestWriteProbeScriptsMulti_Npm(t *testing.T) {
	withFakeExec(t)
	sb := New(t.TempDir(), "lodash", false, types.EcosystemNpm, "")
	sb.containerID = fakeContainerID

	// Should not panic.
	sb.WriteProbeScriptsMulti(context.Background(), []string{"lodash", "express"})
}

// ---------------------------------------------------------------------------
// ImportCommandsMulti
// ---------------------------------------------------------------------------

func TestImportCommandsMulti_PyPI(t *testing.T) {
	sb := New("/tmp/pkg", "requests", false, types.EcosystemPyPI, "")
	pkgs := []string{"requests", "flask"}
	cmds := sb.ImportCommandsMulti(pkgs)

	if len(cmds) != 3 {
		t.Fatalf("expected 3 import commands, got %d", len(cmds))
	}

	for i, cmd := range cmds {
		if cmd[0] != envCmd {
			t.Errorf("cmd[%d] should start with 'env', got %q", i, cmd[0])
		}
		hasPython := false
		for _, arg := range cmd {
			if arg == python3Bin {
				hasPython = true
			}
		}
		if !hasPython {
			t.Errorf("cmd[%d] should contain python3", i)
		}
	}
}

func TestImportCommandsMulti_Npm(t *testing.T) {
	sb := New("/tmp/pkg", "lodash", false, types.EcosystemNpm, "")
	pkgs := []string{"lodash", "express"}
	cmds := sb.ImportCommandsMulti(pkgs)

	if len(cmds) != 3 {
		t.Fatalf("expected 3 import commands, got %d", len(cmds))
	}

	for i, cmd := range cmds {
		if cmd[0] != envCmd {
			t.Errorf("cmd[%d] should start with 'env', got %q", i, cmd[0])
		}
		hasNode := false
		for _, arg := range cmd {
			if arg == nodeBin {
				hasNode = true
			}
		}
		if !hasNode {
			t.Errorf("cmd[%d] should contain node", i)
		}
	}
}

func TestRandBase62(t *testing.T) {
	for _, n := range []int{1, 16, 36, 40} {
		s := randBase62(n)
		if len(s) != n {
			t.Errorf("randBase62(%d) returned len %d", n, len(s))
		}
		for _, c := range s {
			if !strings.ContainsRune(base62Chars, c) {
				t.Errorf("randBase62(%d) contains non-base62 char %q in %q", n, c, s)
			}
		}
	}
	a := randBase62(40)
	b := randBase62(40)
	if a == b {
		t.Error("randBase62 returned identical values on consecutive calls")
	}
}

func TestResolveRuntime_WithRunsc(t *testing.T) {
	withFakeExec(t)
	t.Setenv("FAKE_RUNSC", "1")

	rt := resolveRuntime()
	if rt != RuntimeGVisor {
		t.Errorf("resolveRuntime() = %q, want %q", rt, RuntimeGVisor)
	}
}

func TestResolveRuntime_WithoutRunsc(t *testing.T) {
	withFakeExec(t)
	t.Setenv("FAKE_RUNSC", "0")

	rt := resolveRuntime()
	if rt != RuntimeDefault {
		t.Errorf("resolveRuntime() = %q, want %q", rt, RuntimeDefault)
	}
}

func TestNew_Auto_ResolvesToDefault(t *testing.T) {
	withFakeExec(t)
	t.Setenv("FAKE_RUNSC", "0")

	sb := New("/tmp/pkg", "test", false, types.EcosystemPyPI, RuntimeAuto)
	if sb.runtime != RuntimeDefault {
		t.Errorf("runtime = %q, want %q (auto without runsc)", sb.runtime, RuntimeDefault)
	}
}

func TestNew_Auto_ResolvesToGVisor(t *testing.T) {
	withFakeExec(t)
	t.Setenv("FAKE_RUNSC", "1")

	sb := New("/tmp/pkg", "test", false, types.EcosystemPyPI, RuntimeAuto)
	if sb.runtime != RuntimeGVisor {
		t.Errorf("runtime = %q, want %q (auto with runsc)", sb.runtime, RuntimeGVisor)
	}
}

func TestFakeTokens_NotHexOnly(t *testing.T) {
	hasNonHex := false
	for range 10 {
		key := fakeAWSKeyID()[4:]
		for _, c := range key {
			if (c >= 'G' && c <= 'Z') || (c >= 'g' && c <= 'z') {
				hasNonHex = true
				break
			}
		}
		if hasNonHex {
			break
		}
	}
	if !hasNonHex {
		t.Error("10 consecutive fakeAWSKeyID tokens were all hex-only")
	}
}
