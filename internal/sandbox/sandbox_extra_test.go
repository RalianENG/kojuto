package sandbox

import (
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

const (
	testMountPoint = "/home/dev/projects"
	envCmd         = "env"
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
			if arg == "python3" {
				hasPython = true
			}
		}
		if !hasPython {
			t.Errorf("cmd[%d] should contain 'python3'", i)
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
			if arg == "node" {
				hasNode = true
			}
		}
		if !hasNode {
			t.Errorf("cmd[%d] should contain 'node'", i)
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
		if e == "FAKETIME=+30d" {
			hasFaketime = true
		}
		if len(e) > 10 && e[:10] == "LD_PRELOAD" {
			hasPreload = true
		}
	}

	if !hasPreload {
		t.Error("expected LD_PRELOAD in faketimeEnv")
	}
	if !hasFaketime {
		t.Error("expected FAKETIME=+30d in faketimeEnv")
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
