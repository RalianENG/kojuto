package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestNewDownloadSandbox(t *testing.T) {
	d := NewDownloadSandbox("/host/staging")
	if d.hostOutDir != "/host/staging" {
		t.Errorf("hostOutDir = %q, want %q", d.hostOutDir, "/host/staging")
	}
	if d.containerID != "" {
		t.Errorf("containerID = %q, want empty before Start", d.containerID)
	}
	if d.ContainerID() != "" {
		t.Errorf("ContainerID() = %q, want empty before Start", d.ContainerID())
	}
}

func TestDownloadSandbox_CreateArgs(t *testing.T) {
	d := NewDownloadSandbox("/host/staging")
	args := d.createArgs("seccomp=/tmp/seccomp.json")
	joined := strings.Join(args, " ")

	// Every isolation control shared with the analysis sandbox must be present.
	for _, want := range []string{
		"create",
		"--label=" + SandboxContainerLabel + "=true",
		"--security-opt=no-new-privileges",
		"--security-opt=seccomp=/tmp/seccomp.json",
		"--read-only",
		"--cap-drop=ALL",
		"--pids-limit=256",
		"--tmpfs=/var/cache/kojuto:",
		"--env=NPM_CONFIG_CACHE=/var/cache/kojuto/npm",
		"--env=PIP_CACHE_DIR=/var/cache/kojuto/pip",
		"/host/staging:" + DownloadOutMountPath,
		SandboxImage,
		"sleep",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("createArgs missing %q in:\n%s", want, joined)
		}
	}

	// The deliberate difference from the analysis sandbox: the download
	// container keeps network egress so pip/npm can reach the registry.
	if strings.Contains(joined, "--network=none") {
		t.Errorf("download sandbox must not be network-isolated; got:\n%s", joined)
	}
}

func TestDownloadSandbox_Start(t *testing.T) {
	withFakeExec(t)
	d := NewDownloadSandbox(t.TempDir())

	if err := d.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if d.containerID == "" {
		t.Error("containerID should be set after Start")
	}
	if d.seccompDir == "" {
		t.Error("seccompDir should be set after Start")
	}

	if d.seccompDir != "" {
		os.RemoveAll(d.seccompDir)
	}
}

func TestDownloadSandbox_Run_NotStarted(t *testing.T) {
	d := NewDownloadSandbox(t.TempDir())
	_, err := d.Run(context.Background(), []string{"pip", "download", "requests"})
	if err == nil {
		t.Error("expected error running on a sandbox that was never started, got nil")
	}
}

func TestDownloadSandbox_Run(t *testing.T) {
	withFakeExec(t)
	d := NewDownloadSandbox(t.TempDir())
	d.containerID = fakeContainerID

	if _, err := d.Run(context.Background(), []string{"npm", "install", "--ignore-scripts"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestDownloadSandbox_ContainerID(t *testing.T) {
	d := NewDownloadSandbox(t.TempDir())
	d.containerID = fakeContainerID
	if d.ContainerID() != fakeContainerID {
		t.Errorf("ContainerID() = %q, want %q", d.ContainerID(), fakeContainerID)
	}
}

func TestDownloadSandbox_Cleanup(t *testing.T) {
	withFakeExec(t)
	d := NewDownloadSandbox(t.TempDir())
	d.containerID = fakeContainerID
	d.seccompDir = t.TempDir()

	if err := d.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if d.containerID != "" {
		t.Error("containerID should be cleared after Cleanup")
	}
	if d.seccompDir != "" {
		t.Error("seccompDir should be cleared after Cleanup")
	}
}

func TestDownloadSandbox_Cleanup_Partial(t *testing.T) {
	withFakeExec(t)
	// Never started: no containerID, no seccompDir. Cleanup must be a no-op
	// rather than erroring.
	d := NewDownloadSandbox(t.TempDir())
	if err := d.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup on un-started sandbox: %v", err)
	}
}
