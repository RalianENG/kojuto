package probe

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

// Test-local constants to satisfy goconst — the strings appear repeatedly
// across the download-probe tests only.
const (
	downloadTestMethod      = "strace-container"
	downloadTestContainerID = "abc123"
	downloadTestStraceArg   = "strace"
	downloadTestExecArg     = "exec"
)

func TestNewContainerStraceForDownload(t *testing.T) {
	cs := NewContainerStraceForDownload("/out")
	if cs.phase != types.PhaseDownload {
		t.Errorf("phase = %q, want %q", cs.phase, types.PhaseDownload)
	}
	if cs.workdir != "/out" {
		t.Errorf("workdir = %q, want %q", cs.workdir, "/out")
	}
	// Still the same probe method — the analyzer, not the probe name,
	// branches on the download phase.
	if cs.Method() != downloadTestMethod {
		t.Errorf("Method() = %q, want %q", cs.Method(), downloadTestMethod)
	}
}

// TestBuildCommand_DownloadWorkdir pins that the download probe runs the
// traced command with --workdir set, so `npm install` finds the staging
// package.json bind-mounted at /out.
func TestBuildCommand_DownloadWorkdir(t *testing.T) {
	cs := NewContainerStraceForDownload("/out")
	cmd := cs.buildCommand(context.Background(), downloadTestContainerID, []string{"npm", "install", "--ignore-scripts"})
	args := cmd.Args

	if args[1] != downloadTestExecArg {
		t.Fatalf("args[1] = %q, want %q", args[1], downloadTestExecArg)
	}
	if args[2] != "--workdir=/out" {
		t.Errorf("args[2] = %q, want %q", args[2], "--workdir=/out")
	}
	if args[3] != downloadTestContainerID {
		t.Errorf("args[3] = %q, want the container ID %q", args[3], downloadTestContainerID)
	}
	if args[4] != downloadTestStraceArg {
		t.Errorf("args[4] = %q, want %q", args[4], downloadTestStraceArg)
	}

	// The traced command still lands after the "--" separator.
	idx := slices.Index(args, "--")
	if idx < 0 || !slices.Equal(args[idx+1:], []string{"npm", "install", "--ignore-scripts"}) {
		t.Errorf("traced command after -- = %v, want [npm install --ignore-scripts]", args[idx+1:])
	}
}

// TestBuildCommand_NoWorkdirByDefault — the install/import probes leave the
// working directory at the container default; no --workdir is injected.
func TestBuildCommand_NoWorkdirByDefault(t *testing.T) {
	cs := NewContainerStrace()
	cmd := cs.buildCommand(context.Background(), "abc123", []string{"pip", "install", "requests"})
	for _, a := range cmd.Args {
		if strings.HasPrefix(a, "--workdir") {
			t.Errorf("unexpected --workdir in install/import probe args: %v", cmd.Args)
		}
	}
	// exec is immediately followed by the container ID.
	if cmd.Args[2] != "abc123" {
		t.Errorf("args[2] = %q, want the container ID %q", cmd.Args[2], "abc123")
	}
}

// TestParseStraceOutput_DownloadStampsPhase pins that a download probe stamps
// every emitted event with types.PhaseDownload so the analyzer routes it
// through the download-phase profile.
func TestParseStraceOutput_DownloadStampsPhase(t *testing.T) {
	straceLines := strings.Join([]string{
		`[pid 100] connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("151.101.0.223")}, 16) = 0`,
		`[pid 101] execve("/out/node_modules/evil/payload", ["payload"], ...) = 0`,
	}, "\n")

	cs := NewContainerStraceForDownload("/out")
	reader := io.NopCloser(strings.NewReader(straceLines))
	parseDone := make(chan struct{})
	go cs.parseStraceOutput(reader, parseDone)
	<-parseDone

	close(cs.events)
	var events []types.SyscallEvent
	for evt := range cs.events {
		events = append(events, evt)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	for i, evt := range events {
		if evt.Phase != types.PhaseDownload {
			t.Errorf("event[%d].Phase = %q, want %q", i, evt.Phase, types.PhaseDownload)
		}
	}
}

// TestParseStraceOutput_InstallLeavesPhaseUnset — the default probe must not
// stamp a phase; install/import events flow through the normal analyzer path.
func TestParseStraceOutput_InstallLeavesPhaseUnset(t *testing.T) {
	line := `[pid 100] connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0`

	cs := NewContainerStrace()
	reader := io.NopCloser(strings.NewReader(line))
	parseDone := make(chan struct{})
	go cs.parseStraceOutput(reader, parseDone)
	<-parseDone

	close(cs.events)
	for evt := range cs.events {
		if evt.Phase != "" {
			t.Errorf("install-probe event Phase = %q, want empty", evt.Phase)
		}
	}
}
