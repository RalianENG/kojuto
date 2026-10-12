package analyzer

import (
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

// pipShim is the shape of pip's setuptools shim as strace records it.
const pipShim = "/usr/local/bin/python3.12 -c \nexec(compile('''\n# This is <pip-setuptools-caller> -- a caller that pip uses to run setup.py"

func installClone(parent, child uint32) types.SyscallEvent {
	return types.SyscallEvent{Phase: types.PhaseInstall, Syscall: types.EventClone, PID: parent, ChildPID: child}
}

func installExec(pid uint32, comm, cmdline string) types.SyscallEvent {
	return types.SyscallEvent{Phase: types.PhaseInstall, Syscall: types.EventExecve, PID: pid, Comm: comm, Cmdline: cmdline}
}

// pipTree is kojuto's install script (root, PID 0 then its real PID 10)
// running pip (11), which vforks its setuptools shim (12). As strace prints
// it, the vfork child's exec comes BEFORE the parent's "vfork resumed" line
// that carries the child PID.
func pipTree() []types.SyscallEvent {
	return []types.SyscallEvent{
		installExec(0, "/usr/bin/sh", "sh /var/cache/q1w2e3r4t5/a8s7d6f5.sh"),
		installClone(10, 11),
		installExec(11, "/usr/local/bin/python3.12", "/usr/local/bin/python3.12 /usr/local/bin/pip install --no-index /home/u/projects/x.tar.gz"),
		installExec(12, "/usr/local/bin/python3.12", pipShim),
		installClone(11, 12),
	}
}

func codeExecutionCount(events []types.SyscallEvent) int {
	_, flagged := Analyze(events)
	n := 0
	for _, e := range flagged {
		if e.Category == types.CategoryCodeExecution {
			n++
		}
	}
	return n
}

// TestPackageManagerShimIsNotCodeInjection: pip's own shim, started by pip
// as its first exec at depth 2, is not reported — even though strace prints
// the child's exec before the vfork that names its parent.
func TestPackageManagerShimIsNotCodeInjection(t *testing.T) {
	if n := codeExecutionCount(pipTree()); n != 0 {
		t.Errorf("pip's setuptools shim reported as code_execution (%d events)", n)
	}
}

// TestPackageCodeStillCaughtAroundTheShim pins every way the package itself
// could try to inherit the exemption.
func TestPackageCodeStillCaughtAroundTheShim(t *testing.T) {
	payload := "/usr/local/bin/python3.12 -c import socket;socket.create_connection(('203.0.113.9',443))"
	cases := map[string][]types.SyscallEvent{
		// setup.py replaces the shim process with its own -c: same PID,
		// second exec.
		"re-exec in the shim's PID": append(pipTree(),
			installExec(12, "/usr/local/bin/python3.12", payload)),
		// setup.py spawns a child: depth 3.
		"child of setup.py": append(pipTree(),
			installClone(12, 13),
			installExec(13, "/usr/local/bin/python3.12", payload)),
		// Same tree shape, but in the import phase, whose root is the
		// probe script the package's code runs inside.
		"import phase": {
			{Syscall: types.EventClone, PID: 20, ChildPID: 21},
			{Syscall: types.EventClone, PID: 21, ChildPID: 22},
			{Syscall: types.EventExecve, PID: 22, Comm: "/usr/local/bin/python3.12", Cmdline: payload},
		},
	}
	for name, events := range cases {
		if n := codeExecutionCount(events); n == 0 {
			t.Errorf("%s: inline payload not reported", name)
		}
	}
}

// TestDownloadPhaseDoesNotFeedInstallLineage: the download sandbox is
// another container, so its PIDs must not build the install-phase tree.
func TestDownloadPhaseDoesNotFeedInstallLineage(t *testing.T) {
	events := []types.SyscallEvent{
		{Phase: types.PhaseDownload, Syscall: types.EventClone, PID: 30, ChildPID: 31},
		{Phase: types.PhaseDownload, Syscall: types.EventClone, PID: 31, ChildPID: 32},
		installExec(32, "/usr/local/bin/python3.12", pipShim),
	}
	if n := codeExecutionCount(events); n == 0 {
		t.Error("a download-phase lineage exempted an install-phase inline exec")
	}
}

// TestOnlyTheInlineRuleIsWaived: a depth-2 first exec that trips another
// execve rule (execution from a staging directory) is still reported.
func TestOnlyTheInlineRuleIsWaived(t *testing.T) {
	events := pipTree()
	events[3] = installExec(12, "/tmp/payload", "/tmp/payload")
	if n := codeExecutionCount(events); n == 0 {
		t.Error("execution from /tmp at depth 2 was exempted along with the inline rule")
	}
}

func TestCollectPackageManagerSpawns(t *testing.T) {
	marked := collectPackageManagerSpawns(pipTree())
	if !marked[3] || len(marked) != 1 {
		t.Errorf("marked = %v, want only the shim exec (index 3)", marked)
	}
}
