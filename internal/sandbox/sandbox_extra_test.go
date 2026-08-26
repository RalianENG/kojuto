package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

const (
	testMountPoint  = "/home/dev/projects"
	envCmd          = "env"
	python3Bin      = "python3"
	nodeBin         = "node"
	testContainerID = "test-container"
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

	cmd, err := sb.InstallCommand(context.Background())
	if err != nil {
		t.Fatalf("InstallCommand: %v", err)
	}
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
	// npm install stages its script to /var/cache/kojuto/install.sh via
	// dockerWriteFile, so execCommand needs to be intercepted. The script
	// itself is exercised directly via TestNpmLifecycleScript_*.
	var stagedScript string
	orig := execCommand
	execCommand = func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		// dockerWriteFile pipes the script via stdin to `sh -c "cat > path"`.
		// Capture the stdin reader by wrapping the returned cmd.
		c := exec.CommandContext(ctx, "true")
		// args carries: exec -i --user=root <id> sh -c "cat > path"
		_ = args
		return c
	}
	t.Cleanup(func() { execCommand = orig })

	sb := New("/mnt/packages", "lodash", false, types.EcosystemNpm, "")
	sb.containerID = testContainerID
	cmd, err := sb.InstallCommand(context.Background())
	if err != nil {
		t.Fatalf("InstallCommand: %v", err)
	}
	if len(cmd) != 2 || cmd[0] != "sh" || cmd[1] != installScriptPath {
		t.Fatalf("InstallCommand = %v, want [sh %s] (file-based to avoid sh -c FP)", cmd, installScriptPath)
	}

	// Script content is exercised directly: lifecycle hooks must fire.
	// `npm rebuild` (the previous approach) skipped preinstall and
	// postinstall, which is precisely where most npm supply chain
	// payloads live.
	script := npmLifecycleScript(nil)
	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		if !strings.Contains(script, hook) {
			t.Errorf("script missing %q hook invocation:\n%s", hook, script)
		}
	}
	// No-pkg form must walk node_modules to fire every top-level dep.
	if !strings.Contains(script, "/install/node_modules") {
		t.Errorf("script must reference /install/node_modules, got:\n%s", script)
	}
	_ = stagedScript // reserved for future capture-based assertions
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

// TestGetHostUsername_Sanitizes pins that an exotic USER value (shell
// metacharacters, path separators, non-ASCII) is normalised before it
// flows into mountPoint and from there into -v volume specs and shell
// command lines.
func TestGetHostUsername_Sanitizes(t *testing.T) {
	cases := []struct {
		userEnv, want string
	}{
		{"alice", "alice"},
		{"a;rm -rf /", "arm-rf"},
		{"$(id)", "id"},
		{"a:b", "ab"},
		{"a/b", "ab"},
		{"日本語", "user"},
	}

	for _, tc := range cases {
		t.Setenv("USER", tc.userEnv)
		t.Setenv("USERNAME", "")
		t.Setenv("LOGNAME", "")
		if got := getHostUsername(); got != tc.want {
			t.Errorf("USER=%q: getHostUsername() = %q, want %q", tc.userEnv, got, tc.want)
		}
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
	// Local-mode pip uses the staged-script path for the same reason as
	// npm — keep the outer shell out of analyzer's sh -c branch.
	orig := execCommand
	execCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCommand = orig })

	sb := New("/mnt/packages", "requests", false, types.EcosystemPyPI, "")
	sb.mountPoint = testMountPoint
	sb.SetLocalMode(true)
	sb.containerID = testContainerID

	cmd, err := sb.InstallCommand(context.Background())
	if err != nil {
		t.Fatalf("InstallCommand: %v", err)
	}
	if len(cmd) != 2 || cmd[0] != "sh" || cmd[1] != installScriptPath {
		t.Fatalf("InstallCommand = %v, want [sh %s]", cmd, installScriptPath)
	}
}

// ---------------------------------------------------------------------------
// InstallAllCommand
// ---------------------------------------------------------------------------

func TestInstallAllCommand_PyPI(t *testing.T) {
	sb := New("/mnt/packages", "requests", false, types.EcosystemPyPI, "")
	sb.mountPoint = testMountPoint

	pkgs := []string{"requests", "flask", "numpy"}
	cmd, err := sb.InstallAllCommand(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("InstallAllCommand: %v", err)
	}

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
	orig := execCommand
	execCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCommand = orig })

	sb := New("/mnt/packages", "lodash", false, types.EcosystemNpm, "")
	sb.containerID = testContainerID

	pkgs := []string{"lodash", "express"}
	cmd, err := sb.InstallAllCommand(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("InstallAllCommand: %v", err)
	}
	if len(cmd) != 2 || cmd[0] != "sh" || cmd[1] != installScriptPath {
		t.Fatalf("InstallAllCommand = %v, want [sh %s]", cmd, installScriptPath)
	}

	// Script content is exercised directly.
	script := npmLifecycleScript(pkgs)
	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		if !strings.Contains(script, hook) {
			t.Errorf("script missing %q hook invocation:\n%s", hook, script)
		}
	}
	for _, p := range pkgs {
		want := "/install/node_modules/" + p
		if !strings.Contains(script, want) {
			t.Errorf("script missing path %q:\n%s", want, script)
		}
	}
}

func TestNpmLifecycleScript_ScopedPackage(t *testing.T) {
	// Scoped packages live at /install/node_modules/@scope/name; the
	// script must quote the path so the @ character does not break the
	// shell command. Regression guard for a bug that would have hidden
	// scoped-dep lifecycle behavior from strace.
	got := npmLifecycleScript([]string{"@scope/lib"})
	want := `'/install/node_modules/@scope/lib'`
	if !strings.Contains(got, want) {
		t.Errorf("scoped path missing %q in:\n%s", want, got)
	}
}

func TestShQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"foo", "'foo'"},
		{"a b", "'a b'"},
		{"@scope/pkg", "'@scope/pkg'"},
		{"$(id)", "'$(id)'"},
		{"`id`", "'`id`'"},
		{"a'b", `'a'\''b'`},
		{"", "''"},
	}
	for _, tc := range cases {
		if got := shQuote(tc.in); got != tc.want {
			t.Errorf("shQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNpmLifecycleScript_ParallelDispatch pins the xargs -P invocation
// structure for both the discovery (nil pkgs) and named-pkgs paths.
// Sequential `;`-joined subshells previously dominated batch scan wall
// time on npm CLI startup overhead (~1s per `npm run --silent
// --if-present` no-op × 300 invocations across 100 packages). xargs
// -P bounds peak concurrency at npmLifecycleParallelism so the
// container's --pids-limit and memory ceiling are respected while
// hooks run in parallel.
func TestNpmLifecycleScript_ParallelDispatch(t *testing.T) {
	// Discovery path: find -print0 piped to xargs -0 -P N. -print0
	// + -0 avoids the dash-incompatible `read -d ""` form the old
	// loop went out of its way to skirt around.
	discovery := npmLifecycleScript(nil)
	for _, want := range []string{
		"find /install/node_modules",
		"-print0",
		"| xargs -0 -P 4 -I{}",
		`sh -c 'd=$(dirname "{}") && cd "$d" && `,
	} {
		if !strings.Contains(discovery, want) {
			t.Errorf("discovery script missing %q in:\n%s", want, discovery)
		}
	}
	// The old sequential `while IFS= read -r pj` shape must NOT reappear.
	if strings.Contains(discovery, "while IFS=") {
		t.Errorf("discovery script regressed to sequential while-read loop:\n%s", discovery)
	}

	// Named-pkgs path: printf '%s\n' ... | xargs -P N -I{} sh -c ...
	named := npmLifecycleScript([]string{"lodash", "express"})
	for _, want := range []string{
		`printf '%s\n'`,
		"'/install/node_modules/lodash'",
		"'/install/node_modules/express'",
		"| xargs -P 4 -I{}",
		`sh -c 'cd "{}" && `,
	} {
		if !strings.Contains(named, want) {
			t.Errorf("named script missing %q in:\n%s", want, named)
		}
	}
	// The old sequential `(cd ... && hooks) 2>&1; (cd ... &&` chain
	// must not reappear — that form was the dominant wall-time cost.
	if strings.Contains(named, "&& "+`npm run --silent --if-present preinstall; npm run --silent --if-present install; npm run --silent --if-present postinstall) 2>&1; (cd `) {
		t.Errorf("named script regressed to sequential subshell chain:\n%s", named)
	}
}

func TestNpmLifecycleScript_QuotesShellMetachars(t *testing.T) {
	// Defense-in-depth: even if a malformed name slips past the depfile
	// validator, the cd target must be safely single-quoted so shell
	// metacharacters cannot break out and execute on the sandbox shell.
	got := npmLifecycleScript([]string{`foo$(id)`})
	if !strings.Contains(got, `'/install/node_modules/foo$(id)'`) {
		t.Errorf("metachar payload not single-quoted in:\n%s", got)
	}
	// The bare token must NOT appear unquoted between cd and &&.
	if strings.Contains(got, `cd /install/node_modules/foo$(id) `) {
		t.Errorf("metachar payload unquoted in:\n%s", got)
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

// TestCleanupStaleSandboxContainers_Empty documents the no-op path:
// when no labeled containers exist in any non-running state, the
// function returns (0, nil) without invoking `docker rm`.
func TestCleanupStaleSandboxContainers_Empty(t *testing.T) {
	var calls [][]string
	orig := execCommand
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls = append(calls, append([]string{name}, args...))
		// `docker ps -aq --filter ...` returns empty output -> no
		// stale containers; this is the no-op path.
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCommand = orig })

	n, err := CleanupStaleSandboxContainers(context.Background())
	if err != nil {
		t.Fatalf("CleanupStaleSandboxContainers: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 removed containers, got %d", n)
	}
	// One `docker ps -aq --filter` invocation per status (exited,
	// created, dead) — three total. No `docker rm` because nothing
	// to remove.
	if len(calls) != 3 {
		t.Fatalf("expected 3 docker ps calls, got %d: %v", len(calls), calls)
	}
	for _, args := range calls {
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "ps -aq") ||
			!strings.Contains(joined, "label="+SandboxContainerLabel) {
			t.Errorf("unexpected docker call args: %v", args)
		}
	}
}

// TestCleanupStaleSandboxContainers_FiltersByLabel pins the exact
// filter combination used to find orphans: --filter
// label=kojuto.scan ANDed with --filter status=<X> for each
// non-running state. The status enumeration is required because
// Docker filters compose with AND, not OR.
func TestCleanupStaleSandboxContainers_FiltersByLabel(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()

	seenStatuses := map[string]bool{}
	execCommand = func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		for i, a := range args {
			if a == "--filter" && i+1 < len(args) && strings.HasPrefix(args[i+1], "status=") {
				seenStatuses[strings.TrimPrefix(args[i+1], "status=")] = true
			}
		}
		return exec.CommandContext(ctx, "true")
	}

	if _, err := CleanupStaleSandboxContainers(context.Background()); err != nil {
		t.Fatalf("CleanupStaleSandboxContainers: %v", err)
	}

	// Every non-running, non-paused state Docker can report must be
	// queried — leaving any out would leak that class of orphan.
	for _, want := range []string{"exited", "created", "dead"} {
		if !seenStatuses[want] {
			t.Errorf("status=%q filter not used; seen=%v", want, seenStatuses)
		}
	}
	// Running and paused MUST NOT be queried — those belong to live
	// concurrent kojuto runs and must be left alone.
	for _, forbidden := range []string{"running", "paused", "restarting"} {
		if seenStatuses[forbidden] {
			t.Errorf("status=%q filter must NOT be used (would disturb live scans)", forbidden)
		}
	}
}

// TestCleanupStaleSandboxContainers_RemovesIDs pins the contract that
// container IDs returned by `docker ps` are passed to `docker rm -f`
// in a single batch call.
//
// The fake `docker ps` reads its output from a temp file rather than
// from a shell-dependent `printf`/`echo` invocation — Windows host
// printf does not interpret `\n` in format strings the same way
// POSIX printf does, so a literal newline in the file is the only
// portable way to seed multi-line stdout from a fake exec command.
func TestCleanupStaleSandboxContainers_RemovesIDs(t *testing.T) {
	idsFile := filepath.Join(t.TempDir(), "ids.txt")
	if err := os.WriteFile(idsFile, []byte("abc123\ndef456\n"), 0o600); err != nil {
		t.Fatalf("seeding ids file: %v", err)
	}

	var rmArgs []string
	orig := execCommand
	execCommand = func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "ps" {
			// Each of the 3 status filters returns the same two IDs
			// for a total of 6.
			return exec.CommandContext(ctx, "cat", idsFile)
		}
		if len(args) > 0 && args[0] == "rm" {
			rmArgs = append([]string{}, args...)
		}
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCommand = orig })

	n, err := CleanupStaleSandboxContainers(context.Background())
	if err != nil {
		t.Fatalf("CleanupStaleSandboxContainers: %v", err)
	}
	// 3 statuses × 2 IDs each = 6 IDs.
	if n != 6 {
		t.Errorf("removed count = %d, want 6", n)
	}
	if len(rmArgs) == 0 {
		t.Fatal("docker rm was never called")
	}
	if rmArgs[0] != "rm" || rmArgs[1] != "-f" {
		t.Errorf("expected `docker rm -f <ids>`, got args=%v", rmArgs)
	}
	// All collected IDs should be passed in a single rm call.
	for _, id := range []string{"abc123", "def456"} {
		found := false
		for _, a := range rmArgs[2:] {
			if a == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected id %q in rm args, got %v", id, rmArgs)
		}
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

// TestDockerWriteFile_StructureNoHeredoc pins the security invariant that
// dockerWriteFile delivers content via stdin (`docker exec -i`) instead of
// the previous `cat << 'KOJUTO_EOF'` heredoc. The heredoc form was a root-
// in-container injection sink: an attacker-controlled package name with
// an embedded "\nKOJUTO_EOF\n<cmd>" sequence used to terminate the
// heredoc early and run <cmd> as root. Stdin delivery removes the body
// from the shell command line entirely.
func TestDockerWriteFile_StructureNoHeredoc(t *testing.T) {
	var captured []string
	orig := execCommand
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		captured = append([]string{name}, args...)
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCommand = orig })

	sb := &Sandbox{containerID: testContainerID}
	if err := sb.dockerWriteFile(context.Background(), "/tmp/probe.js",
		"any content with KOJUTO_EOF baked in\nstill not parsed by shell"); err != nil {
		t.Fatalf("dockerWriteFile: %v", err)
	}

	want := []string{
		"docker", dockerSubcmdExec, "-i", "--user=root", testContainerID,
		"sh", "-c", "cat > '/tmp/probe.js'",
	}
	if !reflect.DeepEqual(captured, want) {
		t.Fatalf("docker args mismatch:\n got %q\nwant %q", captured, want)
	}

	for _, a := range captured {
		if strings.Contains(a, "<<") {
			t.Errorf("heredoc syntax leaked into arg %q", a)
		}
		if strings.Contains(a, "KOJUTO_EOF") {
			t.Errorf("KOJUTO_EOF terminator leaked into arg %q", a)
		}
	}
}

// TestDockerWriteFile_QuotesPath confirms the path is single-quoted so a
// future caller passing a path with shell metacharacters cannot break the
// command. Every current caller passes a constant path; this test pins
// the defense-in-depth contract for future code.
func TestDockerWriteFile_QuotesPath(t *testing.T) {
	var captured []string
	orig := execCommand
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		captured = append([]string{name}, args...)
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCommand = orig })

	sb := &Sandbox{containerID: testContainerID}
	if err := sb.dockerWriteFile(context.Background(), "/tmp/$(rm -rf /)/x", "x"); err != nil {
		t.Fatalf("dockerWriteFile: %v", err)
	}

	last := captured[len(captured)-1]
	if !strings.Contains(last, `'/tmp/$(rm -rf /)/x'`) {
		t.Errorf("path not single-quoted in shell arg: %q", last)
	}
}

// withFailingExec replaces execCommand with one that always exits non-zero,
// simulating a docker daemon hiccup or an in-container command failure.
func withFailingExec(t *testing.T) {
	t.Helper()
	orig := execCommand
	execCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "false")
	}
	t.Cleanup(func() { execCommand = orig })
}

func TestPlantHoneypotFiles_FailLoud(t *testing.T) {
	withFailingExec(t)
	sb := &Sandbox{containerID: testContainerID}
	if err := sb.plantHoneypotFiles(context.Background()); err == nil {
		t.Fatal("plantHoneypotFiles returned nil despite failing docker command")
	}
}

func TestRestoreLocalBin_FailLoud(t *testing.T) {
	withFailingExec(t)
	sb := &Sandbox{containerID: testContainerID, ecosystem: types.EcosystemPyPI}
	if err := sb.restoreLocalBin(context.Background()); err == nil {
		t.Fatal("restoreLocalBin returned nil despite failing docker command")
	}
}

func TestWriteProbeScripts_FailLoud(t *testing.T) {
	withFailingExec(t)
	sb := &Sandbox{containerID: testContainerID, pkg: "x", ecosystem: types.EcosystemPyPI}
	if err := sb.WriteProbeScripts(context.Background()); err == nil {
		t.Fatal("WriteProbeScripts returned nil despite failing docker command")
	}
}

func TestWriteProbeScriptsMulti_FailLoud(t *testing.T) {
	withFailingExec(t)
	sb := &Sandbox{containerID: testContainerID, ecosystem: types.EcosystemPyPI}
	if err := sb.WriteProbeScriptsMulti(context.Background(), []string{"x"}); err == nil {
		t.Fatal("WriteProbeScriptsMulti returned nil despite failing docker command")
	}
}

// dockerSubcmdExec is the docker subcommand string used across the
// rollback tests below. Extracted for goconst.
const dockerSubcmdExec = "exec"

// TestStart_RollbackOnPrepareFailure pins the contract that when
// Start's post-start preparation fails, the partially-created
// container is removed before Start returns.
//
// Motivating measurement: --timeout 3s during a live scan left the
// docker exec cp of tmpfs overlays incomplete, and the caller never
// receives a *Sandbox pointer to register Cleanup on. Without the
// rollback the container leaks in Up state, which
// CleanupStaleSandboxContainers deliberately skips (to protect
// concurrent scans).
//
// The fake execCommand succeeds on create/start/network but fails
// the first docker exec (restoreLocalBin), triggering the rollback
// path. We assert `docker rm -f <containerID>` was invoked.
func TestStart_RollbackOnPrepareFailure(t *testing.T) {
	var rmCalls []string
	orig := execCommand
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 {
			switch args[0] {
			case dockerSubcmdExec:
				// Fail this — triggers prepareSandboxState error
				// path and the deferred rollbackPartialStart.
				return exec.CommandContext(ctx, "false")
			case "rm":
				rmCalls = append(rmCalls, strings.Join(args, " "))
			}
		}
		// Everything else routes through TestHelperProcess (docker
		// create returns the fake container id via stdout).
		return fakeExecCommand(ctx, name, args...)
	}
	t.Cleanup(func() { execCommand = orig })

	sb := newTestSandbox(t, types.EcosystemPyPI)
	t.Cleanup(func() {
		if sb.seccompDir != "" {
			os.RemoveAll(sb.seccompDir)
		}
	})

	err := sb.Start(context.Background())
	if err == nil {
		t.Fatal("expected Start to return error when docker exec fails")
	}

	if len(rmCalls) == 0 {
		t.Fatal("rollback did not fire — no docker rm invocation after Start failure")
	}
	joined := strings.Join(rmCalls, " ")
	if !strings.Contains(joined, "rm -f") {
		t.Errorf("expected 'rm -f' in rm calls, got %v", rmCalls)
	}
	// The container id set by Create (via fakeExecCommand's docker
	// create case) must appear in the rm invocation.
	if !strings.Contains(joined, "fake-container-id-12345") {
		t.Errorf("expected fake container id in rm calls, got %v", rmCalls)
	}
}

// TestStartPaused_RollbackOnPrepareFailure mirrors the Start test
// for the paused variant used by eBPF / strace host-side probe modes.
// The docker start succeeds, then the docker exec of prepareSandboxState
// fails — the deferred rollback must remove the leaked container.
func TestStartPaused_RollbackOnPrepareFailure(t *testing.T) {
	var rmCalls []string
	orig := execCommand
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 {
			switch args[0] {
			case dockerSubcmdExec:
				return exec.CommandContext(ctx, "false")
			case "rm":
				rmCalls = append(rmCalls, strings.Join(args, " "))
			}
		}
		return fakeExecCommand(ctx, name, args...)
	}
	t.Cleanup(func() { execCommand = orig })

	// StartPaused expects the caller to have called Create first.
	sb := newTestSandbox(t, types.EcosystemPyPI)
	sb.containerID = testContainerID
	t.Cleanup(func() {
		if sb.seccompDir != "" {
			os.RemoveAll(sb.seccompDir)
		}
	})

	err := sb.StartPaused(context.Background())
	if err == nil {
		t.Fatal("expected StartPaused to return error when docker exec fails")
	}

	if len(rmCalls) == 0 {
		t.Fatal("rollback did not fire — no docker rm invocation after StartPaused failure")
	}
	joined := strings.Join(rmCalls, " ")
	if !strings.Contains(joined, "rm -f "+testContainerID) {
		t.Errorf("expected 'rm -f %s' in rm calls, got %v", testContainerID, rmCalls)
	}
}
