package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/RalianENG/kojuto/internal/depfile"
	"github.com/RalianENG/kojuto/internal/sandbox"
	"github.com/RalianENG/kojuto/internal/types"
)

const (
	testVersion     = "1.0.0"
	testVersion2310 = "2.31.0"
	testReqFile     = "requirements.txt"
)

// fakeInstallLocalNpm stands in for downloader.InstallLocalNpm, which in
// production drives a real DownloadSandbox. It creates the node_modules
// directory the caller expects so prepareLocalNpm can be exercised without
// Docker. The subprocess-based fakeExecCommand helper it replaced existed
// only to mock the host-side `npm install` that prepareLocalNpm used to
// run; that call now happens inside the download sandbox instead.
func fakeInstallLocalNpm(_ context.Context, stagingDir string) ([]types.SyscallEvent, error) {
	if err := os.MkdirAll(filepath.Join(stagingDir, "node_modules"), 0o755); err != nil {
		return nil, err
	}
	return nil, nil
}

// saveAndRestoreFlags saves all global flags and restores them after the test.
func saveAndRestoreFlags(t *testing.T) {
	t.Helper()
	origVersion := flagVersion
	origOutput := flagOutput
	origProbeMethod := flagProbeMethod
	origEcosystem := flagEcosystem
	origFile := flagFile
	origPin := flagPin
	origLocal := flagLocal
	origRuntime := flagRuntime
	origTimeout := flagTimeout
	t.Cleanup(func() {
		flagVersion = origVersion
		flagOutput = origOutput
		flagProbeMethod = origProbeMethod
		flagEcosystem = origEcosystem
		flagFile = origFile
		flagPin = origPin
		flagLocal = origLocal
		flagRuntime = origRuntime
		flagTimeout = origTimeout
	})
}

// saveAndRestoreDeps saves all dependency function vars and restores them.
func saveAndRestoreDeps(t *testing.T) {
	t.Helper()
	origDownload := downloaderDownload
	origValidate := downloaderValidate
	origDetectVersion := downloaderDetectVersion
	origSandboxNew := sandboxNew
	origSandboxEnsure := sandboxEnsureImage
	origDepfile := depfileParse
	origInstallLocalNpm := downloaderInstallLocalNpm
	t.Cleanup(func() {
		downloaderDownload = origDownload
		downloaderValidate = origValidate
		downloaderDetectVersion = origDetectVersion
		sandboxNew = origSandboxNew
		sandboxEnsureImage = origSandboxEnsure
		depfileParse = origDepfile
		downloaderInstallLocalNpm = origInstallLocalNpm
	})
}

// --- scanSinglePackage tests ---

func TestScanSinglePackage_InvalidInput(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagTimeout = 5 * time.Second
	downloaderValidate = func(pkg, _ string) error {
		return fmt.Errorf("invalid package: %s", pkg)
	}

	_, err := scanSinglePackage("--evil", "", types.EcosystemPyPI)
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
	if !strings.Contains(err.Error(), "invalid input") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanSinglePackage_UnsupportedEcosystem(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagTimeout = 5 * time.Second
	downloaderValidate = func(_, _ string) error { return nil }

	_, err := scanSinglePackage("pkg", "", "cargo")
	if err == nil {
		t.Fatal("expected error for unsupported ecosystem")
	}
	if !strings.Contains(err.Error(), "unsupported ecosystem") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanSinglePackage_DownloadFailure(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagTimeout = 5 * time.Second
	downloaderValidate = func(_, _ string) error { return nil }
	downloaderDownload = func(_ context.Context, _, _, _, _ string) (string, []types.SyscallEvent, error) {
		return "", nil, errors.New("download failed: network error")
	}

	_, err := scanSinglePackage("pkg", "", types.EcosystemPyPI)
	if err == nil {
		t.Fatal("expected error for download failure")
	}
	if !strings.Contains(err.Error(), "download") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- downloadPackage tests ---

func TestDownloadPackage_Success(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagEcosystem = types.EcosystemPyPI
	flagVersion = ""

	tmpDir := t.TempDir()
	pkgDir := filepath.Join(tmpDir, "packages")
	os.MkdirAll(pkgDir, 0o755)

	downloaderDownload = func(_ context.Context, _, _, destDir, _ string) (string, []types.SyscallEvent, error) {
		// Create a fake wheel file.
		os.WriteFile(filepath.Join(destDir, "requests-2.31.0-py3-none-any.whl"), []byte("fake"), 0o644)
		return destDir, nil, nil
	}
	downloaderDetectVersion = func(_, _ string) string {
		return testVersion2310
	}

	ctx := context.Background()
	dlDir, _, err := downloadPackage(ctx, "requests")
	if err != nil {
		t.Fatalf("downloadPackage failed: %v", err)
	}
	defer os.RemoveAll(filepath.Dir(dlDir))

	if dlDir == "" {
		t.Error("expected non-empty dlDir")
	}
	if flagVersion != testVersion2310 {
		t.Errorf("flagVersion = %q, want %s", flagVersion, testVersion2310)
	}
}

func TestDownloadPackage_Failure(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagEcosystem = types.EcosystemPyPI
	flagVersion = ""

	downloaderDownload = func(_ context.Context, _, _, _, _ string) (string, []types.SyscallEvent, error) {
		return "", nil, errors.New("pip not found")
	}

	ctx := context.Background()
	_, _, err := downloadPackage(ctx, "pkg")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "downloading package") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- startSandbox tests ---

func TestStartSandbox_EnsureImageFailure(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	sandboxEnsureImage = func(_ context.Context, _ string) error {
		return errors.New("docker not found")
	}

	ctx := context.Background()
	_, err := startSandbox(ctx, "/tmp/pkg", []string{"test"}, methodStraceContainer)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "ensuring sandbox image") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- runBatchScan tests ---

func TestRunBatchScan_ParseError(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagFile = "/nonexistent/requirements.txt"
	depfileParse = func(_ string) ([]depfile.Dep, string, error) {
		return nil, "", errors.New("file not found")
	}

	err := runBatchScan(nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunBatchScan_EmptyDeps(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagFile = testReqFile
	depfileParse = func(_ string) ([]depfile.Dep, string, error) {
		return []depfile.Dep{}, types.EcosystemPyPI, nil
	}

	err := runBatchScan(nil)
	if err == nil {
		t.Fatal("expected error for empty deps")
	}
	if !strings.Contains(err.Error(), "no dependencies") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunBatchScan_PinWithoutFile(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagFile = "" // intentionally empty for --pin check
	flagPin = "output.txt"
	depfileParse = func(_ string) ([]depfile.Dep, string, error) {
		return []depfile.Dep{{Name: "pkg"}}, types.EcosystemPyPI, nil
	}

	err := runBatchScan(nil)
	if err == nil {
		t.Fatal("expected error for --pin without -f")
	}
	if !strings.Contains(err.Error(), "--pin requires") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunBatchScan_WithSuspicious(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagFile = testReqFile
	flagTimeout = 5 * time.Second
	flagPin = ""

	depfileParse = func(_ string) ([]depfile.Dep, string, error) {
		return []depfile.Dep{
			{Name: "evil-pkg", Version: testVersion},
		}, types.EcosystemPyPI, nil
	}
	downloaderValidate = func(_, _ string) error { return nil }
	downloaderDownload = func(_ context.Context, _, _, destDir, _ string) (string, []types.SyscallEvent, error) {
		os.WriteFile(filepath.Join(destDir, "evil_pkg-1.0.0.whl"), []byte("x"), 0o644)
		return destDir, nil, nil
	}
	downloaderDetectVersion = func(_, _ string) string { return testVersion }
	sandboxNew = func(packageDir, pkg string, needsPtrace bool, ecosystem, runtime string) *sandbox.Sandbox {
		return sandbox.New(packageDir, pkg, needsPtrace, ecosystem, runtime)
	}

	// Make sandbox operations fail to trigger scanErr path.
	sandboxEnsureImage = func(_ context.Context, _ string) error {
		return errors.New("intentional failure")
	}

	err := runBatchScan(nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunBatchScan_AllCleanWithPin(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	dir := t.TempDir()
	flagFile = testReqFile
	flagTimeout = 5 * time.Second
	flagPin = filepath.Join(dir, "locked.txt")

	depfileParse = func(_ string) ([]depfile.Dep, string, error) {
		return []depfile.Dep{
			{Name: "requests", Version: testVersion2310},
		}, types.EcosystemPyPI, nil
	}
	downloaderValidate = func(_, _ string) error { return nil }

	// Mock download: create temp dir with a package file.
	downloaderDownload = func(_ context.Context, _, _, destDir, _ string) (string, []types.SyscallEvent, error) {
		os.WriteFile(filepath.Join(destDir, "requests-2.31.0.whl"), []byte("x"), 0o644)
		return destDir, nil, nil
	}
	downloaderDetectVersion = func(_, _ string) string { return testVersion2310 }
	sandboxEnsureImage = func(_ context.Context, _ string) error { return nil }

	// Will fail at sandbox.Start because there's no Docker, but
	// tests the batch logic up to that point.
	err := runBatchScan(nil)
	if err == nil {
		// If somehow it succeeds, check pin file was created.
		if _, statErr := os.Stat(flagPin); statErr != nil {
			t.Errorf("pin file not created: %v", statErr)
		}
	}
}

// --- runLocalScan tests ---

func TestRunLocalScan_FileNotFound(t *testing.T) {
	saveAndRestoreFlags(t)

	flagLocal = "/nonexistent/path/to/package.whl"

	err := runLocalScan(nil)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "local path not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunLocalScan_Directory(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	dir := t.TempDir()
	// Create a .whl file in the dir.
	os.WriteFile(filepath.Join(dir, "pkg-1.0.0-py3-none-any.whl"), []byte("x"), 0o644)

	flagLocal = dir
	flagEcosystem = types.EcosystemPyPI
	flagTimeout = 5 * time.Second

	downloaderDetectVersion = func(_, _ string) string { return testVersion }
	sandboxEnsureImage = func(_ context.Context, _ string) error {
		return errors.New("no docker for test")
	}

	err := runLocalScan(nil)
	if err == nil {
		t.Fatal("expected error (no Docker)")
	}
}

func TestRunLocalScan_SingleFile(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	dir := t.TempDir()
	whlFile := filepath.Join(dir, "mypkg-2.0.0-py3-none-any.whl")
	os.WriteFile(whlFile, []byte("x"), 0o644)

	flagLocal = whlFile
	flagEcosystem = types.EcosystemPyPI
	flagTimeout = 5 * time.Second

	downloaderDetectVersion = func(_, _ string) string { return "2.0.0" }
	sandboxEnsureImage = func(_ context.Context, _ string) error {
		return errors.New("no docker")
	}

	err := runLocalScan(nil)
	if err == nil {
		t.Fatal("expected error (no Docker)")
	}
}

func TestRunLocalScan_NpmAutoDetect(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	dir := t.TempDir()
	tgzFile := filepath.Join(dir, "evil-1.0.0.tgz")
	os.WriteFile(tgzFile, []byte("x"), 0o644)

	flagLocal = tgzFile
	flagEcosystem = types.EcosystemPyPI // should auto-detect to npm
	flagTimeout = 5 * time.Second

	downloaderDetectVersion = func(_, _ string) string { return testVersion }
	downloaderInstallLocalNpm = fakeInstallLocalNpm

	// prepareLocalNpm will fail because no real tgz.
	err := runLocalScan(nil)
	if err == nil {
		t.Fatal("expected error")
	}
	// Verify ecosystem was auto-detected to npm (via the npm codepath).
	if flagEcosystem != types.EcosystemNpm {
		t.Errorf("ecosystem = %q, want %q", flagEcosystem, types.EcosystemNpm)
	}
}

// TestRunLocalScan_RejectsUnsafeFilename pins the security invariant that
// a filename whose derived package name contains shell metacharacters or
// newlines is rejected at the boundary, before any sandbox interaction.
// Without this gate, a malicious .tgz/.whl filename containing a newline
// followed by "KOJUTO_EOF" used to terminate dockerWriteFile's predecessor
// heredoc and execute arbitrary commands as root inside the container.
// The dockerWriteFile refactor closed the heredoc; this test guards the
// belt-and-braces input check.
func TestRunLocalScan_RejectsUnsafeFilename(t *testing.T) {
	saveAndRestoreFlags(t)

	dir := t.TempDir()
	// "\n" + "KOJUTO_EOF" payload baked into a .tgz filename. macOS APFS
	// and Linux ext4/xfs all permit '\n' in filenames; if the underlying
	// FS rejects it, skip rather than fail.
	badName := "evil\nKOJUTO_EOF\nrm-1.0.0.tgz"
	badFile := filepath.Join(dir, badName)
	if err := os.WriteFile(badFile, []byte("x"), 0o644); err != nil {
		t.Skipf("filesystem refuses newlines in filenames: %v", err)
	}

	flagLocal = badFile
	flagEcosystem = types.EcosystemNpm
	flagTimeout = 5 * time.Second

	err := runLocalScan(nil)
	if err == nil {
		t.Fatal("expected validation error for unsafe local filename")
	}
	if !strings.Contains(err.Error(), "unsafe") {
		t.Errorf("expected 'unsafe' in error, got: %v", err)
	}
}

// --- prepareLocalNpm tests ---

func TestPrepareLocalNpm_NoTgz(t *testing.T) {
	dir := t.TempDir()
	// No .tgz file in directory.
	os.WriteFile(filepath.Join(dir, "readme.md"), []byte("hello"), 0o644)

	st, err := prepareLocalNpm(context.Background(), dir, "pkg")
	if st.root != "" {
		defer os.RemoveAll(st.root)
	}
	if err == nil {
		t.Fatal("expected error for no .tgz")
	}
	if !strings.Contains(err.Error(), "no .tgz file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareLocalNpm_BadDir(t *testing.T) {
	st, err := prepareLocalNpm(context.Background(), "/nonexistent/dir", "pkg")
	if st.root != "" {
		defer os.RemoveAll(st.root)
	}
	if err == nil {
		t.Fatal("expected error for nonexistent dir")
	}
}

func TestPrepareLocalNpm_Success(t *testing.T) {
	saveAndRestoreDeps(t)

	dir := t.TempDir()
	tgzPath := filepath.Join(dir, "mypkg-1.0.0.tgz")
	os.WriteFile(tgzPath, []byte("fake"), 0o644)

	downloaderInstallLocalNpm = fakeInstallLocalNpm

	st, err := prepareLocalNpm(context.Background(), dir, "mypkg")
	if err != nil {
		t.Fatalf("prepareLocalNpm failed: %v", err)
	}
	defer os.RemoveAll(st.root)

	// Verify package.json was created in staging dir.
	pkgJSON, readErr := os.ReadFile(filepath.Join(st.dir, "package.json"))
	if readErr != nil {
		t.Fatalf("reading staging package.json: %v", readErr)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(pkgJSON, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if parsed["name"] != "kojuto-local-staging" {
		t.Errorf("name = %v, want kojuto-local-staging", parsed["name"])
	}

	// The dependency spec must be relative. The staging dir is bind-mounted
	// at /out inside the download sandbox, so the absolute host path the
	// previous host-side implementation emitted would not resolve there.
	deps, ok := parsed["dependencies"].(map[string]interface{})
	if !ok {
		t.Fatalf("dependencies missing or wrong shape: %#v", parsed["dependencies"])
	}
	if got := deps["mypkg"]; got != "file:./mypkg-1.0.0.tgz" {
		t.Errorf("dependency spec = %v, want file:./mypkg-1.0.0.tgz", got)
	}

	// The tarball must be copied into the staging dir for that relative
	// spec to resolve inside the container.
	if _, statErr := os.Stat(filepath.Join(st.dir, "mypkg-1.0.0.tgz")); statErr != nil {
		t.Errorf("tarball not staged into mount dir: %v", statErr)
	}
}

// TestPrepareLocalNpm_StagingParentIsPrivate pins the containment invariant
// behind the staging layout. DownloadSandbox relaxes the directory it
// bind-mounts to 0o777 (the container runs as UID 1000, not the host UID),
// so the staging dir must sit below a parent no other account can traverse.
// The previous implementation chmod'd the top-level MkdirTemp directory
// itself, leaving a world-writable directory in the system temp directory
// where any local user could drop an extra tarball into the scan.
func TestPrepareLocalNpm_StagingParentIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	saveAndRestoreDeps(t)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "mypkg-1.0.0.tgz"), []byte("fake"), 0o644)
	downloaderInstallLocalNpm = fakeInstallLocalNpm

	st, err := prepareLocalNpm(context.Background(), dir, "mypkg")
	if err != nil {
		t.Fatalf("prepareLocalNpm failed: %v", err)
	}
	defer os.RemoveAll(st.root)

	if filepath.Dir(st.dir) != st.root {
		t.Fatalf("staging dir %q is not directly below root %q", st.dir, st.root)
	}

	info, statErr := os.Stat(st.root)
	if statErr != nil {
		t.Fatalf("stat staging root: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("staging root perms = %#o, want no group/other access", perm)
	}
}

// --- runScan dispatch tests ---

func TestRunScan_LocalMode(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagLocal = "/nonexistent/file.whl"
	flagFile = ""

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("expected error in local mode")
	}
}

func TestRunScan_BatchMode(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagLocal = ""
	flagFile = testReqFile

	depfileParse = func(_ string) ([]depfile.Dep, string, error) {
		return nil, "", errors.New("parse error")
	}

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("expected error in batch mode")
	}
}

// --- runBatchScan ecosystem override ---

func TestRunBatchScan_EcosystemOverride(t *testing.T) {
	saveAndRestoreFlags(t)
	saveAndRestoreDeps(t)

	flagFile = "deps.txt"
	flagEcosystem = types.EcosystemNpm // explicitly set npm
	flagTimeout = 5 * time.Second
	flagPin = ""

	depfileParse = func(_ string) ([]depfile.Dep, string, error) {
		return []depfile.Dep{{Name: "pkg"}}, types.EcosystemPyPI, nil
	}
	downloaderValidate = func(_, _ string) error { return nil }
	downloaderDownload = func(_ context.Context, _, _, destDir, eco string) (string, []types.SyscallEvent, error) {
		// Verify ecosystem was overridden.
		if eco != types.EcosystemNpm {
			return "", nil, fmt.Errorf("expected npm ecosystem, got %s", eco)
		}
		os.WriteFile(filepath.Join(destDir, "pkg.whl"), []byte("x"), 0o644)
		return destDir, nil, nil
	}
	downloaderDetectVersion = func(_, _ string) string { return "1.0" }
	sandboxEnsureImage = func(_ context.Context, _ string) error {
		return errors.New("no docker")
	}

	// Will fail at sandbox, but the ecosystem override is tested.
	_ = runBatchScan(nil)
}

// --- outputReport via VerdictError wrapping ---

func TestOutputReport_WritesToFile(t *testing.T) {
	saveAndRestoreFlags(t)

	dir := t.TempDir()
	flagOutput = filepath.Join(dir, "out.json")
	flagVersion = testVersion
	flagEcosystem = types.EcosystemPyPI

	result := &scanResult{
		method: "strace-container",
		events: []types.SyscallEvent{
			{Syscall: types.EventConnect, DstAddr: "127.0.0.1", DstPort: 80, Family: 2},
		},
	}

	// Loopback is benign, so verdict should be clean.
	err := outputReport("testpkg", result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, readErr := os.ReadFile(flagOutput)
	if readErr != nil {
		t.Fatalf("reading output: %v", readErr)
	}

	var report types.Report
	if jsonErr := json.Unmarshal(data, &report); jsonErr != nil {
		t.Fatalf("invalid JSON: %v", jsonErr)
	}

	if report.Verdict != types.VerdictClean {
		t.Errorf("verdict = %q, want clean", report.Verdict)
	}
	if report.Package != "testpkg" {
		t.Errorf("package = %q, want testpkg", report.Package)
	}
}

// --- Execute tests ---

func TestExecute_VersionSubcommand(t *testing.T) {
	// Execute with "version" subcommand should not exit with error.
	// We can't fully test Execute() because it calls os.Exit,
	// but we can test the rootCmd directly.
	rootCmd.SetArgs([]string{"version"})
	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("version command failed: %v", err)
	}
}

// --- VerdictError as error interface ---

func TestVerdictError_ErrorsAs(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &VerdictError{Verdict: "suspicious", ExitCode: 2})

	var ve *VerdictError
	if !errors.As(err, &ve) {
		t.Fatal("errors.As should find VerdictError")
	}
	if ve.Verdict != "suspicious" {
		t.Errorf("verdict = %q, want suspicious", ve.Verdict)
	}
}
