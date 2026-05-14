package downloader

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/RalianENG/kojuto/internal/sandbox"
	"github.com/RalianENG/kojuto/internal/types"
)

// ---------------------------------------------------------------------------
// runInSandbox stub
//
// The downloader no longer execs pip/npm directly — every registry command
// goes through runInSandbox, which in production drives a DownloadSandbox
// container. Tests swap it for a stub so they never touch Docker.
// ---------------------------------------------------------------------------

// recordedRun captures what the runInSandbox stub was called with.
type recordedRun struct {
	calls       int
	lastDir     string
	lastCommand []string
}

// stubRunInSandbox swaps runInSandbox for the duration of the test with a stub
// that records its arguments and returns the given output/error, restoring the
// original on cleanup.
func stubRunInSandbox(t *testing.T, out []byte, err error) *recordedRun {
	t.Helper()
	rec := &recordedRun{}
	orig := runInSandbox
	runInSandbox = func(_ context.Context, hostOutDir string, command []string) ([]byte, error) {
		rec.calls++
		rec.lastDir = hostOutDir
		rec.lastCommand = command
		return out, err
	}
	t.Cleanup(func() { runInSandbox = orig })
	return rec
}

// ---------------------------------------------------------------------------
// versionOrLatest
// ---------------------------------------------------------------------------

func TestVersionOrLatest(t *testing.T) {
	if got := versionOrLatest(""); got != "*" {
		t.Errorf("versionOrLatest('') = %q, want '*'", got)
	}
	if got := versionOrLatest("1.2.3"); got != "1.2.3" {
		t.Errorf("versionOrLatest('1.2.3') = %q, want '1.2.3'", got)
	}
}

// ---------------------------------------------------------------------------
// verifyDownload
// ---------------------------------------------------------------------------

func TestVerifyDownload_Empty(t *testing.T) {
	dir := t.TempDir()
	_, err := verifyDownload(dir, "somepkg")
	if err == nil {
		t.Error("expected error for empty dir, got nil")
	}
}

func TestVerifyDownload_WithFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pkg-1.0.0.whl"), []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := verifyDownload(dir, "pkg")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != dir {
		t.Errorf("verifyDownload returned %q, want %q", got, dir)
	}
}

func TestVerifyDownload_BadDir(t *testing.T) {
	_, err := verifyDownload("/nonexistent_dir_12345", "pkg")
	if err == nil {
		t.Error("expected error for nonexistent dir, got nil")
	}
}

// ---------------------------------------------------------------------------
// pypiDownloadArgs
// ---------------------------------------------------------------------------

func TestPypiDownloadArgs_TargetsMountPath(t *testing.T) {
	args := pypiDownloadArgs()
	idx := slices.Index(args, "-d")
	if idx < 0 || idx == len(args)-1 {
		t.Fatalf("pypiDownloadArgs missing '-d <dir>': %v", args)
	}
	if args[idx+1] != sandbox.DownloadOutMountPath {
		t.Errorf("pip download dir = %q, want %q (the sandbox mount path)",
			args[idx+1], sandbox.DownloadOutMountPath)
	}
}

// ---------------------------------------------------------------------------
// detectVersionFromPyPI
// ---------------------------------------------------------------------------

func TestDetectVersionFromPyPI(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		want   string
	}{
		{"requests-2.31.0-py3-none-any.whl", "requests-", "2.31.0"},
		{"numpy-1.26.4-cp312-cp312-manylinux.whl", "numpy-", "1.26.4"},
		{"flask-3.0.0.tar.gz", "flask-", "3.0.0"},
		{"simplepkg-0.1.whl", "simplepkg-", "0.1"},
	}
	for _, c := range cases {
		got := detectVersionFromPyPI(c.name, c.prefix)
		if got != c.want {
			t.Errorf("detectVersionFromPyPI(%q, %q) = %q, want %q", c.name, c.prefix, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// detectVersionFromTgz
// ---------------------------------------------------------------------------

func TestDetectVersionFromTgz(t *testing.T) {
	cases := []struct {
		name string
		pkg  string
		want string
	}{
		{"lodash-4.17.21.tgz", "lodash", "4.17.21"},
		{"express-4.18.2.tgz", "express", "4.18.2"},
		{"pkg-1.0.0.tgz", "@scope/pkg", "1.0.0"},
		{"unmatched.tgz", "other", ""},
	}
	for _, c := range cases {
		got := detectVersionFromTgz(c.name, c.pkg)
		if got != c.want {
			t.Errorf("detectVersionFromTgz(%q, %q) = %q, want %q", c.name, c.pkg, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// DetectNpmVersion
// ---------------------------------------------------------------------------

func TestDetectNpmVersion(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "package")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"version": "5.0.1"})
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectNpmVersion(dir); got != "5.0.1" {
		t.Errorf("DetectNpmVersion = %q, want '5.0.1'", got)
	}
}

func TestDetectNpmVersion_Missing(t *testing.T) {
	dir := t.TempDir()
	if got := DetectNpmVersion(dir); got != "" {
		t.Errorf("DetectNpmVersion on missing dir = %q, want ''", got)
	}
}

func TestDetectNpmVersion_BadJSON(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "package")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte("{bad json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectNpmVersion(dir); got != "" {
		t.Errorf("DetectNpmVersion on bad JSON = %q, want ''", got)
	}
}

// ---------------------------------------------------------------------------
// DetectVersion (integration-level)
// ---------------------------------------------------------------------------

func TestDetectVersion_Whl(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requests-2.31.0-py3-none-any.whl"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectVersion(dir, "requests"); got != "2.31.0" {
		t.Errorf("DetectVersion whl = %q, want '2.31.0'", got)
	}
}

func TestDetectVersion_Tgz(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lodash-4.17.21.tgz"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectVersion(dir, "lodash"); got != "4.17.21" {
		t.Errorf("DetectVersion tgz = %q, want '4.17.21'", got)
	}
}

func TestDetectVersion_NoMatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectVersion(dir, "somepkg"); got != "" {
		t.Errorf("DetectVersion no match = %q, want ''", got)
	}
}

func TestDetectVersion_BadDir(t *testing.T) {
	if got := DetectVersion("/nonexistent_dir_99999", "pkg"); got != "" {
		t.Errorf("DetectVersion bad dir = %q, want ''", got)
	}
}

// ---------------------------------------------------------------------------
// Download — error paths
// ---------------------------------------------------------------------------

func TestDownload_UnsupportedEcosystem(t *testing.T) {
	_, err := Download(context.Background(), "pkg", "1.0", t.TempDir(), "rubygems")
	if err == nil {
		t.Error("expected error for unsupported ecosystem, got nil")
	}
}

func TestDownload_InvalidPackageName(t *testing.T) {
	_, err := Download(context.Background(), "--evil", "", t.TempDir(), types.EcosystemPyPI)
	if err == nil {
		t.Error("expected error for invalid package name, got nil")
	}
}

func TestDownload_InvalidVersion(t *testing.T) {
	_, err := Download(context.Background(), "pkg", "$(whoami)", t.TempDir(), types.EcosystemPyPI)
	if err == nil {
		t.Error("expected error for invalid version, got nil")
	}
}

// ---------------------------------------------------------------------------
// downloadPyPI — sandbox stubbed
// ---------------------------------------------------------------------------

func TestDownloadPyPI_Mock(t *testing.T) {
	rec := stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	// Create a fake downloaded file so verifyDownload succeeds.
	if err := os.WriteFile(filepath.Join(dir, "pkg-1.0.0-py3-none-any.whl"), []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := downloadPyPI(context.Background(), "pkg", "1.0.0", dir)
	if err != nil {
		t.Fatalf("downloadPyPI error: %v", err)
	}
	if got != dir {
		t.Errorf("downloadPyPI returned %q, want %q", got, dir)
	}
	if rec.lastDir != dir {
		t.Errorf("runInSandbox hostOutDir = %q, want %q", rec.lastDir, dir)
	}
	if len(rec.lastCommand) == 0 || rec.lastCommand[0] != "pip" {
		t.Errorf("runInSandbox command = %v, want it to start with 'pip'", rec.lastCommand)
	}
	if !slices.Contains(rec.lastCommand, "pkg==1.0.0") {
		t.Errorf("runInSandbox command = %v, want it to contain 'pkg==1.0.0'", rec.lastCommand)
	}
}

func TestDownloadPyPI_NoVersion(t *testing.T) {
	rec := stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pkg-2.0.0.whl"), []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := downloadPyPI(context.Background(), "pkg", "", dir)
	if err != nil {
		t.Fatalf("downloadPyPI error: %v", err)
	}
	if got != dir {
		t.Errorf("downloadPyPI returned %q, want %q", got, dir)
	}
	// No version pin: the bare package name is the target.
	if !slices.Contains(rec.lastCommand, "pkg") {
		t.Errorf("runInSandbox command = %v, want it to contain 'pkg'", rec.lastCommand)
	}
}

func TestDownloadPyPI_EmptyDir(t *testing.T) {
	stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	// No files — verifyDownload should fail.
	_, err := downloadPyPI(context.Background(), "pkg", "1.0.0", dir)
	if err == nil {
		t.Error("expected error for empty download dir, got nil")
	}
}

func TestDownloadPyPI_SandboxError(t *testing.T) {
	stubRunInSandbox(t, []byte("boom"), errors.New("download command failed"))

	dir := t.TempDir()
	// Even with a downloaded file present, a sandbox failure must surface.
	if err := os.WriteFile(filepath.Join(dir, "pkg-1.0.0.whl"), []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := downloadPyPI(context.Background(), "pkg", "1.0.0", dir)
	if err == nil {
		t.Error("expected error when the download sandbox fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// downloadNpm — sandbox stubbed
// ---------------------------------------------------------------------------

func TestDownloadNpm_Mock(t *testing.T) {
	rec := stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	// Create node_modules so the post-install check passes.
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := downloadNpm(context.Background(), "lodash", "4.17.21", dir)
	if err != nil {
		t.Fatalf("downloadNpm error: %v", err)
	}
	if got != dir {
		t.Errorf("downloadNpm returned %q, want %q", got, dir)
	}
	wantCmd := []string{"npm", "install", "--ignore-scripts"}
	if !slices.Equal(rec.lastCommand, wantCmd) {
		t.Errorf("runInSandbox command = %v, want %v", rec.lastCommand, wantCmd)
	}

	// The staging package.json must be written into destDir, which is what
	// gets bind-mounted into the sandbox.
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("reading staging package.json: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("staging package.json is not valid JSON: %v", err)
	}
	deps, ok := parsed["dependencies"].(map[string]any)
	if !ok || deps["lodash"] != "4.17.21" {
		t.Errorf("staging package.json dependencies = %v, want lodash@4.17.21", parsed["dependencies"])
	}
}

func TestDownloadNpm_NoVersion(t *testing.T) {
	stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := downloadNpm(context.Background(), "express", "", dir)
	if err != nil {
		t.Fatalf("downloadNpm error: %v", err)
	}
	if got != dir {
		t.Errorf("downloadNpm returned %q, want %q", got, dir)
	}
	// No version: dependency resolves to "*".
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("reading staging package.json: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("staging package.json is not valid JSON: %v", err)
	}
	deps, _ := parsed["dependencies"].(map[string]any)
	if deps["express"] != "*" {
		t.Errorf("staging package.json dependencies[express] = %v, want '*'", deps["express"])
	}
}

func TestDownloadNpm_NoNodeModules(t *testing.T) {
	stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	// Don't create node_modules — should error.
	_, err := downloadNpm(context.Background(), "lodash", "4.17.21", dir)
	if err == nil {
		t.Error("expected error when node_modules not created, got nil")
	}
}

func TestDownloadNpm_SandboxError(t *testing.T) {
	stubRunInSandbox(t, []byte("npm err"), errors.New("download command failed"))

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := downloadNpm(context.Background(), "lodash", "4.17.21", dir)
	if err == nil {
		t.Error("expected error when the download sandbox fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// Download full path via stub (pypi and npm)
// ---------------------------------------------------------------------------

func TestDownload_PyPI_Mock(t *testing.T) {
	stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requests-2.31.0-py3-none-any.whl"), []byte("whl"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Download(context.Background(), "requests", "2.31.0", dir, types.EcosystemPyPI)
	if err != nil {
		t.Fatalf("Download pypi error: %v", err)
	}
	if got != dir {
		t.Errorf("Download pypi = %q, want %q", got, dir)
	}
}

func TestDownload_Npm_Mock(t *testing.T) {
	stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := Download(context.Background(), "lodash", "4.17.21", dir, types.EcosystemNpm)
	if err != nil {
		t.Fatalf("Download npm error: %v", err)
	}
	if got != dir {
		t.Errorf("Download npm = %q, want %q", got, dir)
	}
}

// ---------------------------------------------------------------------------
// DownloadAll — sandbox stubbed
// ---------------------------------------------------------------------------

func TestDownloadAll_Mock(t *testing.T) {
	rec := stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	targets := []string{"requests==2.31.0", "flask==3.0.0"}

	err := DownloadAll(context.Background(), targets, dir)
	if err != nil {
		t.Fatalf("DownloadAll error: %v", err)
	}
	// All targets go into the single pip invocation.
	for _, target := range targets {
		if !slices.Contains(rec.lastCommand, target) {
			t.Errorf("runInSandbox command = %v, want it to contain %q", rec.lastCommand, target)
		}
	}
}

func TestDownloadAll_SandboxError(t *testing.T) {
	stubRunInSandbox(t, []byte("pip err"), errors.New("download command failed"))

	err := DownloadAll(context.Background(), []string{"requests==2.31.0"}, t.TempDir())
	if err == nil {
		t.Error("expected error when the download sandbox fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// DownloadAllNpm — sandbox stubbed
// ---------------------------------------------------------------------------

func TestDownloadAllNpm_Mock(t *testing.T) {
	stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	// Create node_modules so the post-install check passes.
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}

	deps := map[string]string{
		"lodash":  "4.17.21",
		"express": "4.18.2",
	}

	err := DownloadAllNpm(context.Background(), deps, dir)
	if err != nil {
		t.Fatalf("DownloadAllNpm error: %v", err)
	}

	// Verify package.json was created.
	pkgJSON := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(pkgJSON)
	if err != nil {
		t.Fatalf("reading package.json: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("package.json is not valid JSON: %v", err)
	}

	if parsed["name"] != "kojuto-staging" {
		t.Errorf("package.json name = %v, want %q", parsed["name"], "kojuto-staging")
	}

	depsMap, ok := parsed["dependencies"].(map[string]interface{})
	if !ok {
		t.Fatal("package.json dependencies is not a map")
	}
	if depsMap["lodash"] != "4.17.21" {
		t.Errorf("dependencies[lodash] = %v, want %q", depsMap["lodash"], "4.17.21")
	}
}

func TestDownloadAllNpm_NoNodeModules(t *testing.T) {
	stubRunInSandbox(t, nil, nil)

	dir := t.TempDir()
	deps := map[string]string{"lodash": "*"}

	err := DownloadAllNpm(context.Background(), deps, dir)
	if err == nil {
		t.Error("expected error when node_modules not created, got nil")
	}
}
