package downloader

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

// ---------------------------------------------------------------------------
// Mock exec command using TestHelperProcess pattern
// ---------------------------------------------------------------------------

func fakeExecCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", name}
	cs = append(cs, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	os.Exit(0)
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
// downloadPyPI — mocked exec
// ---------------------------------------------------------------------------

func TestDownloadPyPI_Mock(t *testing.T) {
	origCmd := execCommand
	execCommand = fakeExecCommand
	defer func() { execCommand = origCmd }()

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
}

func TestDownloadPyPI_NoVersion(t *testing.T) {
	origCmd := execCommand
	execCommand = fakeExecCommand
	defer func() { execCommand = origCmd }()

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
}

func TestDownloadPyPI_EmptyDir(t *testing.T) {
	origCmd := execCommand
	execCommand = fakeExecCommand
	defer func() { execCommand = origCmd }()

	dir := t.TempDir()
	// No files — verifyDownload should fail.
	_, err := downloadPyPI(context.Background(), "pkg", "1.0.0", dir)
	if err == nil {
		t.Error("expected error for empty download dir, got nil")
	}
}

// ---------------------------------------------------------------------------
// downloadNpm — mocked exec
// ---------------------------------------------------------------------------

func TestDownloadNpm_Mock(t *testing.T) {
	origCmd := execCommand
	execCommand = fakeExecCommand
	defer func() { execCommand = origCmd }()

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
}

func TestDownloadNpm_NoVersion(t *testing.T) {
	origCmd := execCommand
	execCommand = fakeExecCommand
	defer func() { execCommand = origCmd }()

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
}

func TestDownloadNpm_NoNodeModules(t *testing.T) {
	origCmd := execCommand
	execCommand = fakeExecCommand
	defer func() { execCommand = origCmd }()

	dir := t.TempDir()
	// Don't create node_modules — should error.
	_, err := downloadNpm(context.Background(), "lodash", "4.17.21", dir)
	if err == nil {
		t.Error("expected error when node_modules not created, got nil")
	}
}

// ---------------------------------------------------------------------------
// Download full path via mock (pypi and npm)
// ---------------------------------------------------------------------------

func TestDownload_PyPI_Mock(t *testing.T) {
	origCmd := execCommand
	execCommand = fakeExecCommand
	defer func() { execCommand = origCmd }()

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
	origCmd := execCommand
	execCommand = fakeExecCommand
	defer func() { execCommand = origCmd }()

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
