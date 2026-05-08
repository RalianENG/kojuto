//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestOpenOutput_FileMode pins the 0o600 contract for the main scan
// report file. Reports embed attacker-supplied code snippets, file
// paths, and the dependency tree of the scanned package; on a multi-
// user host that data must not be readable by other accounts. The
// test runs under syscall.Umask(0) so the assertion measures the
// requested mode rather than the user's umask-clipped result.
//
// Windows has no umask and no Unix-style permission bits, and Go's
// os.File.Mode().Perm() reports a synthetic 0o666/0o444 there, so
// this test lives in a !windows build-tagged file.
func TestOpenOutput_FileMode(t *testing.T) {
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	original := flagOutput
	defer func() { flagOutput = original }()

	dir := t.TempDir()
	flagOutput = filepath.Join(dir, "test-output.json")

	f, err := openOutput()
	if err != nil {
		t.Fatalf("openOutput() error: %v", err)
	}
	defer f.Close()

	info, err := os.Stat(flagOutput)
	if err != nil {
		t.Fatalf("output file was not created: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("output file mode = %o, want 0o600", mode)
	}
}

// TestOutputFiles_OwnerOnly pins the 0o600 contract for both pinned-
// manifest writers — they share the same threat model as the main
// report (multi-user host, package metadata leakage).
func TestOutputFiles_OwnerOnly(t *testing.T) {
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	dir := t.TempDir()
	deps := []pinnedDep{{Name: "lodash", Version: "4.17.21"}}

	pyPath := filepath.Join(dir, "requirements.txt")
	if err := writePinnedPyPI(pyPath, deps); err != nil {
		t.Fatalf("writePinnedPyPI: %v", err)
	}
	pyInfo, err := os.Stat(pyPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := pyInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("pinned requirements.txt mode = %o, want 0o600", mode)
	}

	npmPath := filepath.Join(dir, "package.json")
	if writeErr := writePinnedNpm(npmPath, deps); writeErr != nil {
		t.Fatalf("writePinnedNpm: %v", writeErr)
	}
	npmInfo, err := os.Stat(npmPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := npmInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("pinned package.json mode = %o, want 0o600", mode)
	}
}
