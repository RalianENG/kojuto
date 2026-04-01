package downloader

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	validPkgName = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)
	validVersion = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.*!+_-]*$`)
)

// ValidatePackage checks that the package name and version are safe.
func ValidatePackage(pkg, version string) error {
	if !validPkgName.MatchString(pkg) {
		return fmt.Errorf("invalid package name: %q", pkg)
	}
	if version != "" && !validVersion.MatchString(version) {
		return fmt.Errorf("invalid version: %q", version)
	}
	return nil
}

// Download fetches a PyPI package to destDir using pip download.
// Returns the directory containing downloaded files.
func Download(ctx context.Context, pkg, version, destDir string) (string, error) {
	if err := ValidatePackage(pkg, version); err != nil {
		return "", err
	}

	target := pkg
	if version != "" {
		target = fmt.Sprintf("%s==%s", pkg, version)
	}

	args := []string{"download", "--no-deps", "--only-binary=:all:", "-d", destDir, target}
	cmd := exec.CommandContext(ctx, "pip", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("pip download failed: %w", err)
	}

	entries, err := os.ReadDir(destDir)
	if err != nil {
		return "", fmt.Errorf("reading download dir: %w", err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("no files downloaded for %s", pkg)
	}

	return destDir, nil
}

// DetectVersion tries to extract the version from downloaded filenames.
func DetectVersion(destDir, pkg string) string {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name := e.Name()
		// wheel: pkg-1.0.0-py3-none-any.whl
		// sdist: pkg-1.0.0.tar.gz
		prefix := strings.ReplaceAll(pkg, "-", "_") + "-"
		if idx := strings.Index(strings.ToLower(name), strings.ToLower(prefix)); idx == 0 {
			rest := name[len(prefix):]
			// extract version: everything before next '-' or '.tar'
			for i, c := range rest {
				if c == '-' || strings.HasPrefix(rest[i:], ".tar") {
					return rest[:i]
				}
			}
			ext := filepath.Ext(rest)
			return strings.TrimSuffix(rest, ext)
		}
	}
	return ""
}
