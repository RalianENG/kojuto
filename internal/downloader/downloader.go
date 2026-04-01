package downloader

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Download fetches a PyPI package to destDir using pip download.
// Returns the directory containing downloaded files.
func Download(ctx context.Context, pkg, version, destDir string) (string, error) {
	target := pkg
	if version != "" {
		target = fmt.Sprintf("%s==%s", pkg, version)
	}

	args := []string{"download", "--no-deps", "-d", destDir, target}
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
