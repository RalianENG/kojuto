package downloader

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RalianENG/kojuto/internal/types"
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

// Download fetches a package to destDir.
// Ecosystem determines which package manager is used (pypi or npm).
func Download(ctx context.Context, pkg, version, destDir, ecosystem string) (string, error) {
	if err := ValidatePackage(pkg, version); err != nil {
		return "", err
	}

	switch ecosystem {
	case types.EcosystemPyPI:
		return downloadPyPI(ctx, pkg, version, destDir)
	case types.EcosystemNpm:
		return downloadNpm(ctx, pkg, version, destDir)
	default:
		return "", fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
}

func downloadPyPI(ctx context.Context, pkg, version, destDir string) (string, error) {
	target := pkg
	if version != "" {
		target = pkg + "==" + version
	}

	args := []string{"download", "--no-deps", "--only-binary=:all:", "-d", destDir, target}
	cmd := exec.CommandContext(ctx, "pip", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("pip download failed: %w", err)
	}

	return verifyDownload(destDir, pkg)
}

func downloadNpm(ctx context.Context, pkg, version, destDir string) (string, error) {
	target := pkg
	if version != "" {
		target = pkg + "@" + version
	}

	// npm pack downloads a tarball to the current directory.
	args := []string{"pack", "--pack-destination", destDir, target}
	cmd := exec.CommandContext(ctx, "npm", args...)
	cmd.Dir = destDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("npm pack failed: %w", err)
	}

	return verifyDownload(destDir, pkg)
}

func verifyDownload(destDir, pkg string) (string, error) {
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

		// Try npm tarball: <scope-stripped>-<version>.tgz
		if strings.HasSuffix(name, ".tgz") {
			return detectVersionFromTgz(name, pkg)
		}

		// Try PyPI wheel/sdist
		prefix := strings.ReplaceAll(pkg, "-", "_") + "-"
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			return detectVersionFromPyPI(name, prefix)
		}
	}

	return ""
}

func detectVersionFromPyPI(name, prefix string) string {
	rest := name[len(prefix):]

	for i, c := range rest {
		if c == '-' || strings.HasPrefix(rest[i:], ".tar") {
			return rest[:i]
		}
	}

	ext := filepath.Ext(rest)

	return strings.TrimSuffix(rest, ext)
}

func detectVersionFromTgz(name, pkg string) string {
	// npm tarball: package-name-1.2.3.tgz
	base := strings.TrimSuffix(name, ".tgz")
	// Strip scope: @scope-package-name -> package-name
	cleanPkg := pkg
	if idx := strings.Index(cleanPkg, "/"); idx >= 0 {
		cleanPkg = cleanPkg[idx+1:]
	}

	prefix := cleanPkg + "-"
	if strings.HasPrefix(base, prefix) {
		return base[len(prefix):]
	}

	return ""
}

// DetectNpmVersion reads version from package.json inside the npm tarball directory.
func DetectNpmVersion(destDir string) string {
	pkgJSON := filepath.Join(destDir, "package", "package.json")

	data, err := os.ReadFile(pkgJSON)
	if err != nil {
		return ""
	}

	var parsed struct {
		Version string `json:"version"`
	}

	if jsonErr := json.Unmarshal(data, &parsed); jsonErr != nil {
		return ""
	}

	return parsed.Version
}
