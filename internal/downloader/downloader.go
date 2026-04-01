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

	// Always request Linux-compatible wheels so the sandbox container (Linux)
	// can install them, even when the host is Windows or macOS.
	// This does NOT introduce a new fingerprint inside the container — the
	// container always runs Linux, so Linux wheels are the expected norm.
	// The --platform flags are only visible in the host-side pip process,
	// which is outside the strace monitoring scope.
	// Download with dependencies — supply chain attacks like the axios
	// incident show that compromised deps must be monitored too.
	// All downloaded packages will be installed under strace in the sandbox.
	args := []string{
		"download", "--only-binary=:all:",
		"--platform", "manylinux2014_x86_64",
		"--platform", "manylinux_2_17_x86_64",
		"--platform", "linux_x86_64",
		"--platform", "any",
		"--implementation", "cp",
		"--python-version", "312",
		"--abi", "cp312",
		"--abi", "abi3",
		"--abi", "none",
		"-d", destDir,
		target,
	}
	cmd := exec.CommandContext(ctx, "pip", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("pip download failed: %w", err)
	}

	return verifyDownload(destDir, pkg)
}

func downloadNpm(ctx context.Context, pkg, version, destDir string) (string, error) {
	// Create a staging project with the target as a dependency.
	// npm install --ignore-scripts resolves the full dep tree on the host
	// without running any lifecycle scripts. The resulting node_modules is
	// then mounted into the sandbox container, where lifecycle scripts
	// (preinstall, postinstall, etc.) are re-executed under strace.
	pkgData := map[string]interface{}{
		"name":         "kojuto-staging",
		"private":      true,
		"dependencies": map[string]string{pkg: versionOrLatest(version)},
	}
	pkgJSON, err := json.Marshal(pkgData)
	if err != nil {
		return "", fmt.Errorf("marshalling staging package.json: %w", err)
	}

	if err := os.WriteFile(filepath.Join(destDir, "package.json"), pkgJSON, 0o644); err != nil {
		return "", fmt.Errorf("writing staging package.json: %w", err)
	}

	cmd := exec.CommandContext(ctx, "npm", "install", "--ignore-scripts")
	cmd.Dir = destDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("npm install (host staging) failed: %w", err)
	}

	// Verify node_modules was created.
	nmDir := filepath.Join(destDir, "node_modules")
	if _, err := os.Stat(nmDir); err != nil {
		return "", fmt.Errorf("node_modules not created for %s", pkg)
	}

	return destDir, nil
}

func versionOrLatest(version string) string {
	if version != "" {
		return version
	}
	return "*"
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
