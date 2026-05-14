package downloader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RalianENG/kojuto/internal/probe"
	"github.com/RalianENG/kojuto/internal/sandbox"
	"github.com/RalianENG/kojuto/internal/types"
)

var (
	validPkgName = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)
	validVersion = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.*!+_-]*$`)
)

// runInDownloadSandbox spins up a hardened, network-enabled DownloadSandbox
// that bind-mounts hostOutDir at the container's /out, runs command inside it
// under strace, reaps the container, and returns the command output plus the
// syscall events strace captured.
//
// pip and npm run attacker-influenced code during a download — registry
// metadata parsers, dependency resolvers, tarball extractors (a real
// path-traversal surface) — so the download phase is both *contained* to
// this ephemeral container and *observed*: the events feed the analyzer's
// download-phase profile (execve out of the staging dir, writes that escape
// it, network egress).
//
// Events are drained concurrently with the traced command: the download
// phase legitimately produces many connect events (registry + CDN), and a
// consumer that only drained afterward could overflow the probe's buffer.
func runInDownloadSandbox(ctx context.Context, hostOutDir string, command []string) ([]byte, []types.SyscallEvent, error) {
	ds := sandbox.NewDownloadSandbox(hostOutDir)
	if err := ds.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("starting download sandbox: %w", err)
	}
	// Reap the container even if ctx is already canceled. Using the
	// caller's ctx here would skip cleanup on cancellation, orphaning
	// the container — context.Background() is deliberate.
	defer func() { _ = ds.Cleanup(context.Background()) }() //nolint:contextcheck // see comment above

	cp := probe.NewContainerStraceForDownload(sandbox.DownloadOutMountPath)

	var events []types.SyscallEvent
	drained := make(chan struct{})
	go func() {
		for evt := range cp.Events() {
			events = append(events, evt)
		}
		close(drained)
	}()

	out, err := cp.StartAndInstall(ctx, ds.ContainerID(), command)
	<-drained
	if err != nil {
		return out, events, fmt.Errorf("download command failed: %w", err)
	}

	// Fail closed: a dropped event could be the one that would have flagged
	// a malicious download-time syscall. Concurrent draining makes an
	// overflow effectively impossible, so a non-zero count signals
	// something pathological — treat the download as unobservable rather
	// than trusting a partial event stream.
	if dropped := cp.Dropped(); dropped > 0 {
		return out, events, fmt.Errorf("download monitoring lost %d event(s); cannot verify download safely", dropped)
	}
	return out, events, nil
}

// runInSandbox is the seam downloader tests replace so they never touch
// Docker; production points it at the real DownloadSandbox-backed runner.
var runInSandbox = runInDownloadSandbox

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

// Download fetches a package to destDir inside the download sandbox and
// returns the staging directory plus the syscall events captured while
// pip/npm ran. Ecosystem determines which package manager is used.
func Download(ctx context.Context, pkg, version, destDir, ecosystem string) (string, []types.SyscallEvent, error) {
	if err := ValidatePackage(pkg, version); err != nil {
		return "", nil, err
	}

	switch ecosystem {
	case types.EcosystemPyPI:
		return downloadPyPI(ctx, pkg, version, destDir)
	case types.EcosystemNpm:
		return downloadNpm(ctx, pkg, version, destDir)
	default:
		return "", nil, fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
}

// pypiDownloadArgs returns the common pip download arguments for
// Linux-compatible wheels. Wheels land in DownloadOutMountPath — the staging
// directory bind-mounted into the download sandbox — not a host path.
func pypiDownloadArgs() []string {
	return []string{
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
		"-d", sandbox.DownloadOutMountPath,
	}
}

// DownloadAll fetches multiple PyPI packages in a single pip invocation
// inside a download sandbox. This is significantly faster than calling
// Download for each package individually. Returns the download-phase
// syscall events for the analyzer.
func DownloadAll(ctx context.Context, targets []string, destDir string) ([]types.SyscallEvent, error) {
	args := append([]string{"pip"}, pypiDownloadArgs()...)
	args = append(args, targets...)
	out, events, err := runInSandbox(ctx, destDir, args)
	os.Stderr.Write(out)
	if err != nil {
		return events, fmt.Errorf("pip download failed: %w", err)
	}
	return events, nil
}

func downloadPyPI(ctx context.Context, pkg, version, destDir string) (string, []types.SyscallEvent, error) {
	target := pkg
	if version != "" {
		target = pkg + "==" + version
	}

	args := append([]string{"pip"}, pypiDownloadArgs()...)
	args = append(args, target)
	out, events, err := runInSandbox(ctx, destDir, args)
	os.Stderr.Write(out)
	if err != nil {
		return "", events, fmt.Errorf("pip download failed: %w", err)
	}

	dir, err := verifyDownload(destDir, pkg)
	return dir, events, err
}

// writeStagingPackageJSON writes a minimal staging package.json into destDir
// with the given dependency set. destDir is bind-mounted into the download
// sandbox, so npm install inside the container picks this up as the project
// manifest.
func writeStagingPackageJSON(destDir string, deps map[string]string) error {
	pkgData := map[string]interface{}{
		"name":         "kojuto-staging",
		"private":      true,
		"dependencies": deps,
	}
	pkgJSON, err := json.Marshal(pkgData)
	if err != nil {
		return fmt.Errorf("marshaling staging package.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "package.json"), pkgJSON, 0o644); err != nil {
		return fmt.Errorf("writing staging package.json: %w", err)
	}
	return nil
}

// DownloadAllNpm fetches multiple npm packages in a single npm install
// invocation inside a download sandbox. Returns the download-phase syscall
// events for the analyzer.
func DownloadAllNpm(ctx context.Context, deps map[string]string, destDir string) ([]types.SyscallEvent, error) {
	if err := writeStagingPackageJSON(destDir, deps); err != nil {
		return nil, err
	}
	out, events, err := runInSandbox(ctx, destDir, []string{"npm", "install", "--ignore-scripts"})
	os.Stderr.Write(out)
	if err != nil {
		return events, fmt.Errorf("npm install (batch staging) failed: %w", err)
	}
	nmDir := filepath.Join(destDir, "node_modules")
	if _, err := os.Stat(nmDir); err != nil {
		return events, errors.New("node_modules not created")
	}
	return events, nil
}

func downloadNpm(ctx context.Context, pkg, version, destDir string) (string, []types.SyscallEvent, error) {
	// Create a staging project with the target as a dependency. npm install
	// --ignore-scripts resolves the full dep tree without running any
	// lifecycle scripts. It runs inside the download sandbox because npm
	// executes attacker-controlled registry metadata and unpacks
	// attacker-controlled tarballs. The resulting node_modules is then
	// mounted into the analysis sandbox, where lifecycle scripts (preinstall,
	// postinstall, etc.) are re-executed under strace.
	if err := writeStagingPackageJSON(destDir, map[string]string{pkg: versionOrLatest(version)}); err != nil {
		return "", nil, err
	}

	out, events, err := runInSandbox(ctx, destDir, []string{"npm", "install", "--ignore-scripts"})
	os.Stderr.Write(out)
	if err != nil {
		return "", events, fmt.Errorf("npm install (sandbox staging) failed: %w", err)
	}

	// Verify node_modules was created.
	nmDir := filepath.Join(destDir, "node_modules")
	if _, err := os.Stat(nmDir); err != nil {
		return "", events, fmt.Errorf("node_modules not created for %s", pkg)
	}

	return destDir, events, nil
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
