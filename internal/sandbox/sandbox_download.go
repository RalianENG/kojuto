package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// DownloadOutMountPath is where the host staging directory is bind-mounted
// inside the download container. pip writes wheels here via `-d`; npm
// extracts node_modules here when this is the working directory. Exported so
// the downloader can build registry commands that target this path.
const DownloadOutMountPath = "/out"

// downloadKeepAliveSeconds is how long the download container's sleep
// entrypoint stays alive. Generous so large dependency trees finish; the
// container is removed by Cleanup well before this elapses.
const downloadKeepAliveSeconds = "1800"

// DownloadSandbox is a hardened, network-enabled container used to fetch
// packages from a registry. It exists so registry downloads — which run
// package-manager code (pip, npm) against attacker-controlled metadata,
// dependency graphs, and archive contents (tarball extraction is a real
// path-traversal surface) — never execute on the host.
//
// It differs from the analysis Sandbox in exactly two ways:
//
//   - It HAS network egress (Docker's default bridge) and real DNS: it
//     must reach the registry and resolve registry hostnames. The
//     analysis sandbox, by contrast, runs with no usable network.
//   - It plants no honeypots, stages no probe scripts, and does not mask
//     /.dockerenv: the download phase does not execute the scanned
//     package's own code, so the anti-fingerprinting machinery aimed at
//     sandbox-aware payloads is unnecessary here.
//
// Every other isolation control — read-only rootfs, cap-drop=ALL,
// no-new-privileges, the restrictive seccomp profile, pids-limit,
// memory/cpu caps, and the kojuto.scan label so orphans are reaped by
// CleanupStaleSandboxContainers — is identical to the analysis sandbox.
// A compromise of the download phase (an exploited pip/npm parser, a
// path-traversal during tarball extraction) is contained to this
// ephemeral container instead of running on the host.
type DownloadSandbox struct {
	containerID string
	hostOutDir  string
	seccompDir  string
}

// NewDownloadSandbox returns a DownloadSandbox that bind-mounts hostOutDir
// (writable) at DownloadOutMountPath inside the container. The caller
// stages any inputs (e.g. an npm staging package.json) into hostOutDir
// before Start and reads the downloaded artifacts back from it after.
func NewDownloadSandbox(hostOutDir string) *DownloadSandbox {
	return &DownloadSandbox{hostOutDir: hostOutDir}
}

// ContainerID returns the download container's ID, valid between Start and
// Cleanup. The probe layer uses it to attach strace to the download phase.
func (d *DownloadSandbox) ContainerID() string { return d.containerID }

// createArgs builds the `docker create` argument list for the download
// container. seccompOpt is the `seccomp=<path>` value from writeSeccompFile.
// Every hardening control here is identical to the analysis sandbox; the
// deliberate difference is that network egress is left at Docker's default
// (no --network=none) so pip/npm can reach the registry.
func (d *DownloadSandbox) createArgs(seccompOpt string) []string {
	cpus, mem := getHostResources()
	return []string{
		"create",
		// Reaped by CleanupStaleSandboxContainers if a crash skips Cleanup.
		"--label=" + SandboxContainerLabel + "=true",
		"--security-opt=no-new-privileges",
		"--security-opt=" + seccompOpt,
		"--read-only",
		"--cap-drop=ALL",
		// SYS_PTRACE is required so strace can attach to the traced pip/npm
		// process inside this container. Without it strace fails with EPERM
		// on the initial ptrace(PTRACE_ATTACH), the traced command never runs,
		// and the download exits with a non-zero status. Mirrors the analysis
		// sandbox's re-add for needsPtrace=true; the seccomp profile still
		// blocks the cross-process ptrace surface (process_vm_readv /
		// process_vm_writev), so the added capability cannot be abused to
		// read another process's memory.
		"--cap-add=SYS_PTRACE",
		"--tmpfs=/tmp:nosuid,mode=1777,size=100m",
		"--tmpfs=/home/dev:nosuid,mode=1777,size=64m",
		// Package-manager caches. The analysis sandbox pins these here too;
		// kept off the read-only rootfs and out of the bind-mounted /out.
		"--tmpfs=/var/cache/kojuto:nosuid,mode=1777,size=512m",
		"--env=NPM_CONFIG_CACHE=/var/cache/kojuto/npm",
		"--env=PIP_CACHE_DIR=/var/cache/kojuto/pip",
		"--memory=" + mem,
		"--cpus=" + cpus,
		"--pids-limit=256",
		// Writable handoff: pip/npm write artifacts here, the analysis
		// sandbox reads them next. The container sees only this path, not
		// the host filesystem.
		"-v", d.hostOutDir + ":" + DownloadOutMountPath,
		SandboxImage,
		"sleep", downloadKeepAliveSeconds,
	}
}

// Start creates and starts the download container.
func (d *DownloadSandbox) Start(ctx context.Context) error {
	seccompOpt, seccompDir, err := writeSeccompFile()
	if err != nil {
		return err
	}
	d.seccompDir = seccompDir

	// The sandbox image runs as USER dev (UID 1000). The host staging
	// directory is bind-mounted at /out; without world-writable perms the
	// dev user inside the container cannot save downloaded wheels to it.
	// Under `sudo ./kojuto` on Linux (the CI integration path) the host
	// dir is owned by root, so pip.download errors with:
	//   PermissionError: [Errno 13] Permission denied: '/out/*.whl'
	// Docker Desktop on Windows/macOS masks this by translating host
	// permissions on bind mounts, which is why local scans succeeded.
	// chmod 0777 is safe here — the directory is a per-scan tempdir the
	// caller owns and cleans up; nothing sensitive shares it.
	if chmodErr := os.Chmod(d.hostOutDir, 0o777); chmodErr != nil {
		return fmt.Errorf("chmod host staging dir for download sandbox: %w", chmodErr)
	}

	cmd := execCommand(ctx, "docker", d.createArgs(seccompOpt)...)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("docker create (download sandbox): %w", err)
	}
	d.containerID = strings.TrimSpace(string(out))

	startCmd := execCommand(ctx, "docker", "start", d.containerID)
	startCmd.Stdout = io.Discard
	startCmd.Stderr = io.Discard
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("docker start (download sandbox): %w", err)
	}
	return nil
}

// Run executes command inside the download container with the working
// directory set to DownloadOutMountPath, returning combined output. Used
// for the plain (un-traced) download path; the strace-wrapped path drives
// the same container via its ContainerID.
func (d *DownloadSandbox) Run(ctx context.Context, command []string) ([]byte, error) {
	if d.containerID == "" {
		return nil, errors.New("download sandbox not started")
	}
	args := append([]string{"exec", "--workdir=" + DownloadOutMountPath, d.containerID}, command...)
	cmd := execCommand(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("download command failed: %w", err)
	}
	return out, nil
}

// Cleanup stops and removes the download container and clears temp files.
// Safe to call on a partially-started sandbox.
func (d *DownloadSandbox) Cleanup(ctx context.Context) error {
	if d.seccompDir != "" {
		os.RemoveAll(d.seccompDir)
		d.seccompDir = ""
	}
	if d.containerID == "" {
		return nil
	}
	cmd := execCommand(ctx, "docker", "rm", "-f", d.containerID)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker cleanup (download sandbox): %w", err)
	}
	d.containerID = ""
	return nil
}
