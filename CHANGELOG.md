# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0]

### Added
- **Anti-debugging evasion detection** — `ptrace(PTRACE_TRACEME)` calls parsed from strace output and classified as `evasion` category (risk: high)
- **`--strict` flag** — ignores `sensitive_paths.exclude` from `kojuto.yml`, preventing config-based detection bypass; enabled by default in the GitHub Action
- **Known Limitations** section in README and SECURITY.md documenting out-of-scope attack vectors (memory-only execution, low-entropy DNS tunneling, environment variable reads)

### Changed
- **Dockerfile hardening** — replaced NodeSource `curl | bash` with multi-stage `COPY` from digest-pinned `node:20-slim` official image; removed unpinned `pip install pip setuptools wheel` (base image versions used as-is)
- **GitHub Action SHA pinning** — usage examples reference full commit SHA instead of mutable `@v0` tag, with Dependabot config for automated updates
- **Randomized faketime offset** — `libfaketime` shift randomized to +30–180 days per scan (was fixed +30d) to prevent hardcoded bypass; upper bound avoids TLS certificate expiry
- **Shell command sensitive path check** — `isShellCmdBenign` now flags commands whose arguments reference sensitive paths (e.g. `cat ~/.ssh/id_rsa`, `grep -r . ~/.aws/`), closing a gap where `shellSafeCommands` allowed credential reads via benign binaries
- GitHub Action `strict` input defaults to `true` (breaking: existing `sensitive_paths.exclude` configs are ignored in CI unless `strict: false` is set)

### Fixed
- `shellSafeCommands` bypass: `cat`, `grep`, `head`, `tail` could read credential files without triggering execve-level detection

### Security
- Low-entropy DNS tunneling evasion documented as design tradeoff (entropy threshold vs false positive rate; network isolation limits practical impact)
- Memory-only execution (`mmap` + `PROT_EXEC`) documented as known limitation (network isolation and read-only rootfs limit impact; `--runtime runsc` recommended for additional protection)

## [0.4.0]

### Added
- **Configurable sensitive paths** — `kojuto.yml` config file with `include`/`exclude` for user-customizable sensitive path monitoring; `--config` flag to specify config location
- **Sensitive path expansion (9 → ~40 patterns)** — cloud CLI (`.azure/`, `.config/gcloud/`, `.kube/config`), environment files (`.env`, `.env.local`), browser data (`google-chrome/`, `firefox/`), shell startup files (`.bashrc`, `.zshrc`, `.profile`), keyrings, app tokens (Slack, Discord, Terraform, Vault)
- **DoH tunneling detection** — connections to known DNS-over-HTTPS servers (Google, Cloudflare, Quad9, OpenDNS, NextDNS) on port 443 classified as `dns_tunneling`
- **Fileless execution detection** — `execve` from `/dev/shm/` and `/proc/self/fd/` paths always flagged as suspicious regardless of binary name
- **Persistence monitoring** — `openat` with `O_WRONLY`/`O_RDWR` to shell startup files (`.bashrc`, `.zshrc`, `.profile`, `crontab`) classified as `persistence` (risk: high)
- **Attack category classification** — each suspicious event enriched with `category` and `reason` fields: `c2_communication`, `credential_access`, `code_execution`, `binary_hijacking`, `backdoor`, `persistence`, `dns_tunneling`, `data_exfiltration`
- **Report summary** — `summary` field with `risk_level` (critical/high/medium/none), `categories`, human-readable `description`, and actionable `remediation` guidance
- **Batch screening mode** — `scan -f` now installs all packages in a single sandbox for fast screening; falls back to per-package scan only when suspicious activity detected. 50 PyPI packages in ~30s (was ~3 hours)
- **Batch download** — `DownloadAll` (PyPI) and `DownloadAllNpm` for single-invocation batch downloads
- **Combined import scripts** — one import probe script per OS identity instead of per-package, reducing Python/Node launches from N×3 to 3
- **npm direct mount** — npm `node_modules` mounted writable directly (skip `cp -a` copy step), cutting npm batch scan time in half
- `kojuto.example.yml` — sample config file with all default paths documented

### Changed
- Sensitive path detection expanded from 9 hardcoded patterns to ~40 configurable defaults covering credentials, cloud configs, browser data, shell startup files, and application tokens
- `openat` events now distinguished by access mode: `O_RDONLY` → `credential_access`, `O_WRONLY`/`O_RDWR` to startup files → `persistence`
- Default batch mode (`-f`) changed from per-package to single-sandbox screening with automatic fallback
- npm `InstallAllCommand` targets only specified packages (not all transitive deps) for faster rebuild
- `.tar.gz` auto-detection no longer overrides explicit `-e pypi` (fixes PyPI source distribution scanning)
- Event buffer increased from 256 to 8192 with non-blocking overflow to prevent deadlock in large batch scans
- Detection benchmarks updated: 300 randomly sampled malicious packages from Datadog dataset (61/61 detected, 0/70 FP)

### Fixed
- Local scan (`--local`) with source distributions (`.tar.gz`) now uses `--no-build-isolation` for sdist support

## [0.3.0]

### Added
- GitHub Action: `ecosystem`, `file`, `pin`, `local`, `runtime`, `timeout` inputs added to match full CLI capability; supports single, batch, and local scan modes
- Cosign keyless signing for release checksums via GitHub OIDC (no GPG key management required)
- `CONTRIBUTING.md` with development setup, commit conventions, syscall addition checklist, and release verification guide
- `make help` target listing all available Makefile commands
- CLI help: detailed `--help` output with prerequisites, long description, and usage examples for the `scan` command
- Actionable error hints for missing Docker, pip/npm, timeout, and invalid input scenarios
- Comprehensive unit test suite with mock infrastructure (TestHelperProcess pattern) — coverage 25% → 81%
- Build-time version injection via ldflags (`kojuto version` now shows commit and build date)
- `openat` syscall monitoring for sensitive file access detection (`.ssh/`, `.aws/`, `/etc/shadow`, `/proc/self/environ`, `.netrc`, `.git-credentials`, `.docker/config.json`, `.config/gh/`)
- `rename`/`renameat`/`renameat2` syscall monitoring to detect trusted binary hijacking
- `sendfile` added to strace trace list for forensic completeness
- `SrcPath`/`DstPath` fields for rename events; `OpenFlags` field for openat events
- Honeypot environment simulation: fake credential files (SSH, AWS, Git, netrc, GitHub CLI) and CI/cloud environment variables planted in sandbox to trigger harvesting malware
- All honeypot tokens randomly generated per scan via `crypto/rand` to prevent static fingerprinting
- `libfaketime` integration: import probes run with `FAKETIME=+30d` to trigger date-gated payloads
- eBPF probe expanded with 4 new kprobes: `__sys_sendto`, `do_execveat_common`, `do_sys_openat2`, `vfs_rename`
- Separate perf buffer for file events in eBPF mode; best-effort probe attachment for non-critical kprobes
- `--pin` flag for generating version-pinned dependency files after all-clean batch scans (PyPI: `pkg==version`, npm: pinned `package.json`)
- `--local` flag for scanning local package files (`.whl`, `.tgz`) or directories without downloading from registries
- Local npm `.tgz` scanning with automatic `node_modules` staging via `npm install --ignore-scripts`
- axios/plain-crypto-js attack simulation package in `testdata/` for detection validation
- `--runtime` flag for gVisor (`runsc`) container runtime support, masking `/proc/1/cgroup` and `/proc/self/mountinfo`
- eBPF kprobes for `sendmsg`, `bind`, `listen`, `accept` — full syscall parity with strace-container mode
- `scripts/setup-caps.sh` to grant `CAP_BPF` + `CAP_PERFMON` for sudo-free eBPF operation
- DNS tunneling detection: extract query domains from `sendto` payloads and flag high-entropy subdomains via Shannon entropy analysis
- `DNSQuery` field in `SyscallEvent` for DNS query domain visibility in reports
- Benign DNS suffix exclusions for package registries (`pypi.org`, `npmjs.org`, etc.)
- Hostname sanitization to prevent Docker CLI argument injection
- Test coverage for new parsers (openat, rename), analyzer (rename trusted binary, openat, bind/listen/accept), and sandbox (honeypot token generation, sanitizeDockerArg)

### Changed
- Documentation (README, Japanese docs, SPECIFICATION) updated to list all 13 monitored syscalls including `sendmmsg`, `bind`, `listen`, `accept`/`accept4`, `renameat`/`renameat2`, `sendfile`
- `openat` sensitive path documentation expanded to include all 9 monitored paths (`.gnupg/`, `/proc/self/environ`, `.netrc`, `.docker/config.json`, `.config/gh/`)
- GitHub Action README examples expanded to show batch and local scanning modes
- Version string no longer hardcoded; injected at build time by GoReleaser
- Removed unused `.golangci.bck.yml`
- Custom seccomp profile is now always applied regardless of `--probe-method` (previously only applied when strace needed SYS_PTRACE)
- `seccompDir` moved from global variable to per-`Sandbox` struct field (fixes race condition in concurrent scans)
- `/usr/local/bin` tmpfs permissions tightened from `mode=1777` to `mode=0755`
- npm `package.json` generation now uses `json.Marshal` instead of `fmt.Sprintf` (prevents JSON injection)
- eBPF probe description updated from "connect-only" to multi-syscall coverage
- Import phase commands wrapped with `libfaketime` (install phase uses real time)

### Security
- `memfd_create` added to seccomp blocklist (prevents fileless ELF execution bypassing noexec tmpfs)
- seccomp profile enforced unconditionally (closes escape vectors via `memfd_create`, `userfaultfd`, `open_by_handle_at` in eBPF mode)

## [0.2.0]

### Added
- Batch scan from dependency files (`-f requirements.txt`, `-f package.json`)
- Dependency file parser supporting `*.txt` (pip) and `*.json` (npm) formats
- npm ecosystem support (`-e npm`)
- `sendmsg`, `sendmmsg`, `bind`, `listen`, `accept` syscall monitoring
- Transitive dependency scanning (removed `--no-deps` from pip/npm)
- Cross-platform pip download (`--platform manylinux2014_x86_64` for Windows/macOS hosts)
- 2-phase scan: install monitoring + import/require monitoring
- Multi-OS import probing: simulate Linux, Windows, macOS identities to defeat platform-gated payloads
- `sh -c` command content inspection with `shellSafeCommands` whitelist
- `interpreterExecFlags` to detect `python3 -c` / `node -e` inline code execution
- Custom seccomp profile blocking `prctl(PR_SET_NAME)`, `memfd_create`, `unshare`, `setns`, and 40+ dangerous syscalls
- Exit code 2 for both suspicious and inconclusive verdicts
- `.dockerignore` to prevent leaking files into Docker build context

### Changed
- Default probe method changed from eBPF to `strace-container` for broader syscall coverage
- Sandbox network changed from `--network=none` to isolated internal bridge (anti-fingerprint: `ETIMEDOUT` instead of `ENETUNREACH`)
- Container hostname, username, CPU, and memory now mirror the host system
- Package mount path mirrors host directory layout (`/home/<user>/projects`)
- `/.dockerenv` removed on container start
- Container user renamed from `scanner` to `dev` (uid 1000)
- `--read-only` filesystem with targeted tmpfs mounts
- `--cap-drop=ALL` with selective capability re-addition
- `docker run` split into `docker create` + `docker start` to reduce TOCTOU window
- Cleanup uses independent context to prevent orphaned containers
- eBPF perf buffer increased from 64KB to ~2MB
- Docker base image pinned by digest
- `curl` removed from sandbox image after Node.js setup

### Security
- `isBenignExec` validates full binary path, not just basename (prevents `/tmp/python3` spoofing)
- `cmdline`-based filters removed; replaced with path + directory validation
- Empty `DstAddr` treated as suspicious (prevents parse-failure bypass)
- `sed` removed from benign binary list (GNU sed `e` command can execute shell)
- `pip install` arguments include `--` separator
- `npm pack` uses `--ignore-scripts` on host

## [0.1.0]

### Added
- Project scaffolding
- CLI framework with cobra
- eBPF probe for connect(2) detection
- strace fallback for non-eBPF environments
- In-container strace for cross-platform support (macOS/Windows)
- Docker sandbox with network isolation
- PyPI package downloader
- JSON report output