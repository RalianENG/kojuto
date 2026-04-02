# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0]

### Added
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