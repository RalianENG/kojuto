# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0]

### Added
- npm ecosystem support (`-e npm`)
- `sendmsg` syscall monitoring (strace parser + event type)
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