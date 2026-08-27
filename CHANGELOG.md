# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Import-phase reality check + `VerdictInconclusive`** — the sandbox now proves that the target package was actually imported (not just pip-resolved) by emitting a `KOJUTO:import_attempt:<dist>:<module>:<result>` audit-hook event for each attempt. Python resolves dist→module names via `importlib.metadata` (`top_level.txt`, falling back to file-walk of the installed dist, then to the canonical name) so packages whose distribution name differs from their import name — pillow→PIL, pyyaml→yaml, opencv-python→cv2, python-dateutil→dateutil, beautifulsoup4→bs4 — are actually imported instead of silently no-oping via `__import__("pillow")` ModuleNotFoundError. Node.js tries `require()` first and falls back to dynamic `import()` on ERR_REQUIRE_ESM. The analyzer counts attempts vs. successes and returns the new `VerdictInconclusive` when the sandbox tried imports but none succeeded AND no HIGH-severity event was independently observed — instead of falsely reporting `clean` on packages that failed to install. HIGH-severity findings (network exfil, credential access, library hijacking) still flip the verdict to SUSPICIOUS even when every import failed, so an install-time attack that crashes before import completes is not masked. Closes the silent-no-op gap that let dist-name≠module-name typosquat targets appear clean whenever the sandbox's naive `pkg.replace("-","_")` guess didn't match the actual module.
- **`library_hijacking` for PyPI** — closes the follow-up to the npm-side rule. Fires when the scanned package writes into another installed PyPI package's `site-packages/<other_pkg>/` directory with `O_APPEND` set. The append-flag discriminator cleanly separates attacker "add backdoor to existing `__init__.py`" from pip's normal wheel extraction (which uses `O_WRONLY|O_CREAT|O_TRUNC`, never `O_APPEND`) — so pip installs never trip the rule, no whitelist required. The parser layer (`isInstalledPackageWrite`) applies the O_APPEND gate for PyPI paths, so pip's install-time writes never even reach the analyzer; the analyzer layer (`classifyOpenat`) then checks the cross-package condition and fires `CategoryLibraryHijack` HIGH. `extractPyPISitePackage` extracts the target package name (rejects `__pycache__`, `*.dist-info`, `*.egg-info` pip bookkeeping) and matches against the scan-target set to distinguish self-writes from hijacks. Overwrite-based hijack (`O_TRUNC` over an existing file) remains a follow-up — it needs pre-write file-existence correlation.
- **Sandbox container auto-cleanup** — every container kojuto creates carries the `kojuto.scan=true` Docker label. At each scan startup, `sandbox.CleanupStaleSandboxContainers` removes labeled containers in non-running states (`exited`, `created`, `dead`) before creating the new sandbox. Concurrent kojuto invocations are protected: running and paused containers belonging to other live scans are filtered out and never touched. Failures are logged but do not abort the scan — the next scan still runs. SIGINT and SIGTERM both trigger the existing Cleanup defer; SIGKILL'd kojuto instances leave their containers in `running` state and are NOT swept by this pass (documented limitation; `docker rm -f` is the manual recovery and the typical "100 leaked containers from a crashed dev session" pain is solved for every other failure mode).
- **`library_hijacking` detection** — new `CategoryLibraryHijack` (HIGH) fires when the scanned package writes into another installed npm package's source tree (`/install/node_modules/<other_pkg>/...` where `<other_pkg>` is not in the scan target set). The hijacked package's source gets backdoored; harm fires when a later workflow imports the package, outside kojuto's scan window — placement is the only opportunity to detect this attack class. The rule complements static analyzers (which catch obvious AST patterns) by also catching runtime-decoded target paths that source-level inspection cannot resolve.
  - `analyzer.SetScanPkgs(pkgs)` records the package set and is called from `cmd/root.go` alongside the existing `sandbox.SetScanPkgs`. When the set is empty (no setter call), the rule is inert so older code paths and tests are unaffected.
  - `extractNpmInstalledPkg` extracts the target package identifier from the openat path, handling scoped (`@scope/name`) and non-scoped packages and skipping npm's own bookkeeping entries (`.package-lock.json`, `.bin/`, `.cache/`).
  - The parser's `parseOpenat` now emits events for writes into `/install/node_modules/<pkg>/...` so the analyzer can apply the rule. `isBenignInstalledPackageWrite` filters self-pkg writes (legitimate build output like `argon2/build/Release/argon2.node`) and npm bookkeeping at the `isBenign` layer, so only cross-package writes reach the classifier. The PyPI side (`/usr/local/lib/python*/site-packages/`) is intentionally out of scope for this rule — pip's wheel extraction during install legitimately writes many files across many package directories and needs a different discriminator; tracked as follow-up.
- **`CategoryUnknownBinary` (severity LOW)** — execve events that do not match a positively-defined attack signature are recorded under this new category for forensic chain visibility without flipping the verdict. Covers the residual default branch of `classifyExecve` AND `sh -c` invocations whose contents fail `isShellCmdBenign`. The rationale block above `classifyExecve` documents why a positive allowlist of legitimate-install binaries is intractable (build toolchains span every ecosystem) and why the harm-firing syscall layer (network/credential/persistence/RWX/audit hook) is the actual detection point. `TestAnalyze_ShellCMultiLayer` documents the mapping from each previously-caught `sh -c` attack pattern to its downstream harm rule
- **V8 JIT mprotect/mmap filter (path-aware, clone-aware)** — analyzer pre-pass builds a streaming PID→comm map from execve and clone events, then skips simultaneous-RWX `mprotect`/`mmap` events whose PID resolves to a known JIT interpreter (`node`/`nodejs`/`deno`/`bun` plus the `npm`/`npx`/`yarn`/`pnpm` shebang wrappers that run as node under binfmt_script) launched from a trusted directory (`/usr/bin/`, `/usr/local/bin/`, `/bin/`). The filter requires (a) a prior execve for the PID, (b) the basename is in `jitInterpreters`, and (c) the launch path is in `jitInterpreterTrustedDirs` — an attacker who plants a binary named `node` under `/install/<pkg>/bin/` does NOT get the pass. Eliminates the per-package `memory_execution` false positive that every Node-driven scan previously produced. The long-standing TODO comment in `strace_parse.go` documenting this issue is now retired
- **Clone-attributed thread comm propagation** — `EventClone` (a new event type) is parsed from `clone`/`clone3`/`vfork` strace lines and used to copy the parent's execve comm to the child PID when the child never executes its own execve (V8 worker threads, `posix_spawn` helpers, fork-without-exec). Without this pass, every V8 worker thread emitting mprotect RWX leaked past the JIT filter. The propagation runs as a streaming pre-pass, so a child that later does its own execve still gets correct attribution (clone propagation never overwrites an existing entry)
- **Main-target PID aliasing** — strace prints the main traced process's syscalls without a `[pid X]` prefix (extracting as `PID=0`) until ambiguity forces a switch, after which the same process appears as `[pid X]` with its real kernel PID. The `collectPIDComm` streaming pass now propagates `m[0]` to any non-zero PID that emits a non-clone event without having appeared as a clone child — that PID is the disambiguated main target. Without this aliasing, import-phase node (which runs as the main strace target) had two PIDs in our event stream for the same process, and worker threads cloned from the disambiguated PID had no parent attribution
- **Audit hooks for dynamic code execution detection** — Python PEP 578 hook (`sitecustomize.py`) intercepts `compile`/`exec`/`import`/`ctypes.dlopen`; Node.js `--require` hook (`kojuto-require.js`) intercepts `eval`/`Function`/`vm.runInNewContext`/`vm.runInThisContext`/`vm.Script`. New `dynamic_code_execution` category and `EventDynamicExec` event type
- **Severity-tiered verdict** — `types.CategorySeverity` classifies each detection category as HIGH (one event raises the verdict to SUSPICIOUS), MEDIUM (two-or-more raise it), or LOW (never raises the verdict alone). `dynamic_code_execution` is LOW, `dns_tunneling` and `evasion` are MEDIUM, all other categories stay HIGH. Unmapped categories fail closed (treated as HIGH). LOW events still appear in `report.events` for forensics — verdict reflects severity, not raw event count. Stops legitimate Python compat libraries (`six`, `attrs`, `future`) from flipping to SUSPICIOUS on benign internal `compile`/`exec` calls
- **Caller-aware audit hook** — `sitecustomize.py` now walks the Python call stack and reports the actual `.py` file invoking `compile`/`exec`, not the user-controllable `filename` argument (which `six` deliberately sets to `<string>`). When the deepest frame lives inside the scanned package's `site-packages` directory the hook prefixes the wire payload with `+` so the analyzer bypasses path-based benign filtering. Sandbox passes the scan list via `KOJUTO_SCAN_PKGS` so the hook knows which paths count as "user code"
- **System binary write detection** — `openat` with write flags to trusted system binaries (`python3`, `node`, `pip`, `sh`, etc.) in `/usr/local/bin/` or `/usr/bin/` classified as `binary_hijacking`, preventing benignPaths bypass via tmpfs overwrite
- **gVisor auto-detection** — `--runtime` default changed from empty (runc) to `auto`: probes `docker info` for runsc availability and uses gVisor if registered, falls back to runc otherwise
- **npm test package** — `testdata/probe-npm-0.1.0/` with lifecycle hook payloads (preinstall/postinstall) and require-time import phase covering 31 TTPs across 9 attack categories including audit hook validation
- **GitHub Action inputs** — `config`, `quiet`, and `no-color` exposed as Action inputs to match CLI flags (`--config`, `--quiet`, `--no-color`)

### Changed
- **Probe install launch uses a staged script file, not `sh -c <inline>`** — `Sandbox.InstallCommand` / `InstallAllCommand` now write the install script to `/var/cache/kojuto/install.sh` (a dedicated tmpfs) via `dockerWriteFile` and return `["sh", "/var/cache/kojuto/install.sh"]`. The outer probe shell is filtered as benign by `isBenignExec` (sh from `/bin/` matches `benignPaths`) instead of tripping the `sh -c` branch of `classifyExecve`. Attackers cannot mimic this shape because npm/yarn/pnpm always spawn lifecycle hooks as `sh -c <package script>`; the file-path form is reserved for kojuto's own launch path. Signature change: both methods now take `context.Context` and return `(cmd, error)`
- **Unrecognized execve AND `sh -c` content demoted to LOW severity** — both `classifyExecve`'s default branch and its `sh -c` branch now assign `CategoryUnknownBinary` instead of `CategoryCodeExecution`. The event still appears in the report for chain visibility, but the verdict is decided by the syscall-level rules that observe the binary's actual behavior. Surfaced by clean-corpus measurement: native-module packages (argon2, bcrypt, sharp, etc.) all fire `sh -c "cross-env FOO=bar node-gyp-build"` in their preinstall hook, and the negative-space first-token filter in `isShellCmdBenign` cannot keep up with the legitimate set of node-ecosystem build tools. Each attack pattern previously caught by cmdline content has a dedicated harm-firing rule downstream: curl/wget → `c2_communication` on connect; cp/mv to /usr/local/bin/* → `binary_hijacking` on openat (parser emits openat specifically for system-binary write targets); cat ~/.ssh/* → `credential_access` on openat; bind/listen → `backdoor`. A detailed design rationale lives above `classifyExecve` documenting the dynamic/static defense split and the mapping from each historical sh -c case to its downstream rule
- **strace tracing extended with `clone`/`clone3` and `--quiet=attach`** — clone variants are now in the strace trace list so the analyzer's PID→comm propagation pass can attribute child syscalls correctly. `--quiet=attach` suppresses the `strace: Process N attached` informational line, which strace otherwise prints INLINE inside the originating clone() trace, splitting the trace across two output lines and breaking single-line regex parsers
- Go version requirement lowered from 1.25.0 to 1.24.0 (stable release); `golang.org/x/sys` downgraded from v0.43.0 to v0.41.0
- `--runtime` flag default changed from `""` to `"auto"`
- `evasion-test` package updated: `b2_eval_exec` and `b3_function_constructor` promoted from `[BYPASS]` to `[DETECT]` (now `a10`/`a11`); new `b9_audit_hook_disable`, `b10_eval_via_import`, `c6_detect_audit_hook` evasion tests
- Default sensitive paths trimmed: `/proc/self/maps` and `/proc/self/cgroup` removed from `DefaultSensitivePaths()` to eliminate per-scan false-positive evasion events caused by glibc / V8 / Python `runpy` reading them on every process launch. Re-enable via `kojuto.yml` `sensitive_paths.include` if needed
- Verdict block keeps ANSI color even when stdout is redirected to a file (the verdict is rendered to stderr; only the JSON report goes to stdout, so terminal coloring is preserved for piped/redirected report output)
- Analyzer remediation message and category list ordering made deterministic — Go's randomized map iteration previously caused identical event sets to produce different summary text and `categories` array ordering between runs
- Documentation aligned with implementation: README/SPECIFICATION/SECURITY now describe the actual `--network=none` sandbox (previously claimed an isolated bridge); Python audit hook list corrected (`compile`/`exec`/`import` — `eval` is a Node.js-only event); SPECIFICATION test-data section rewritten around `probe-alpha`/`probe-npm`/`evasion-test` (the obsolete `axios-demo` entry was stale)

### Fixed
- **Fileless execution via memfd_create + fexecve now detected in strace-container mode** — the strace `-e trace=` list gained `execveat`. glibc 2.34+ routes ordinary path-based execve through the execveat syscall internally, so without this every `execve("/bin/foo", ...)` on modern glibc was silent — and the AT_EMPTY_PATH form used by fexecve / memfd loaders was doubly invisible. The new `parseExecveat` in `internal/probe/strace_parse.go` handles three shapes: (a) `execveat(AT_FDCWD, "/path", ...)` — treated as ordinary execve so all existing rules (`suspiciousExecDirs`, `benignPaths`, `interpreterExecFlags`, `sh -c` inspection) fire unchanged; (b) `execveat(fd, "", ..., AT_EMPTY_PATH)` — synthesized as `Comm="/proc/self/fd/<fd>"` so the existing `suspiciousExecDirs` entry for `/proc/self/fd/` fires code_execution HIGH; (c) fd-relative paths — recorded as-is, fall through to the unknown_binary LOW default. The eBPF probe already handled execveat via its `tp_execveat` tracepoint; this closes the parity gap on macOS/Windows host installations that use strace-container mode. Surfaced by measuring `testdata/evasion-test`'s `d1_memfd_fexecve` boundary probe, which previously produced zero events.
- **Isolated DNS lookups no longer flip verdict to SUSPICIOUS** — new `CategoryDNSLookup` (LOW) replaces the previous HIGH `c2_communication` classification on `connect(:53)` and on `sendto`/`sendmsg` DNS queries that are neither high-entropy nor known-exfil-service. Rationale: under `--network=none` the resolution never completes, and legitimate defensive probes (`getaddrinfo` at import, glibc NSS lookups, npm registry health checks) fire this syscall on nearly every scan. The real C2 signal is the follow-up TCP connect to the resolved IP, which the default `EventConnect` branch still classifies as HIGH independently. DNS lookups remain in `report.events` at LOW so the resolver + query domain stay visible for forensic reconstruction. Also closes an incidental bug where a benign low-entropy DNS query sent to an external resolver (custom `resolv.conf` pointing at `8.8.8.8`, host without an embedded Docker DNS) was misclassified as `dns_tunneling` MEDIUM by the else-branch of `classify`'s `sendto` handler
- **`extractPID` returns 0 for space-padded child PIDs** — strace right-pads small PIDs with spaces to align columns (`[pid    12]`, `[pid     1]`), and `strconv.ParseUint` rejects leading whitespace. Every container PID parsed as 0, silently disabling all downstream PID-aware analysis (V8 JIT correlation, process-tree reconstruction). `strings.TrimSpace` before parse fixes it
- **Package-manager caches no longer trip the persistence backstop** — `NPM_CONFIG_CACHE=/var/cache/kojuto/npm` and `PIP_CACHE_DIR=/var/cache/kojuto/pip` pin both caches to a dedicated tmpfs (`--tmpfs=/var/cache/kojuto:nosuid,mode=1777,size=200m`) outside the sandbox's `HOME=/home/dev`. Without these, npm's `_logs/`/`_cacache/` and pip's wheel cache wrote under `/home/dev/.npm/` and `/home/dev/.cache/pip/`, both correctly flagged by the "/home is illegitimate" structural backstop. Redirecting at the sandbox layer is preferable to relaxing the analyzer rule — the detection guarantee stays strict, and legitimate cache I/O goes to a path the analyzer never inspects (avoids the "set up a benign-looking path under HOME and smuggle payload" bypass that a carve-out would have enabled)
- **`/tmp/` added to `suspiciousExecDirs`** — execve from `/tmp/` is now positively classified as `code_execution` HIGH, matching the documented behavior in README. Previously this only worked by accident via the catch-all default branch of `classifyExecve`; with the demotion to `CategoryUnknownBinary` LOW, the basename-spoofing detection (e.g. `/tmp/python3`) needed an explicit positive rule
- **`/.dockerenv` masking actually works now** — the post-start `rm -f /.dockerenv` had been silently failing on every scan since `--read-only` rootfs was introduced (the rootfs is, by design, not writable). `/.dockerenv` is now masked at container creation time by bind-mounting an empty regular file from the host over the path. Sandbox-aware payloads that read `/.dockerenv` see empty content; gVisor (`--runtime=runsc`) is still recommended to also defeat path-existence checks
- **Sandbox preparation no longer fails silently** — `plantHoneypotFiles`, `restoreLocalBin`, `WriteProbeScripts`, and `WriteProbeScriptsMulti` now return errors instead of swallowing the result of every `docker exec`. A swallowed honeypot-write or probe-script-write failure used to leave the container partially prepared, and any sandbox-aware payload that detected the gap and stayed dormant would surface as `clean`. The errors propagate through `Start` / `StartPaused` and abort the scan
- 21 linter errors: gofmt (15 files), importShadow (2), ifElseChain (1), godot (1), intrange (1), staticcheck De Morgan (1)

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