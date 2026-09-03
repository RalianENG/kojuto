# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in kojuto, please report it responsibly.

**Do NOT open a public issue.**

Instead, please use [GitHub's private vulnerability reporting](https://github.com/RalianENG/kojuto/security/advisories/new) feature.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

kojuto is a security tool that intentionally runs untrusted code in an isolated environment. The following are considered valid security concerns:

- **Sandbox escape** — any way for analyzed packages to affect the host system
- **eBPF probe vulnerabilities** — issues in the kernel-level monitoring code
- **Detection bypass** — attack patterns that evade both dynamic and static analysis
- **False negatives** — attack patterns that bypass detection (please report as feature requests unless they indicate a fundamental design flaw)

## Security Design

### Sandbox Isolation

- Packages run in Docker containers with **`--network=none`** (zero network connectivity — no bridge interface, no Docker embedded DNS resolver, no attack surface)
- Filesystem is **read-only** with targeted tmpfs mounts for writable paths
- **`--cap-drop=ALL`** removes all Linux capabilities; `SYS_PTRACE`, `CHOWN`, and `FOWNER` are re-added only when needed
- **`--no-new-privileges`** prevents privilege escalation
- **Custom seccomp profile** always applied (regardless of probe method), blocking `mount`, `unshare`, `setns`, `bpf`, `io_uring_setup`/`io_uring_enter`/`io_uring_register`, `prctl(PR_SET_NAME)`, `ptrace(PTRACE_ATTACH)`/`ptrace(PTRACE_SEIZE)`, and 50+ other dangerous syscalls. `memfd_create` is intentionally allowed — the `execveat(fd, "", ..., AT_EMPTY_PATH)` fileless-loader pattern is caught downstream (parser synthesizes `Comm=/proc/self/fd/<n>` which matches `suspiciousExecDirs` HIGH), so blocking it silently would remove evidence rather than provide it. Blocking the `io_uring` family closes an evasion path that would otherwise dispatch `openat`/`connect`/`send`/`unlinkat` through SQEs, entirely bypassing strace's `sys_enter_*` tracepoints
  - **The profile is ALLOW-by-default.** `--security-opt seccomp=<file>` *replaces* Docker's stock deny-by-default profile rather than layering on it, so the deny list above is the entire set of syscalls blocked — anything not named there is permitted, including syscalls Docker would have blocked. The list covers everything reachable without a capability kojuto does not grant; what remains open would fail with `EPERM` against `--cap-drop=ALL`. Any newly discovered escape or detection-bypass syscall must be added explicitly.
  - **`archMap` covers x86_64 (+x86, +x32) and aarch64 (+arm).** This is load-bearing, not cosmetic: libseccomp resolves syscall names for one architecture, so a filter without arch coverage matches only the native ABI and every deny above could be bypassed by shipping a static 32-bit binary or issuing the x32 form of a syscall. Hosts on an architecture absent from the map fall back to native-only coverage.
- **`SYS_PTRACE` is required for in-container strace, and is genuinely powerful.** The seccomp profile denies `PTRACE_ATTACH` and `PTRACE_SEIZE`, which is what prevents a package from getting a handle on a process it did not fork — including the strace process observing it. `PTRACE_TRACEME` stays allowed so anti-debugging self-checks still run and are reported as `evasion`. Note that blocking `process_vm_readv`/`process_vm_writev` does **not** by itself contain `SYS_PTRACE`: `PTRACE_PEEKDATA`/`POKEDATA` read and write another process's memory without those syscalls. Earlier revisions of this document claimed otherwise.
- **Hostname sanitization** prevents Docker CLI argument injection via hostile hostnames
- Resource limits: memory and CPU mirrored from host (capped at 4GB/4 cores), PID limit of 256
- **Host-side resource limits.** Each probe stops retaining events past `probe.MaxProbeEvents`, and the strace parser's dirfd / created-file correlation maps are bounded. Hitting any of those ceilings counts as lost visibility and forces an `inconclusive` verdict. Without them, a package that loops on a traced syscall grew an unbounded slice in the kojuto process and could exhaust host memory — the sandbox's own limits do not constrain the scanner.

### Detection

- **Dynamic analysis**: strace monitors `connect`, `sendto`, `sendmsg`, `sendmmsg`, `bind`, `listen`, `accept`, `accept4`, `execve`, `execveat`, `clone`, `clone3`, `openat`, `rename`, `renameat`, `renameat2`, `sendfile`, `ptrace`, `mmap`, `mprotect`, `unlink`, and `unlinkat` syscalls during install and import phases. Captured filenames are C-unescaped, dirfd-resolved (per-PID fd→path map so `openat(<fd>, "shadow", ...)` after `openat(AT_FDCWD, "/etc", ...) = <fd>` resolves to `/etc/shadow`), and `path.Clean`-normalized (`/etc/./shadow`, `/etc//shadow`, `/etc/foo/../shadow` all collapse to `/etc/shadow`) BEFORE the sensitive-path substring check runs
- **Audit hooks**: Python PEP 578 hook (`sitecustomize.py`) intercepts `compile`/`exec`/`import` events; Node.js `--require` hook intercepts `eval`/`Function`/`vm` calls. Detects dynamic code execution that generates no `execve` syscall
- **Import phase reality check**: the sandbox resolves each distribution to its actual import-name via `importlib.metadata.top_level.txt` (Python) / `require()`→`import()` fallback (Node) so packages whose install name differs from their module name (`pillow` → `PIL`, `pyyaml` → `yaml`, `opencv-python` → `cv2`) are actually imported instead of silently no-oping. When every attempted import fails and no HIGH-severity event was independently observed, the verdict is `inconclusive` — kojuto refuses to claim "clean" on a package whose import-phase code never ran
- **DNS tunneling detection**: extracts query domains from `sendto` payloads and flags high-entropy subdomains (Shannon entropy > 3.5 bits/char) used for data exfiltration
- **Credential access detection**: `openat` monitoring flags access to sensitive paths (`~/.ssh/`, `~/.aws/`, `/etc/shadow`, `/proc/self/environ`, etc.)
- **Sandbox-detection probing**: reads of `/proc/self/maps`, `/proc/self/cgroup`, `/proc/self/status`, `/proc/self/mountinfo`, and `/sys/class/net` are classified as `evasion`. Multiple reads of the same path (glibc / V8 / Python `runpy` read `/proc/self/maps` on every process launch) are deduplicated by path so the verdict rule (2+ MEDIUM events to flip) measures DISTINCT sandbox-detection paths touched — a single maps read stays clean; maps + cgroup + status flips
- **Binary hijacking detection**: `rename`/`renameat`/`renameat2` monitoring detects attempts to overwrite trusted binaries (`python3`, `node`, `sh`, etc.)
- **Multi-OS import probing**: packages are imported under simulated Linux, Windows, and macOS identities to trigger platform-gated payloads
- **Time-shifted import**: `libfaketime` advances the clock by a random offset between +30 and +180 days during import probes to trigger date-gated payloads; randomization prevents signature-based evasion, upper bound avoids TLS certificate expiry
- **Honeypot simulation**: fake credential files and CI environment variables (randomly generated per scan) provoke credential-harvesting malware into observable behavior
- **eBPF mode** (opt-in): kprobes for `connect`, `sendto`, `sendmsg`, `bind`, `listen`, `accept`, `openat`, and `rename`, plus tracepoints for `execve`/`execveat` (code execution), `ptrace` (evasion), `mmap`/`mprotect` (memory execution), and `unlink`/`unlinkat` (anti-forensics) — full detection parity with strace-container mode. `execve` uses a tracepoint rather than a kprobe because GCC's interprocedural optimization renames `do_execveat_common` to `do_execveat_common.isra.0`, breaking symbol-based kprobe attach
- **gVisor runtime** (`--runtime auto`, default): auto-detects gVisor availability; user-space kernel masks `/proc/1/cgroup` and `/proc/self/mountinfo`, defeating the remaining container-detection signals
- **sudo-free eBPF**: `scripts/setup-caps.sh` grants `CAP_BPF` + `CAP_PERFMON` to the binary via `setcap`, eliminating the need for root

### Anti-Fingerprinting

- Host hostname, username, CPU count, and memory are mirrored into the container
- `/.dockerenv` is masked at container creation time by bind-mounting an empty regular file from the host over it (`--read-only` rootfs makes post-start `rm` impossible, so masking is the only mechanism)
- Package mount path mirrors host directory layout
- `/etc/resolv.conf` is populated via `--dns=198.51.100.1` (RFC 5737 TEST-NET-2, guaranteed unreachable) so the file is non-empty even under `--network=none` — prevents the empty-resolv-conf signal that would reveal isolation. `connect()` returns `ENETUNREACH`; combine with `--runtime runsc` to mask remaining `/proc/1/cgroup` and `/proc/self/mountinfo` signals

### Known Limitations

kojuto detects malicious behavior at the syscall level. The following attack vectors are outside its current detection scope:

- **Memory-only execution** (`mmap` + `PROT_EXEC`): Shellcode executed via JIT-style memory mapping without `execve`. Simultaneous PROT_WRITE+PROT_EXEC is detected; W^X patterns (`mmap(RW)` → `mprotect(RX)`) are indistinguishable from V8 JIT. Network isolation and read-only filesystem limit the practical impact.
- **Audit hook evasion**: `eval`/`exec`/`Function` are now detected via audit hooks, but sophisticated malware can disable the Python audit hook via `ctypes` (clobbering the C-level hook list) or detect the hook's presence by inspecting `sitecustomize.py`. The Node.js hook can be bypassed by overriding `globalThis.eval` before the hook loads.
- **Legitimate-host exfiltration**: Stolen data sent via connections to benign hosts (e.g. `pypi.org:443`) cannot be distinguished from normal traffic at the syscall level, as kojuto does not inspect packet payloads.
- **Environment variable reads**: `os.environ` / `process.env` access does not generate syscalls (values are in process memory at startup). Honeypot environment variables are set, but reads are detected only indirectly when the values are exfiltrated via network connections.
- **Import-time delayed execution**: kojuto imports packages but does not call their functions. Payloads that activate only when specific functions are called (e.g. `pkg.connect()`) will not trigger during scanning.
- **Timing beyond +180 days**: `libfaketime` shifts the clock by a random offset between +30 and +180 days. Payloads gated on dates further in the future may not activate. The upper bound avoids TLS certificate expiry issues.
- **Low-entropy DNS tunneling**: DNS tunneling detection relies on Shannon entropy (> 3.5 bits/char) and label length heuristics. Dictionary-based encoding schemes that produce low-entropy subdomain labels can evade detection. This is a deliberate design tradeoff: lowering the entropy threshold would cause false positives on legitimate package registry queries. Network isolation prevents DNS queries from reaching external servers, limiting the practical impact.

### Host Protection

- **No package-manager code runs on the host.** `pip download` and `npm install` both execute inside the network-enabled `DownloadSandbox`, not on the host — they parse attacker-controlled registry metadata, resolve attacker-controlled dependency graphs, and unpack attacker-controlled archives (extraction is a real path-traversal surface). This includes `scan --local`, which resolves a local tarball in the same sandbox; that path used to run `npm install` on the host even though it is the entry point documented for scanning known-malicious samples.
- `pip download` uses `--only-binary=:all:` to prevent source builds
- `npm install` uses `--ignore-scripts` during resolution; lifecycle scripts are re-executed inside the analysis sandbox under strace, which is where kojuto wants to observe them
- npm `package.json` generation uses `json.Marshal` (not string interpolation) to prevent JSON injection
- **Staging directories are not world-readable.** The download sandbox runs as UID 1000, which is not the host UID, so the bind-mounted staging directory has to be world-writable. It is created one level below a `0700` parent so that mode is unreachable to other local accounts — otherwise any local user could drop an extra wheel or tarball into a scan in progress and have it installed and attributed to the scanned package.
- **Output relayed from the sandbox is escaped before it reaches the terminal.** pip/npm stdout, a package's stderr, and failed-install diagnostics all go through `internal/safeout`, which renders ANSI escapes inert while preserving newlines and tabs. Both the JSON report and the console path use the same routine. Without this, a package could emit escape sequences that redraw or erase the `SUSPICIOUS` verdict block kojuto prints to the same stream moments later.
- Reports and pinned dependency files are written `0600`; they can carry attacker-supplied snippets and internal package names