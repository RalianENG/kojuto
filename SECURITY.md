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

- Packages run in Docker containers with an **isolated internal bridge network** (no external gateway)
- Filesystem is **read-only** with targeted tmpfs mounts for writable paths
- **`--cap-drop=ALL`** removes all Linux capabilities; `SYS_PTRACE`, `CHOWN`, and `FOWNER` are re-added only when needed
- **`--no-new-privileges`** prevents privilege escalation
- **Custom seccomp profile** always applied (regardless of probe method), blocking `mount`, `unshare`, `setns`, `bpf`, `memfd_create`, `prctl(PR_SET_NAME)`, and 40+ other dangerous syscalls
- **Hostname sanitization** prevents Docker CLI argument injection via hostile hostnames
- Resource limits: memory and CPU mirrored from host (capped at 4GB/4 cores), PID limit of 256

### Detection

- **Dynamic analysis**: strace monitors `connect`, `sendto`, `sendmsg`, `sendmmsg`, `bind`, `listen`, `accept`, `accept4`, `execve`, `openat`, `rename`, `renameat`, `renameat2`, `sendfile`, `ptrace`, `mmap`, `mprotect`, `unlink`, and `unlinkat` syscalls during install and import phases
- **Audit hooks**: Python PEP 578 hook (`sitecustomize.py`) intercepts `compile`/`exec`/`import` events; Node.js `--require` hook intercepts `eval`/`Function`/`vm` calls. Detects dynamic code execution that generates no `execve` syscall
- **DNS tunneling detection**: extracts query domains from `sendto` payloads and flags high-entropy subdomains (Shannon entropy > 3.5 bits/char) used for data exfiltration
- **Credential access detection**: `openat` monitoring flags access to sensitive paths (`~/.ssh/`, `~/.aws/`, `/etc/shadow`, `/proc/self/environ`, etc.)
- **Binary hijacking detection**: `rename`/`renameat`/`renameat2` monitoring detects attempts to overwrite trusted binaries (`python3`, `node`, `sh`, etc.)
- **Multi-OS import probing**: packages are imported under simulated Linux, Windows, and macOS identities to trigger platform-gated payloads
- **Time-shifted import**: `libfaketime` advances the clock by a random offset between +30 and +180 days during import probes to trigger date-gated payloads; randomization prevents signature-based evasion, upper bound avoids TLS certificate expiry
- **Honeypot simulation**: fake credential files and CI environment variables (randomly generated per scan) provoke credential-harvesting malware into observable behavior
- **eBPF mode** (opt-in): kprobes for `connect`, `sendto`, `sendmsg`, `bind`, `listen`, `accept`, `openat`, and `rename`, plus tracepoints for `execve`/`execveat` (code execution), `ptrace` (evasion), `mmap`/`mprotect` (memory execution), and `unlink`/`unlinkat` (anti-forensics) — full detection parity with strace-container mode. `execve` uses a tracepoint rather than a kprobe because GCC's interprocedural optimization renames `do_execveat_common` to `do_execveat_common.isra.0`, breaking symbol-based kprobe attach
- **gVisor runtime** (`--runtime auto`, default): auto-detects gVisor availability; user-space kernel masks `/proc/1/cgroup` and `/proc/self/mountinfo`, defeating the remaining container-detection signals
- **sudo-free eBPF**: `scripts/setup-caps.sh` grants `CAP_BPF` + `CAP_PERFMON` to the binary via `setcap`, eliminating the need for root

### Anti-Fingerprinting

- Host hostname, username, CPU count, and memory are mirrored into the container
- `/.dockerenv` is removed on startup
- Package mount path mirrors host directory layout
- Isolated bridge network provides real network interfaces (connect returns `ETIMEDOUT`, not `ENETUNREACH`)

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

- Packages are never executed on the host system
- `pip download` uses `--only-binary=:all:` to prevent source builds on the host
- `npm install` uses `--ignore-scripts` on host; lifecycle scripts re-executed inside sandbox under strace
- npm `package.json` generation uses `json.Marshal` (not string interpolation) to prevent JSON injection