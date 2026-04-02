# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in kojuto, please report it responsibly.

**Do NOT open a public issue.**

Instead, please email: **security@kojuto.dev** (or use GitHub's private vulnerability reporting feature).

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

- **Dynamic analysis**: strace monitors `connect`, `sendto`, `sendmsg`, `execve`, `openat`, `rename`, and `sendfile` syscalls during install and import phases
- **DNS tunneling detection**: extracts query domains from `sendto` payloads and flags high-entropy subdomains (Shannon entropy > 3.5 bits/char) used for data exfiltration
- **Credential access detection**: `openat` monitoring flags access to sensitive paths (`~/.ssh/`, `~/.aws/`, `/etc/shadow`, `/proc/self/environ`, etc.)
- **Binary hijacking detection**: `rename`/`renameat`/`renameat2` monitoring detects attempts to overwrite trusted binaries (`python3`, `node`, `sh`, etc.)
- **Multi-OS import probing**: packages are imported under simulated Linux, Windows, and macOS identities to trigger platform-gated payloads
- **Time-shifted import**: `libfaketime` advances the clock +30 days during import probes to trigger date-gated payloads
- **Honeypot simulation**: fake credential files and CI environment variables (randomly generated per scan) provoke credential-harvesting malware into observable behavior
- **eBPF mode** (opt-in): kprobes for `connect`, `sendto`, `sendmsg`, `bind`, `listen`, `accept`, `execve`, `openat`, and `rename` — full parity with strace-container mode; best-effort attachment for non-critical probes
- **gVisor runtime** (`--runtime runsc`): user-space kernel masks `/proc/1/cgroup` and `/proc/self/mountinfo`, defeating the remaining container-detection signals
- **sudo-free eBPF**: `scripts/setup-caps.sh` grants `CAP_BPF` + `CAP_PERFMON` to the binary via `setcap`, eliminating the need for root

### Anti-Fingerprinting

- Host hostname, username, CPU count, and memory are mirrored into the container
- `/.dockerenv` is removed on startup
- Package mount path mirrors host directory layout
- Isolated bridge network provides real network interfaces (connect returns `ETIMEDOUT`, not `ENETUNREACH`)

### Host Protection

- Packages are never executed on the host system
- `pip download` uses `--only-binary=:all:` to prevent source builds on the host
- `npm install` uses `--ignore-scripts` on host; lifecycle scripts re-executed inside sandbox under strace
- npm `package.json` generation uses `json.Marshal` (not string interpolation) to prevent JSON injection