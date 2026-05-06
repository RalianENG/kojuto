# Supply Chain Attack Detection Tool — Specification

## 1. Overview

### Purpose

An OSS tool that detects suspicious syscalls during package installation and import to discover supply chain attacks before execution.

### Scope

| Category | Description |
|---|---|
| **In Scope** | Dynamic analysis during install and import (syscall monitoring) |
| **In Scope** | Multi-OS simulation to bypass platform-gated payloads |
| **Out of Scope** | Static analysis layer (delegated to GuardDog) |

### Supported Ecosystems

- PyPI (Python)
- npm (Node.js)

---

## 2. Detection Targets

### Phases and Attack Surfaces

| Phase | PyPI | npm |
|---|---|---|
| Install | `setup.py` / build hooks / `cmdclass` | `preinstall` / `postinstall` scripts |
| Import | `__init__.py` / module-level code | `require()` entry point |

### Monitored Syscalls

| Syscall | Target | Attack Example |
|---|---|---|
| `connect(2)` | Outbound TCP/UDP connections | Data exfiltration to C2 server |
| `sendto(2)` | UDP send (without connect) + DNS query extraction | DNS tunneling, data exfiltration |
| `sendmsg(2)` | Message send | Bypassing connect-based detection |
| `sendmmsg(2)` | Batch message send | Bypassing connect-based detection |
| `bind(2)` | Bind socket to address | Server setup (backdoor indicator) |
| `listen(2)` | Listen for incoming connections | Backdoor listener setup |
| `accept(2)` / `accept4(2)` | Accept incoming connections | Active backdoor operation |
| `execve(2)` | Process creation | Malware binary execution, reverse shell |
| `openat(2)` | File access (sensitive paths + home dir writes) | Credential theft, persistence, sandbox detection |
| `rename(2)` / `renameat(2)` / `renameat2(2)` | File rename / move | Trusted binary hijacking (`/usr/local/bin/python3`) |
| `mmap(2)` | Memory mapping with PROT_WRITE\|PROT_EXEC | Shellcode injection via ctypes/ffi-napi (RWX anonymous mapping) |
| `mprotect(2)` | Memory permission change to WRITE+EXEC | Shellcode injection (modify then execute pattern) |
| `unlink(2)` / `unlinkat(2)` | File deletion (create→execute→delete correlation) | Anti-forensics payload self-deletion |
| `ptrace(2)` | `PTRACE_TRACEME` self-check | Anti-debugging evasion (detects tracing to suppress malicious behavior) |
| `sendfile(2)` | Zero-copy file-to-socket transfer | Forensic trace (not parsed into events) |

### Audit Hooks (Non-Syscall Detection)

| Runtime | Mechanism | Events Intercepted | Attack Example |
|---|---|---|---|
| Python | PEP 578 `sys.addaudithook()` via `sitecustomize.py` | `compile`, `exec`, `import`, `ctypes.dlopen` | `exec(base64.b64decode(...))`, obfuscated payload execution |
| Node.js | `--require` preload via `NODE_OPTIONS` | `eval`, `Function`, `vm.runInNewContext`, `vm.runInThisContext`, `vm.Script` | `eval(Buffer.from(...,'base64'))`, `new Function('return process.env.SECRET')` |

Audit hook output is multiplexed with strace output on stderr using a `KOJUTO:` prefix. The parser filters standard library internals (pip, npm, setuptools, frozen modules, dataclass codegen) via filename and snippet heuristics to minimize false positives.

### execve Analysis Logic

- Validates full binary path (directory + basename), not just basename
- For `sh -c` / `bash -c`: inspects the first token of the command against `shellSafeCommands`
- Shell commands whose arguments reference sensitive paths are flagged (e.g. `cat ~/.ssh/id_rsa`)
- `python3 -c` / `node -e` flagged as suspicious (inline code execution)
- `sed` excluded from benign list (GNU sed `e` command can execute shell)

### openat Analysis Logic

Two complementary detection strategies:

1. **Sensitive path matching** (any access mode): ~60 path patterns including SSH/GPG keys, cloud credentials (AWS/Azure/GCP/OCI/Aliyun), crypto wallets (Bitcoin/Ethereum/Solana/Monero/Electrum/Exodus/Atomic), browser data (Chrome/Firefox/Brave/Opera/Vivaldi/Edge + extension Local Storage/IndexedDB), shell startup files, desktop keyrings, application tokens, and sandbox detection paths (`/proc/self/status`, `/proc/self/mountinfo`, `/sys/class/net`). `/proc/self/maps` and `/proc/self/cgroup` are deliberately omitted from defaults — V8/Node startup, glibc, and Python's runpy read them on every launch — opt in via config include only if the extra signal is worth the per-scan noise.
2. **Home directory write detection** (whitelist-based): ANY write (`O_WRONLY`/`O_RDWR`/`O_CREAT`) to `/home/` or `/root/` is flagged — pip/npm only write to site-packages, `/usr/local/bin`, `/tmp`, and `/install`. This catches systemd persistence, LaunchAgent injection, and unknown attack paths without maintaining a blacklist
3. **System binary write detection**: writes to known system binaries (`python3`, `node`, `pip`, `sh`, etc.) in `/usr/local/bin/` or `/usr/bin/` are classified as `binary_hijacking` — prevents benignPaths bypass where an attacker overwrites a trusted binary on a writable tmpfs mount
4. **Sandbox detection classification**: reads to `/proc/self/status`, `/proc/self/mountinfo`, `/proc/<pid>/comm`, and `/sys/class/net` are classified as `evasion` (not `credential_access`) to indicate environment probing. If `/proc/self/maps` or `/proc/self/cgroup` are added back via custom config include, they are also classified as `evasion`.

- `.npmrc` and `.pypirc` are excluded (npm/pip read these during normal operation)
- Events include `open_flags` (e.g. `O_RDONLY`) to indicate read/write intent

### rename Analysis Logic

- Monitors `rename(2)`, `renameat(2)`, and `renameat2(2)` syscalls
- Events include both `src_path` and `dst_path` for full context
- Suspicious if `dst_path` overwrites a known trusted binary (e.g. `python3`, `node`, `sh` in `/usr/bin/` or `/usr/local/bin/`)
- Benign if the destination is not a whitelisted binary (e.g. pip installing a new CLI script)

### DNS Tunneling Detection

- Extracts DNS query domain from `sendto` payload when destination port is 53
- Parses DNS wire format (RFC 1035) to reconstruct the queried domain name
- Events include `dns_query` field with the extracted domain
- Heuristics for tunneling detection:
  - Subdomain label length > 30 characters
  - Total query length > 80 characters
  - Shannon entropy > 3.5 bits/char in subdomain labels (indicates base64/hex-encoded data)
- Benign suffixes excluded: `pypi.org`, `npmjs.org`, `pythonhosted.org`, `googleapis.com`, etc.
- Loopback DNS queries with clean domains are treated as benign

---

## 3. Architecture

```
CLI (cobra)
  │
  ├─ Downloader       Package download (pip / npm)
  │
  ├─ Sandbox          Docker container isolation
  │   ├─ --network=none (zero network connectivity, no embedded DNS resolver)
  │   ├─ Read-only rootfs + targeted tmpfs mounts
  │   ├─ cap-drop=ALL + custom seccomp profile
  │   ├─ no-new-privileges
  │   └─ Anti-fingerprinting (host information mirroring)
  │
  ├─ Probe            Syscall + audit hook monitoring
  │   ├─ strace-container (default, full syscall coverage)
  │   ├─ strace (host-level, Linux only)
  │   ├─ eBPF (opt-in, full syscall parity with strace, fastest)
  │   └─ Audit hooks (Python PEP 578 + Node.js --require, multiplexed on strace stderr)
  │
  ├─ Analyzer         Event classification and risk assessment
  │   ├─ Network events: filter out loopback/unspecified/link-local
  │   ├─ DNS tunneling: entropy-based detection of exfil via subdomains
  │   ├─ execve: path validation + shell command content inspection
  │   ├─ openat: sensitive file access detection (credentials, keys)
  │   ├─ rename: trusted binary hijacking detection
  │   └─ Parse failures (empty address) treated as suspicious
  │
  └─ Reporter         JSON output
```

### Execution Flow

1. Download package on host (network allowed) — or use `--local` to skip download and scan a local file/directory
2. Install in isolated container + monitor with strace (Phase 1)
3. Import in same container × 3 OS identities (Linux / Windows / macOS) + monitor with strace (Phase 2)
4. Merge events from all phases and analyze
5. Generate report
6. (Optional) If `--pin` specified and all packages clean, generate pinned dependency file

### Dependency Pinning (`--pin`)

- Available in batch scan mode (`-f` required)
- Generates a locked dependency file with exact versions resolved during download
- **Refused if any package is suspicious or errored** — only all-clean scans produce a pin file
- PyPI output: `pkg==version` format (requirements.txt)
- npm output: `package.json` with pinned `dependencies`

### Multi-OS Import Probing

- Python: monkey-patches `platform.system()`, `sys.platform`, `os.name` before import
- Node.js: overrides `process.platform` via `Object.defineProperty` before require
- Detects OS-gated malware (e.g. `if platform.system() == "Windows": attack()`) dynamically

### Time-Shifted Import (libfaketime)

- Import probes run with `LD_PRELOAD=libfaketime.so` and `FAKETIME=+Nd` where N is randomized between 30 and 180
- Triggers date-gated payloads (e.g. `if datetime.now() > datetime(2026, 5, 1): attack()`)
- Intercepts `gettimeofday`/`clock_gettime` at libc level — covers Python `datetime.now()`, Node `Date.now()`
- Install phase uses real time to avoid breaking pip/npm

### Honeypot Environment Simulation

- Fake credential files planted in container: `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.git-credentials`, `~/.netrc`, `~/.config/gh/hosts.yml`
- CI/cloud environment variables injected: `CI=true`, `GITHUB_ACTIONS=true`, `AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`, `NPM_TOKEN`
- All tokens and secret values randomly generated per scan via `crypto/rand` to prevent static fingerprinting by malware aware of kojuto source
- Triggers credential-harvesting logic that checks for file/env presence before exfiltrating

---

## 4. Sandbox Security

### Docker Container Configuration

| Setting | Value | Purpose |
|---|---|---|
| Network | `--network=none` | Zero network connectivity (no bridge, no embedded DNS resolver attack surface) |
| Filesystem | `--read-only` + tmpfs | Restrict writes |
| Capabilities | `--cap-drop=ALL` | Minimize privileges |
| seccomp | Custom profile (always applied) | Block `mount`, `unshare`, `setns`, `bpf`, `memfd_create`, `prctl(PR_SET_NAME)`, etc. |
| Privilege escalation | `--no-new-privileges` | Prevent |
| Resources | Host CPU/memory mirrored (capped at 4 cores / 4GB) | Anti-fingerprint |
| PID | `--pids-limit=256` | Prevent fork bombs |

### Anti-Fingerprinting

| Measure | Details |
|---|---|
| Hostname | Mirrors the host's actual hostname |
| Username | Host's actual username reflected in mount path |
| CPU / Memory | Host's actual values mirrored (with caps) |
| `/.dockerenv` | Removed on startup |
| `/etc/resolv.conf` | Injected via `--dns=198.51.100.1` (RFC 5737 TEST-NET-2, guaranteed unreachable) so the file is non-empty without revealing isolation |
| Network | `--network=none` returns `ENETUNREACH` on `connect()`; combine with `--runtime runsc` to mask remaining `/proc/1/cgroup` and `/proc/self/mountinfo` signals |
| Mount path | `/home/<host-user>/projects` (resembles host layout) |

### Container Runtime

| Runtime | Flag | Isolation | /proc masking |
|---|---|---|---|
| auto (default) | `--runtime auto` | gVisor if available, else runc | Best available |
| runc | `--runtime runc` | Docker kernel sharing | /proc/1/cgroup, mountinfo leak |
| gVisor (runsc) | `--runtime runsc` | User-space kernel | Fully masked |

### Known Unmasked Signals (runc only)

| Signal | Reason | Mitigation |
|---|---|---|
| `/proc/1/cgroup` contains `docker` | Written by kernel | Use `--runtime runsc` |
| `/proc/self/mountinfo` contains `overlay` | Docker storage driver | Use `--runtime runsc` |

---

## 5. Validation

### Test Data

The `testdata/` directory contains attack simulation packages for detection validation:

- `probe-alpha-0.1.0/` (PyPI sdist) — multi-vector TTP coverage map covering install-phase (`setup.py` + `payload.py`) and import-phase (`__init__.py`) detections: DNS exfil services, C2 connect, stage-2 drop+exec, bind/listen backdoor, ptrace evasion, ~14 wallet/credential reads, DNS tunneling, and create→exec→delete anti-forensics. See [`testdata/probe-alpha-0.1.0/DETECTION_MAP.md`](../testdata/probe-alpha-0.1.0/DETECTION_MAP.md).
- `probe-npm-0.1.0/` (npm tarball) — equivalent coverage on the Node.js side (preinstall/postinstall lifecycle hooks + require-time payload, audit-hook eval/Function/vm validation).
- `evasion-test-0.1.0/` — sandbox-detection and audit-hook-bypass attempts; verifies that `[DETECT]` cases are flagged and `[BYPASS]` cases are documented gaps.

Usage:

```bash
kojuto scan --local testdata/probe-alpha-0.1.0/
kojuto scan --local testdata/probe-npm-0.1.0/  -e npm
kojuto scan --local testdata/evasion-test-0.1.0/
```

Expected result for `probe-alpha`: `suspicious` covering ~10 categories across install + 3 OS-identity import phases.

---

## 6. Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| Language | Go (unified) | Single-binary distribution, rich eBPF bindings |
| eBPF probe | `cilium/ebpf` + `bpf2go` | Embeds bytecode at build time, no kernel headers needed at runtime |
| eBPF C code | C (`.c` file) | BPF programs require C; auto-generated via `bpf2go` |
| CLI | `cobra` | Standard Go CLI framework |
| Sandbox | Docker | Proven isolation, available by default in CI environments |
| Output format | JSON | Designed for CI/CD pipeline integration |