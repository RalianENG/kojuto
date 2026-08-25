# probe-alpha — Detection Coverage Map

**Purpose**: Validate kojuto's detection against multi-vector supply chain attack TTPs.

> **DO NOT PUBLISH TO PyPI** — This is a test artifact.

## Usage

```bash
# Scan as local sdist
kojuto scan --local testdata/probe-alpha-0.1.0/dist/probe_alpha-0.1.0.tar.gz

# Or scan from source directory
kojuto scan --local testdata/probe-alpha-0.1.0/
```

## Expected Detections

### Install Phase (setup.py → payload.py)

| # | TTP | Syscall | Category | Source | Status |
|---|-----|---------|----------|--------|--------|
| 1 | `python3 -c "import probe_alpha.payload"` | execve | `code_execution` | setup.py:PostInstall | OLD |
| 2 | DNS resolve discord.com | sendto:53 | `data_exfiltration` | payload.py:_dns_resolve_exfil_services | **NEW** |
| 3 | DNS resolve api.telegram.org | sendto:53 | `data_exfiltration` | payload.py:_dns_resolve_exfil_services | **NEW** |
| 4 | DNS resolve pastebin.com | sendto:53 | `data_exfiltration` | payload.py:_dns_resolve_exfil_services | **NEW** |
| 5 | DNS resolve webhook.site | sendto:53 | `data_exfiltration` | payload.py:_dns_resolve_exfil_services | **NEW** |
| 6 | DNS resolve transfer.sh | sendto:53 | `data_exfiltration` | payload.py:_dns_resolve_exfil_services | **NEW** |
| 7 | DNS resolve ipinfo.io | sendto:53 | `data_exfiltration` | payload.py:_dns_resolve_exfil_services | **NEW** |
| 8 | connect discord.com:443 | connect | `c2_communication` | payload.py stage-2 | OLD |
| 9 | connect pastebin.com:443 | connect | `c2_communication` | payload.py stage-2 | OLD |
| 10 | Stage-2 drop + exec from /tmp | execve | `code_execution` | payload.py:_drop_stage2 | OLD |
| 11 | bind(0.0.0.0:4444) + listen | bind/listen | `backdoor` | payload.py:_backdoor_listener | OLD |
| 12 | Self-deletion (os.unlink) | unlink | *unmonitored* | stage-2 payload | GAP |

### Import Phase (__init__.py — runs 3x per OS identity)

| # | TTP | Syscall | Category | Source | Status |
|---|-----|---------|----------|--------|--------|
| 13 | ptrace(PTRACE_TRACEME) | ptrace | `evasion` | __init__.py:_anti_debug | OLD |
| 14 | connect ipinfo.io:443 | connect | `c2_communication` | __init__.py:_recon | OLD |
| 15 | DNS resolve ipinfo.io | sendto:53 | `data_exfiltration` | __init__.py:_recon | **NEW** |
| 16 | Read ~/.solana/id.json | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 17 | Read ~/.ethereum/keystore | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 18 | Read ~/.bitcoin/wallet.dat | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 19 | Read ~/.electrum/wallets/* | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 20 | Read ~/.monero/keys | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 21 | Read ~/.exodus/exodus.wallet | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 22 | Read ~/.atomic/Local Storage/leveldb | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 23 | Read ~/.config/solana/cli/config.yml | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 24 | Read ~/.config/Ledger Live/app.json | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 25 | Read Chrome Local Storage/leveldb | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 26 | Read Brave IndexedDB | openat | `credential_access` | __init__.py:_read_wallets | **NEW** |
| 27 | Read ~/.ssh/id_rsa | openat | `credential_access` | __init__.py:_read_credentials | OLD |
| 28 | Read ~/.aws/credentials | openat | `credential_access` | __init__.py:_read_credentials | OLD |
| 29 | Read ~/.git-credentials | openat | `credential_access` | __init__.py:_read_credentials | OLD |
| 30 | Read ~/.config/gh/hosts.yml | openat | `credential_access` | __init__.py:_read_credentials | OLD |
| 31 | connect api.telegram.org:443 | connect | `c2_communication` | __init__.py:_exfil_telegram | OLD |
| 32 | DNS resolve api.telegram.org | sendto:53 | `data_exfiltration` | __init__.py:_exfil_telegram | **NEW** |
| 33 | DNS tunnel (base64 subdomain) | sendto:53 | `dns_tunneling` | __init__.py:_dns_tunnel_exfil | OLD |
| 34 | Write ~/.bashrc (persistence) | openat(O_WRONLY) | `persistence` | __init__.py:_run | OLD |

### Boundary Tests (payload.py — GAP candidates)

| # | TTP | Syscall | Expected Category | Source | Status |
|---|-----|---------|-------------------|--------|--------|
| 35 | Write to `/usr/local/lib/python3.12/site-packages/pip/__init__.py` | openat(O_WRONLY) | **NONE** (PyPI library-hijack rule not implemented) | payload.py:_pypi_library_hijack | **GAP** |
| 36 | Write to `.../site-packages/urllib3/__init__.py` (secondary target) | openat(O_WRONLY) | **NONE** (same) | payload.py:_pypi_library_hijack | **GAP** |

## Coverage Summary

| Category | OLD | NEW | GAP |
|----------|-----|-----|-----|
| credential_access (wallets) | — | 11 | — |
| credential_access (classic) | 4 | — | — |
| data_exfiltration | — | 8 | — |
| c2_communication | 4 | — | — |
| code_execution | 2 | — | — |
| backdoor | 1 | — | — |
| persistence | 1 | — | — |
| evasion | 1 | — | — |
| dns_tunneling | 1 | — | — |
| *anti-forensics (unlink)* | — | — | 1 |
| *PyPI library hijacking* | — | — | 2 |
| **Total** | **14** | **19** | **3** |

## Notes on GAP entries

- **_pypi_library_hijack**: The npm side of this attack class (`/install/node_modules/<other>/`) is implemented in [Unreleased] under `CategoryLibraryHijack`. The PyPI side is deferred because `pip install` legitimately writes many files across many `site-packages/` directories during wheel extraction, and the analyzer needs a discriminator that separates pip-driven writes from probe-driven writes. Likely path: process attribution (writer PID's execve was pip vs. writer was a lifecycle-hook subprocess) rather than path pattern. Documented in CHANGELOG under `library_hijacking` bullet as follow-up.
  - **Measured**: an actual scan produces **zero** openat events for the hijack target. Two layers of invisibility stack: (a) the sandbox's `--read-only` rootfs prevents the write from succeeding on `/usr/local/lib/python*/site-packages/` (EROFS), and (b) even if the write targeted the writable pip-install directory (`/install/lib/python*/`), the analyzer's `parseOpenat` layer does not emit openat events for that path pattern. Both would need to change to close the gap.
