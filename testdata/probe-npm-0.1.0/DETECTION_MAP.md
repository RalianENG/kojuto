# probe-npm — Detection Coverage Map

**Purpose**: Validate kojuto's detection against npm supply chain attack TTPs,
including Node.js audit hook (eval/Function/vm) coverage.

> **DO NOT PUBLISH TO npm** — This is a test artifact.

## Usage

```bash
# Scan as local tgz
kojuto scan --local testdata/probe-npm-0.1.0/ -e npm
```

## Expected Detections

### Install Phase (preinstall.js — lifecycle hook)

| # | TTP | Syscall | Category | Source | Status |
|---|-----|---------|----------|--------|--------|
| 1 | connect discord.com:443 | connect | `c2_communication` | preinstall.js:dnsResolveExfilServices | CORE |
| 2 | connect api.telegram.org:443 | connect | `c2_communication` | preinstall.js:dnsResolveExfilServices | CORE |
| 3 | connect pastebin.com:443 | connect | `c2_communication` | preinstall.js:dnsResolveExfilServices | CORE |
| 4 | connect webhook.site:443 | connect | `c2_communication` | preinstall.js:dnsResolveExfilServices | CORE |
| 5 | connect transfer.sh:443 | connect | `c2_communication` | preinstall.js:dnsResolveExfilServices | CORE |
| 6 | connect ipinfo.io:443 | connect | `c2_communication` | preinstall.js:dnsResolveExfilServices | CORE |
| 7 | Stage-2 drop + exec from /tmp | execve | `code_execution` | preinstall.js:dropStage2 | CORE |
| 8 | bind(0.0.0.0:4444) + listen | bind/listen | `backdoor` | preinstall.js:backdoorListener | CORE |
| 9 | DNS tunnel (base64 subdomain) | sendto:53 | `dns_tunneling` | preinstall.js:dnsTunnelExfil | CORE |
| 10 | Stage-2 self-deletion (unlink) | unlink | `anti_forensics` | stage-2 payload | CORE |

### Install Phase (postinstall.js — lifecycle hook)

| # | TTP | Syscall | Category | Source | Status |
|---|-----|---------|----------|--------|--------|
| 11 | Read ~/.ssh/id_rsa | openat | `credential_access` | postinstall.js:readCredentials | CORE |
| 12 | Read ~/.ssh/id_ed25519 | openat | `credential_access` | postinstall.js:readCredentials | CORE |
| 13 | Read ~/.aws/credentials | openat | `credential_access` | postinstall.js:readCredentials | CORE |
| 14 | Read ~/.git-credentials | openat | `credential_access` | postinstall.js:readCredentials | CORE |
| 15 | Read ~/.config/gh/hosts.yml | openat | `credential_access` | postinstall.js:readCredentials | CORE |
| 16 | Read ~/.docker/config.json | openat | `credential_access` | postinstall.js:readCredentials | CORE |
| 17 | Read ~/.solana/id.json | openat | `credential_access` | postinstall.js:readWallets | CORE |
| 18 | Read ~/.bitcoin/wallet.dat | openat | `credential_access` | postinstall.js:readWallets | CORE |
| 19 | Read ~/.exodus/exodus.wallet | openat | `credential_access` | postinstall.js:readWallets | CORE |
| 20 | Write ~/.bashrc (persistence) | openat(O_WRONLY) | `persistence` | postinstall.js:persistence | CORE |
| 21 | eval(base64 payload) | audit hook | `dynamic_code_execution` | postinstall.js:dynamicExec | **NEW** |
| 22 | new Function() | audit hook | `dynamic_code_execution` | postinstall.js:dynamicExec | **NEW** |
| 23 | vm.runInNewContext() | audit hook | `dynamic_code_execution` | postinstall.js:dynamicExec | **NEW** |

### Import Phase (index.js — runs 3x per OS identity)

| # | TTP | Syscall | Category | Source | Status |
|---|-----|---------|----------|--------|--------|
| 24 | connect ipinfo.io:443 | connect | `c2_communication` | index.js:recon | CORE |
| 25 | Read ~/.ssh/id_rsa | openat | `credential_access` | index.js:readCredentials | CORE |
| 26 | Read ~/.aws/credentials | openat | `credential_access` | index.js:readCredentials | CORE |
| 27 | Read ~/.git-credentials | openat | `credential_access` | index.js:readCredentials | CORE |
| 28 | Read ~/.config/gh/hosts.yml | openat | `credential_access` | index.js:readCredentials | CORE |
| 29 | connect api.telegram.org:443 | connect | `c2_communication` | index.js:exfilTelegram | CORE |
| 30 | eval(base64 payload) | audit hook | `dynamic_code_execution` | index.js:dynamicExec | **NEW** |
| 31 | new Function() | audit hook | `dynamic_code_execution` | index.js:dynamicExec | **NEW** |
| 32 | vm.runInNewContext() | audit hook | `dynamic_code_execution` | index.js:dynamicExec | **NEW** |
| 33 | Read /proc/self/status | openat | `evasion` | index.js:sandboxDetect | CORE |
| 34 | Read /sys/class/net | openat | `evasion` | index.js:sandboxDetect | CORE |

## Coverage Summary

| Category | CORE | NEW (audit hook) |
|----------|------|-------------------|
| c2_communication | 8 | — |
| credential_access | 10 | — |
| code_execution | 1 | — |
| backdoor | 1 | — |
| persistence | 1 | — |
| dns_tunneling | 1 | — |
| anti_forensics | 1 | — |
| evasion | 2 | — |
| dynamic_code_execution | — | 6 |
| **Total** | **25** | **6** |
