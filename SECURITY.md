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
- **False negatives** — attack patterns that bypass detection (please report as feature requests unless they indicate a fundamental design flaw)

## Security Design

- Packages are executed in Docker containers with `--network=none`, `--read-only`, and `--no-new-privileges`
- eBPF probes use minimal capabilities (`CAP_BPF` + `CAP_PERFMON`), never `--privileged`
- The tool never executes package code on the host system
