# testdata — Simulated Malware for EDR Validation

These packages are **test artifacts** for validating kojuto's detection capabilities.
They simulate attack patterns observed in real supply chain incidents
without containing any functional malware.

## Safety Properties

- **No real C2 servers** — all IP addresses are RFC 5737 documentation addresses (203.0.113.x) or localhost
- **No real credentials** — all tokens are randomly generated fakes
- **No functional shellcode** — only NOP (0x90) + RET (0xC3) instructions
- **No data exfiltration** — sandbox runs with `--network=none` (zero network connectivity)
- **No persistence** — sandbox uses read-only rootfs with tmpfs overlays

## Legal

These test artifacts are created for **authorized security testing** of the kojuto EDR tool.
They do not constitute malware under any applicable law:

- No unauthorized access to third-party systems
- No distribution via package registries (PyPI/npm)
- All execution occurs within isolated Docker containers controlled by the user
- Created under the security research exemption of GitHub's Terms of Service

## DO NOT

- Publish these packages to PyPI or npm
- Use these packages outside of kojuto's test infrastructure
- Modify these packages to target real systems or credentials
