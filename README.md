# kojuto

> Caught you. — Runtime network surveillance for PyPI and npm packages.

A supply chain attack detection tool that monitors syscalls during package installation to detect suspicious outbound network activity.

## How It Works

1. **Download** — Fetch the target package to the host (network allowed)
2. **Isolate** — Run `pip install` inside a Docker container with `--network=none`
3. **Monitor** — Record `connect(2)` syscalls via eBPF (or strace fallback)
4. **Report** — Output findings as JSON / SARIF

Legitimate packages don't make network connections during install. Any connection attempt is flagged as suspicious.

## Quick Start

```bash
# Build
make build

# Build sandbox image
make sandbox-image

# Scan a package
sudo ./kojuto scan <package-name>

# Scan a specific version
sudo ./kojuto scan requests --version 2.31.0

# Output to file
sudo ./kojuto scan requests -o report.json
```

## Requirements

- Linux (kernel 5.8+)
- Docker
- Go 1.22+ (build from source)
- Root or CAP_BPF + CAP_PERFMON (for eBPF; strace fallback available)

## Roadmap

| Version | Feature |
|---------|---------|
| v0.1 | PyPI install phase, `connect(2)` detection, Linux only |
| v0.2 | Import phase + `execve(2)` monitoring |
| v0.3 | npm support |
| v0.4 | Known-pattern DB + SARIF output + GitHub Action |
| v0.5 | Function load phase detection |

## Documentation

- [Quick Start](docs/QUICKSTART.md)
- [Specification](docs/SPECIFICATION.md)
- [日本語ドキュメント](docs/README_ja.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
