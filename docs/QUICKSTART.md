# Quick Start

## Prerequisites

- Linux (kernel 5.8+)
- Docker
- Go 1.22+ (for building from source)
- Root privileges (for eBPF) or strace fallback

## Installation

### From source

```bash
git clone https://github.com/RalianENG/kojuto.git
cd kojuto
make build
sudo mv kojuto /usr/local/bin/
```

### Build the sandbox image

```bash
docker build -f Dockerfile.sandbox -t kojuto-sandbox:latest .
```

## Usage

### Scan a PyPI package

```bash
sudo kojuto scan requests
```

### Scan a specific version

```bash
sudo kojuto scan requests --version 2.31.0
```

### Output to file

```bash
sudo kojuto scan requests -o report.json
```

### Use strace fallback (no root/eBPF required for probe, but Docker still needed)

```bash
kojuto scan requests --probe-method strace
```

### Use in-container strace (all platforms with Docker, including macOS/Windows)

```bash
kojuto scan requests --probe-method strace-container
```

### Set scan timeout

```bash
sudo kojuto scan requests --timeout 10m
```

### Flags

| Flag | Description |
|------|-------------|
| `-v, --version` | Package version to scan (default: latest) |
| `-o, --output` | Output file path (default: stdout) |
| `--probe-method` | `auto` / `ebpf` / `strace` / `strace-container` (default: `auto`) |
| `--timeout` | Scan timeout (default: `5m`) |

## Understanding the Report

```json
{
  "package": "example-package",
  "version": "1.0.0",
  "timestamp": "2026-04-01T12:00:00Z",
  "verdict": "suspicious",
  "events": [
    {
      "timestamp": "2026-04-01T12:00:01Z",
      "pid": 1234,
      "comm": "python3",
      "family": 2,
      "dst_addr": "203.0.113.50",
      "dst_port": 443
    }
  ],
  "probe_method": "ebpf"
}
```

- **verdict: "clean"** — No outbound connection attempts detected during install.
- **verdict: "suspicious"** — Outbound connection attempts were detected. Review the `events` array for details.

## GitHub Actions

```yaml
- uses: RalianENG/kojuto@v0
  with:
    package: your-dependency
    version: '2.31.0'        # optional
    probe-method: auto       # optional: auto, ebpf, strace, strace-container
```
