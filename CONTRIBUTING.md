# Contributing to kojuto

Thank you for your interest in contributing!

## Development Setup

### Prerequisites

- Go 1.22+
- Docker
- Linux (for eBPF development) or WSL2 on Windows
- clang/llvm (for eBPF C code compilation)

### Build

```bash
make build
```

### Build the sandbox image

```bash
make sandbox-image
```

### Test

```bash
make test                # unit tests
sudo make test-integration  # integration tests (requires Docker + root)
```

### Lint

```bash
make lint
```

### Clean

```bash
make clean
```

### Code Generation

If you modify `internal/probe/probe.c`, regenerate the Go bindings:

```bash
make generate
```

This requires clang and the Linux kernel headers.

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Ensure tests pass (`make test`)
5. Commit with a clear message
6. Push and open a pull request

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use `golangci-lint` for linting
- Keep functions focused and small
- Add tests for new functionality

## Reporting Bugs

Use the [bug report template](https://github.com/kojuto/kojuto/issues/new?template=bug_report.yml).

## Suggesting Features

Use the [feature request template](https://github.com/kojuto/kojuto/issues/new?template=feature_request.yml).
