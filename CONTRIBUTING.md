# Contributing to kojuto

Thanks for your interest in contributing! This guide covers the development workflow.

## Prerequisites

- Go 1.24+
- Docker (for sandbox image and integration tests)
- golangci-lint v2+ (`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`)
- Linux for eBPF development (optional — strace-container mode works on all platforms)

## Getting Started

```bash
git clone https://github.com/RalianENG/kojuto.git
cd kojuto
make build
make sandbox-image
make test
```

## Development Workflow

1. Fork the repo and create a feature branch from `main`
2. Write code and tests
3. Run the full check suite before pushing:

```bash
make lint        # golangci-lint
make test-race   # unit tests with race detector
make vet         # go vet
```

4. Open a PR against `main`

## Project Layout

```
cmd/               CLI entry point (cobra commands, flag handling)
internal/
  analyzer/        Event classification and verdict logic
  depfile/         requirements.txt / package.json parser
  downloader/      pip / npm package download
  probe/           Syscall monitoring (eBPF, strace, in-container strace)
  report/          JSON report generation
  sandbox/         Docker container lifecycle and security hardening
  types/           Shared types and constants
scripts/           Utility scripts (setup-caps.sh)
testdata/          Attack simulation packages for validation
docs/              Specification and Japanese documentation
```

## eBPF Development

eBPF code lives in `internal/probe/probe.c` and requires Linux with clang:

```bash
# Generate Go bindings from eBPF C code (Linux only)
make generate
```

The generated `*_bpfel.go` / `*_bpfel.o` files are not checked in. Non-Linux platforms use `probe_stub.go` and `probe_other.go` stubs.

## Testing

```bash
make test            # unit tests
make test-race       # unit tests with race detector (Linux/macOS)
make test-cover      # unit tests with coverage report
make test-integration # integration tests (requires Docker)
```

Tests that depend on Docker or external tools use the `TestHelperProcess` mock pattern to run without real dependencies. See `internal/sandbox/sandbox_mock_test.go` for examples.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add --foo flag for bar scanning
fix: handle empty package names in batch mode
test: add coverage for DNS tunneling detection
docs: update README with new flag documentation
```

## Code Style

- Run `golangci-lint run ./...` — CI enforces zero warnings
- Keep functions under 100 lines (enforced by `funlen` linter)
- Prefer `errors.New` over `fmt.Errorf` for static error strings
- Use `context.TODO()` instead of `nil` context
- Error messages should be actionable (see `downloadHint` / `dockerHint` in `cmd/root.go`)

## Adding a New Syscall

1. Add the trace to `internal/probe/container_strace.go` (strace filter)
2. Add a regex parser in `internal/probe/strace_parse.go`
3. Add classification logic in `internal/analyzer/analyzer.go`
4. Add the event constant in `internal/types/types.go`
5. If using eBPF: add the kprobe in `internal/probe/probe.c` and regenerate
6. Update docs: README, docs/README_ja.md, docs/SPECIFICATION.md
7. Add tests for parser, analyzer, and end-to-end detection

## Releasing

Releases are automated via GoReleaser on tag push. Checksums are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) (keyless, via GitHub OIDC — no secrets to manage).

### Creating a release

```bash
git tag v0.4.0
git push origin v0.4.0
# → CI runs → GoReleaser builds + cosign signs → GitHub Release created
```

### Verifying a release

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp "github.com/RalianENG/kojuto" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

## Security

If you discover a security vulnerability, **do not open a public issue**. Follow the process in [SECURITY.md](SECURITY.md).
