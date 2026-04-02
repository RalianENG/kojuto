.PHONY: build generate test test-race test-integration test-cover lint security vet clean sandbox-image help

BINARY := kojuto

## help: Show this help message
help:
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*' $(MAKEFILE_LIST) | grep -v '^##' | sed 's/:.*/ /' | sort | sed 's/^/  /'

## Build
build: ## Build the kojuto binary
	go build -o $(BINARY) .

## Code generation (eBPF, requires Linux + clang)
generate: ## Generate eBPF Go bindings (Linux only)
	cd internal/probe && go generate ./...

## Testing
test: ## Run unit tests
	go test ./...

test-race: ## Run unit tests with race detector
	go test -race ./...

test-integration: ## Run integration tests (requires Docker)
	go test -tags integration -v ./...

test-cover: ## Run tests with coverage report
	go test -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -func=coverage.txt

## Quality
lint: ## Run golangci-lint
	golangci-lint run ./...

vet: ## Run go vet
	go vet ./...

security: ## Run gosec and govulncheck
	gosec ./...
	govulncheck ./...

## Docker
sandbox-image: ## Build the sandbox Docker image
	docker build -f Dockerfile.sandbox -t kojuto-sandbox:latest .

## Cleanup
clean: ## Remove build artifacts and generated files
	rm -f $(BINARY) $(BINARY).exe coverage.txt
	rm -f internal/probe/*_bpfel.go internal/probe/*_bpfel.o
	rm -f internal/probe/*_bpfeb.go internal/probe/*_bpfeb.o
