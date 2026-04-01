.PHONY: build generate test test-race test-integration lint security vet clean sandbox-image

BINARY := kojuto

## Build
build:
	go build -o $(BINARY) .

## Code generation (eBPF, requires Linux + clang)
generate:
	cd internal/probe && go generate ./...

## Testing
test:
	go test ./...

test-race:
	go test -race ./...

test-integration:
	go test -tags integration -v ./...

test-cover:
	go test -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -func=coverage.txt

## Quality
lint:
	golangci-lint run ./...

vet:
	go vet ./...

security:
	gosec ./...
	govulncheck ./...

## Docker
sandbox-image:
	docker build -f Dockerfile.sandbox -t kojuto-sandbox:latest .

## Cleanup
clean:
	rm -f $(BINARY) $(BINARY).exe coverage.txt
	rm -f internal/probe/*_bpfel.go internal/probe/*_bpfel.o
	rm -f internal/probe/*_bpfeb.go internal/probe/*_bpfeb.o
