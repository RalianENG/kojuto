.PHONY: build generate test test-integration lint clean

BINARY := kojuto

build:
	go build -o $(BINARY) .

generate:
	cd internal/probe && go generate ./...

test:
	go test ./internal/analyzer/... ./internal/report/... ./internal/downloader/...

test-integration:
	go test -tags integration ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
	rm -f internal/probe/*_bpfel.go internal/probe/*_bpfel.o
	rm -f internal/probe/*_bpfeb.go internal/probe/*_bpfeb.o

sandbox-image:
	docker build -f Dockerfile.sandbox -t kojuto-sandbox:latest .
