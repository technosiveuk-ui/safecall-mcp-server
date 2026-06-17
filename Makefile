# SafeCall MCP Server — common development tasks.
#
# VERSION is derived from git (tag → commit) and injected into the binary via
# ldflags so `--version` reports a meaningful build identifier.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BINARY  := server_bin

.PHONY: all build run test race vet bench cover clean docker install-deps

all: build

## build: compile the MCP server binary into ./server_bin
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/safecall-mcp-server

## run: build and run the server (stdio; will block waiting for JSON-RPC input)
run: build
	./$(BINARY)

## test: run the full test suite
test:
	go test -count=1 ./...

## race: run tests with the race detector
race:
	go test -race -count=1 ./...

## vet: run go vet
vet:
	go vet ./...

## bench: run benchmarks (verifies NFR2 hot-path latency budget)
bench:
	go test -bench=. -benchmem -run=^$$ ./...

## cover: print per-function coverage summary
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

## clean: remove build artifacts
clean:
	rm -f $(BINARY) coverage.out coverage.html

## docker: build the container image
docker:
	docker build -t safecall-mcp-server:$(VERSION) --build-arg VERSION=$(VERSION) .

## install-deps: install development tools (govulncheck)
install-deps:
	go install golang.org/x/vuln/cmd/govulncheck@latest
