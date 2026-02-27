.PHONY: build build-testgen run dry-run test test-coverage vet lint fmt docker-build docker-run testdata clean tidy help

# Variables
BINARY_NAME=aggregator
TESTGEN_NAME=testgen
GO=go
BIN_DIR=bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags="-w -s -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)"
IMAGE=cspm-aggregator

# Default target
help:
	@echo "CSPM Aggregator - Multi-Cloud Security Posture Scoring"
	@echo ""
	@echo "Usage:"
	@echo "  make build          Build the aggregator binary"
	@echo "  make build-testgen  Build the test data generator"
	@echo "  make run            Run aggregator with config"
	@echo "  make dry-run        Run aggregator in dry-run mode (all clouds)"
	@echo "  make test           Run tests"
	@echo "  make test-coverage  Run tests with coverage report"
	@echo "  make vet            Run go vet"
	@echo "  make lint           Run golangci-lint"
	@echo "  make fmt            Format code"
	@echo "  make docker-build   Build Docker image"
	@echo "  make docker-run     Run Docker container (dry-run)"
	@echo "  make testdata       Generate test data (3000 findings)"
	@echo "  make tidy           Tidy go modules"
	@echo "  make clean          Clean build artifacts"

# Build aggregator binary
build:
	$(GO) build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/aggregator

# Build test data generator
build-testgen:
	$(GO) build -o $(BIN_DIR)/$(TESTGEN_NAME) ./cmd/testgen

# Run with config
run: build
	./$(BIN_DIR)/$(BINARY_NAME) --config configs/config.yaml

# Run in dry-run mode
dry-run: build
	./$(BIN_DIR)/$(BINARY_NAME) --dry-run --cloud all --config configs/config.yaml

# Run tests
test:
	$(GO) test -race -count=1 -timeout 120s ./...

# Run tests with coverage
test-coverage:
	$(GO) test -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Vet
vet:
	$(GO) vet ./...

# Lint
lint:
	golangci-lint run

# Format
fmt:
	$(GO) fmt ./...
	gofmt -s -w .

# Build Docker image with version injection
docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE):$(VERSION) \
		-t $(IMAGE):latest .

# Run Docker container in dry-run mode
docker-run:
	docker run --rm $(IMAGE):latest --dry-run --cloud all

# Generate test data
testdata: build-testgen
	./$(BIN_DIR)/$(TESTGEN_NAME) -count 3000 -out ./testdata

# Tidy modules
tidy:
	$(GO) mod tidy

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR)/
	rm -f coverage.out coverage.html
