# Makefile for docker-dns (Go rewrite)

# Colors for output
GREEN=\033[0;32m
YELLOW=\033[1;33m
NC=\033[0m # No Color

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet
BINARY_NAME=docker-dns
BINARY_PATH=./cmd/docker-dns
BUILD_DIR=build
VERSION?=0.0.0-dev
GIT_COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOCACHE_DIR=$(CURDIR)/.cache/go-build

# Build flags
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.date=$(BUILD_TIME)"
export CGO_ENABLED=0

.PHONY: all build clean test test-short test-coverage deps update tidy modernize fmt vet lint check help run dev version

# Default target
all: test build

## build: Build the docker-dns binary
build:
	@echo "$(GREEN)Building $(BINARY_NAME)...$(NC)"
	@echo "Version: $(VERSION)"
	@echo "Commit: $(GIT_COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(BINARY_PATH)
	@echo "$(GREEN)Build complete: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)

## clean: Clean build artifacts and test files
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

## test: Run all tests
test:
	@echo "$(GREEN)Running tests...$(NC)"
	GOCACHE=$(GOCACHE_DIR) $(GOTEST) -v ./...

## test-short: Run short tests
test-short:
	@echo "Running short tests..."
	GOCACHE=$(GOCACHE_DIR) $(GOTEST) -short -v ./...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	GOCACHE=$(GOCACHE_DIR) $(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@$(GOCMD) tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download

## update: Update dependencies to latest versions
update:
	@echo "$(YELLOW)Warning: This will update dependencies. Review changes carefully.$(NC)"
	$(GOGET) -u ./...
	$(GOMOD) tidy

## tidy: Tidy go.mod
tidy:
	@echo "Tidying go.mod..."
	$(GOMOD) tidy

## modernize: Modernize the project (format, vet, update, tidy, and apply latest Go patterns)
modernize: fmt vet update tidy
	@echo "$(GREEN)Running Go modernization tool...$(NC)"
	@$(GOCMD) run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test ./... || echo "Note: modernize tool completed (warnings are normal)"
	@echo "$(GREEN)Project modernized!$(NC)"

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## lint: Run golangci-lint (requires golangci-lint to be installed)
lint:
	@echo "$(GREEN)Running golangci-lint (latest version)...$(NC)"
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run ./...

## check: Run fmt, vet, lint, and tests
check: fmt vet lint test

## run: Run docker-dns with current environment
run:
	@echo "$(GREEN)Running $(BINARY_NAME)...$(NC)"
	$(GOCMD) run $(BINARY_PATH)

## dev: Run docker-dns in development mode (debug logging)
dev:
	@echo "$(GREEN)Running $(BINARY_NAME) in development mode...$(NC)"
	LOG_LEVEL=debug $(GOCMD) run $(BINARY_PATH)

## version: Display version information
version:
	@if [ -f $(BUILD_DIR)/$(BINARY_NAME) ]; then \
		$(BUILD_DIR)/$(BINARY_NAME) --version; \
	else \
		echo "Binary not built. Run 'make build' first."; \
	fi

## help: Show this help message
help:
	@echo "$(GREEN)docker-dns - Makefile$(NC)"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
