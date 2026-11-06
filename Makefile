# StateWeaver Makefile

BINARY_NAME=stateweaver
BUILD_DIR=bin
GO=go
BUILD_FLAGS=-buildvcs=false

.PHONY: all build test lint lab integration-test clean

all: build test

build:
	@echo "==> Building StateWeaver binary..."
	$(GO) build $(BUILD_FLAGS) -o $(BINARY_NAME) ./cmd/stateweaver

test:
	@echo "==> Running unit tests..."
	$(GO) test -v ./internal/...

lint:
	@echo "==> Formatting and vetting Go code..."
	$(GO) fmt ./...
	$(GO) vet ./...

lab:
	@echo "==> Building lab binaries..."
	$(GO) build $(BUILD_FLAGS) -o $(BUILD_DIR)/vulnerable-api ./lab/vulnerable-api
	$(GO) build $(BUILD_FLAGS) -o $(BUILD_DIR)/secure-api ./lab/secure-api
	@echo "==> Lab binaries built in $(BUILD_DIR)/"

integration-test:
	@echo "==> Running differential authorization benchmark..."
	$(GO) test -v ./tests/...

clean:
	@echo "==> Cleaning build artifacts..."
	@rm -rf $(BINARY_NAME) $(BINARY_NAME).exe $(BUILD_DIR) reports/ graphs/ .stateweaver/

