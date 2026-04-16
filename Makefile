.PHONY: build build-assam build-get-cert build-ratls-mesh build-cert-issuer build-cert-rotator \
       build-nri-image-policy build-node-container-whitelist \
       test test-integration vet fmt lint clean

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR  = ./build
MODULE     = github.com/lunal-dev/c8s

# --- All binaries ---

build: build-assam build-get-cert build-ratls-mesh build-cert-issuer build-cert-rotator \
       build-nri-image-policy build-node-container-whitelist

# --- Assam ---

build-assam:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/ear.Version=$(VERSION)" \
		-o $(BUILD_DIR)/assam ./cmd/assam
	@echo "Built $(BUILD_DIR)/assam"

# --- Get-Cert ---

build-get-cert:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w" \
		-o $(BUILD_DIR)/get-cert ./cmd/get-cert
	@echo "Built $(BUILD_DIR)/get-cert"

# --- RA-TLS Mesh ---

build-ratls-mesh:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w" \
		-o $(BUILD_DIR)/ratls-mesh ./cmd/ratls-mesh
	@echo "Built $(BUILD_DIR)/ratls-mesh"

# --- Cert Issuer ---

build-cert-issuer:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w" \
		-o $(BUILD_DIR)/cert-issuer ./cmd/cert-issuer
	@echo "Built $(BUILD_DIR)/cert-issuer"

# --- Cert Rotator ---

build-cert-rotator:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w" \
		-o $(BUILD_DIR)/cert-rotator ./cmd/cert-rotator
	@echo "Built $(BUILD_DIR)/cert-rotator"

# --- NRI Image Policy ---

build-nri-image-policy:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o $(BUILD_DIR)/nri-image-policy ./cmd/nri-image-policy
	@echo "Built $(BUILD_DIR)/nri-image-policy"

# --- Node Container Whitelist ---

build-node-container-whitelist:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o $(BUILD_DIR)/node-container-whitelist ./cmd/node-container-whitelist
	@echo "Built $(BUILD_DIR)/node-container-whitelist"

# --- Tests ---

test:
	go test -race -count=1 -timeout=120s ./...

test-integration:
	./test/integration/run.sh

# --- Linting ---

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (echo "files need formatting:"; gofmt -l .; exit 1)

lint: fmt vet

# --- Cleanup ---

clean:
	rm -rf $(BUILD_DIR)
