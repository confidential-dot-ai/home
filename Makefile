.PHONY: build build-c8s build-c8s-node build-assam build-get-cert build-ratls-mesh build-cert-issuer build-cert-rotator \
       build-nri-image-policy build-node-container-whitelist \
       test test-integration vet fmt lint clean \
       manifests generate check-crd-chart install-controller-gen require-controller-gen

CONTROLLER_GEN         ?= controller-gen
CONTROLLER_GEN_VERSION ?= v0.20.1

# CRD YAMLs land in the helm chart's crds/ folder — the install vector.
CRD_OUT_DIR    ?= ./internal/helmchart/c8s/crds

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR  = ./build
MODULE     = github.com/lunal-dev/c8s

# --- All binaries ---

build: build-c8s

# --- c8s multi-mode binary (the canonical artifact each per-role image
# COPYs in). Per-role Dockerfiles set ENTRYPOINT ["/c8s", "<name>"].

build-c8s:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/c8s ./cmd/c8s
	@echo "Built $(BUILD_DIR)/c8s"

# Slim variant for node-side images (nri-image-policy, node-container-whitelist,
# ratls-mesh, get-cert): omits 'operator' and 'install' subcommands so the
# binary doesn't pull controller-runtime or the embedded helm chart.
build-c8s-node:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -tags c8s_node \
		-ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/c8s-node ./cmd/c8s
	@echo "Built $(BUILD_DIR)/c8s-node"

# --- Assam ---

build-assam:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/assam ./cmd/assam
	@echo "Built $(BUILD_DIR)/assam"

# --- Get-Cert ---

build-get-cert:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/get-cert ./cmd/get-cert
	@echo "Built $(BUILD_DIR)/get-cert"

# --- RA-TLS Mesh ---

build-ratls-mesh:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/ratls-mesh ./cmd/ratls-mesh
	@echo "Built $(BUILD_DIR)/ratls-mesh"

# --- Cert Issuer ---

build-cert-issuer:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/cert-issuer ./cmd/cert-issuer
	@echo "Built $(BUILD_DIR)/cert-issuer"

# --- Cert Rotator ---

build-cert-rotator:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/cert-rotator ./cmd/cert-rotator
	@echo "Built $(BUILD_DIR)/cert-rotator"

# --- NRI Image Policy ---

build-nri-image-policy:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/nri-image-policy ./cmd/nri-image-policy
	@echo "Built $(BUILD_DIR)/nri-image-policy"

# --- Node Container Whitelist ---

build-node-container-whitelist:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
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

# --- CRD generation ---

install-controller-gen:
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

require-controller-gen:
	@command -v $(CONTROLLER_GEN) >/dev/null 2>&1 || { \
		echo "controller-gen not found. Install with:"; \
		echo "  go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)"; \
		exit 1; \
	}

manifests: require-controller-gen
	@mkdir -p $(CRD_OUT_DIR)
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:dir=$(CRD_OUT_DIR)

check-crd-chart: require-controller-gen
	@set -eu; \
	tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:dir="$$tmp"; \
	diff -ruN "$(CRD_OUT_DIR)" "$$tmp"

generate: require-controller-gen
	$(CONTROLLER_GEN) object paths=./api/...

# --- Cleanup ---

clean:
	rm -rf $(BUILD_DIR)
