.PHONY: build install build-c8s build-c8s-node build-get-cert build-ratls-mesh \
       build-nri-image-policy build-policy-monitor \
       test test-integration test-e2e-cw-label-policy test-e2e-mesh-cw-enforcement vet fmt lint clean \
       manifests generate check-crd-chart install-controller-gen require-controller-gen

CONTROLLER_GEN         ?= controller-gen
CONTROLLER_GEN_VERSION ?= v0.20.1

# CRD YAMLs land in the helm chart's crds/ folder — the install vector.
CRD_OUT_DIR    ?= ./internal/helmchart/c8s/crds

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR  = ./build
MODULE     = github.com/confidential-dot-ai/c8s

LDFLAGS = -s -w -X $(MODULE)/internal/version.Version=$(VERSION)

# --- All binaries ---

build: build-c8s

# Build the c8s CLI and install it onto PATH via `go install`. The day-2 CLI
# (install, attest, ops) is meant to run on an operator's machine, so it lands
# in GOBIN (else GOPATH/bin) rather than ./build.
install:
	go install -ldflags="$(LDFLAGS)" ./cmd/c8s
	@bindir="$$(go env GOBIN)"; [ -n "$$bindir" ] || bindir="$$(go env GOPATH)/bin"; \
		echo "Installed c8s to $$bindir/c8s"

# --- c8s multi-mode binary (the canonical artifact each per-role image
# COPYs in). Per-role Dockerfiles set ENTRYPOINT ["/c8s", "<name>"].

build-c8s:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 \
		go build -ldflags="$(LDFLAGS)" \
		-o $(BUILD_DIR)/c8s ./cmd/c8s
	@echo "Built $(BUILD_DIR)/c8s"

# Slim variant for node-side images (nri-image-policy, ratls-mesh, get-cert):
# omits 'operator' and 'install' subcommands so the
# binary doesn't pull controller-runtime or the embedded helm chart.
build-c8s-node:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -tags c8s_node \
		-ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/c8s-node ./cmd/c8s
	@echo "Built $(BUILD_DIR)/c8s-node"

# --- Policy-monitor (in-kata-guest image-digest enforcer) ---
# Standalone binary baked into kata-guest-base. It watches kata-agent's
# container bundles and SIGKILLs any container whose image digest isn't
# on the allowlist baked into the dm-verity guest rootfs. Static build
# with the same flags as the other in-guest binaries so the kata-guest
# osbuilder can copy it into the rootfs.
build-policy-monitor:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/policy-monitor ./cmd/policy-monitor
	@echo "Built $(BUILD_DIR)/policy-monitor"

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

# --- NRI Image Policy ---

build-nri-image-policy:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w -X $(MODULE)/internal/version.Version=$(VERSION)" \
		-o $(BUILD_DIR)/nri-image-policy ./cmd/nri-image-policy
	@echo "Built $(BUILD_DIR)/nri-image-policy"

# --- Tests ---

test:
	go test -race -count=1 -timeout=120s ./...

test-integration:
	./test/integration/run.sh

# Live-cluster check of the cw-label integrity admission policy. Needs
# kubectl pointed at a cluster with the c8s chart installed.
test-e2e-cw-label-policy:
	./test/e2e/cw-label-policy.sh

# Live-cluster check that the workload path is mesh-wrapped and plaintext
# bypasses to cw pods fail closed. Needs kubectl pointed at a cluster with
# the c8s chart installed and a Running confidential workload.
test-e2e-mesh-cw-enforcement:
	./test/e2e/mesh-cw-enforcement.sh

# --- Linting ---

vet:
	go vet ./...

# gofmt over tracked Go files only — scanning `.` recurses into the gitignored
# kata-guest-base/.build/ (fetched kata source + a root-owned rootfs tree) and
# fails on permission-denied.
fmt:
	@test -z "$$(git ls-files '*.go' | xargs gofmt -l)" || (echo "files need formatting:"; git ls-files '*.go' | xargs gofmt -l; exit 1)

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
