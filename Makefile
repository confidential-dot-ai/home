.PHONY: build install build-c8s \
       test test-integration vet fmt lint clean \
       manifests generate check-crd-chart install-controller-gen require-controller-gen

CONTROLLER_GEN         ?= controller-gen
CONTROLLER_GEN_VERSION ?= v0.20.1

# CRD YAMLs land in the helm chart's crds/ folder — the install vector.
CRD_OUT_DIR    ?= ./internal/helmchart/c8s/crds

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DIR  = ./build
MODULE     = github.com/lunal-dev/c8s

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
