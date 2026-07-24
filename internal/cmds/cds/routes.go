package cds

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/server"
)

// dependencies bundles everything the cds router needs.
type dependencies struct {
	AttestHandler    AttestHandler
	AttestKeyHandler attestation.Handler
	SignCSRHandler   SignCSRHandler
	AllowlistHandler allowlist.Handler
	HandoffHandler   *issuer.HandoffHandler // nil disables /handoff (no --handoff-measurements)
	ReadyFn          attestation.ReadinessFunc
	EarIssuer        ear.Issuer
	JWKSFunc         func() []byte
	CACertPEM        []byte
	OperatorKeysPEM  []byte                // pinned operator public keys; empty = /operator-keys 404s
	RateLimiter      *issuer.IPRateLimiter // per-source-IP limiter for attestation endpoints
	MaxRequestSize   int64                 // applied to write endpoints; must be > 0
}

func newRouter(deps dependencies) http.Handler {
	if deps.MaxRequestSize <= 0 {
		panic("cds: dependencies.MaxRequestSize must be positive")
	}
	if deps.RateLimiter == nil {
		panic("cds: dependencies.RateLimiter must be set")
	}
	r := chi.NewRouter()
	r.Use(server.RequestLogger)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/readyz", attestation.HandleReadyz(deps.ReadyFn))
	r.Get("/.well-known/jwks.json", server.HandleJWKS(deps.EarIssuer, deps.JWKSFunc))
	r.Method(http.MethodGet, "/metrics", promhttp.Handler())

	r.Post("/authenticate", attestation.HandleAuthenticate(deps.AttestHandler.Challenges))
	r.Method(http.MethodPost, "/attest", deps.protected(http.HandlerFunc(deps.AttestHandler.HandleAttest)))
	r.Method(http.MethodPost, "/attest-key", deps.protected(http.HandlerFunc(deps.AttestKeyHandler.HandleAttestKey)))
	r.Method(http.MethodPost, "/sign-csr", deps.protected(http.HandlerFunc(deps.SignCSRHandler.HandleSignCSR)))

	// /handoff is mounted only when --handoff-measurements is set; a singleton
	// cds runs without it.
	if deps.HandoffHandler != nil {
		r.Method(http.MethodPost, "/handoff", deps.protected(http.HandlerFunc(deps.HandoffHandler.HandleHandoff)))
	}

	// GET is unauthenticated (RA-TLS integrity only); every mutation goes
	// through allowlistWrite (operator-JWT auth in the handler + rate limit +
	// 1 MiB body cap).
	r.Get("/allowlist", deps.AllowlistHandler.HandleList)
	r.Method(http.MethodPut, "/allowlist", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandleReplaceAll)))
	r.Method(http.MethodPost, "/allowlist/digests", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandleAddDigest)))
	r.Method(http.MethodDelete, "/allowlist/digests", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandleDeleteDigests)))
	r.Method(http.MethodPut, "/allowlist/workloads/{name}", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandlePutWorkload)))
	r.Method(http.MethodDelete, "/allowlist/workloads/{name}", deps.allowlistWrite(http.HandlerFunc(deps.AllowlistHandler.HandleDeleteWorkload)))

	r.Get("/ca", handleCA(deps.CACertPEM))
	r.Get("/operator-keys", handleOperatorKeys(deps.OperatorKeysPEM))

	return r
}

// allowlistWriteBodyCap bounds an allowlist mutation body. A workload document
// dwarfs a digest line, so it is far larger than MaxRequestSize.
const allowlistWriteBodyCap int64 = 1 << 20

// protected wraps a write handler with per-source-IP rate limiting and the
// request-body cap. Used for the endpoints an unauthenticated caller can hit
// before any signature check: attestation issuance (each junk write costs up to
// one ECDSA verify per pinned key).
func (deps dependencies) protected(next http.Handler) http.Handler {
	return issuer.RateLimitMiddleware(deps.RateLimiter, capBody(deps.MaxRequestSize, next))
}

// allowlistWrite is protected with the larger allowlist body cap.
func (deps dependencies) allowlistWrite(next http.Handler) http.Handler {
	return issuer.RateLimitMiddleware(deps.RateLimiter, capBody(allowlistWriteBodyCap, next))
}

func capBody(max int64, next http.Handler) http.Handler {
	return http.MaxBytesHandler(next, max)
}

func handleCA(caCertPEM []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caCertPEM)
	}
}

// handleOperatorKeys serves the pinned operator public-key bundle (public
// material, like /ca) so `c8s verify` can report which keys may mutate the
// allowlist. 404 when allowlist writes are disabled (no pinned keys).
func handleOperatorKeys(operatorKeysPEM []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if len(operatorKeysPEM) == 0 {
			http.Error(w, "no operator keys configured (allowlist writes disabled)", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(operatorKeysPEM)
	}
}
