package cds

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secretspolicy"
	"github.com/confidential-dot-ai/c8s/internal/server"
)

// dependencies bundles everything the cds router needs.
type dependencies struct {
	AttestHandler    AttestHandler
	AttestKeyHandler attestation.Handler
	SignCSRHandler   SignCSRHandler
	AllowlistHandler allowlist.Handler
	// SecretsPolicyHandler serves the secrets release policy (workload digest ->
	// KV paths). nil disables the /secrets-policy endpoints (no --secrets-policy-db).
	SecretsPolicyHandler *secretspolicy.Handler
	HandoffHandler       *issuer.HandoffHandler // nil disables /handoff (no --handoff-measurements)
	ReadyFn              attestation.ReadinessFunc
	EarIssuer            ear.Issuer
	JWKSFunc             func() []byte
	CACertPEM            []byte
	OperatorKeysPEM      []byte                // pinned operator public keys; empty = /operator-keys 404s
	RateLimiter          *issuer.IPRateLimiter // per-source-IP limiter for attestation endpoints
	MaxRequestSize       int64                 // applied to write endpoints; must be > 0
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

	r.Get("/allowlist", deps.AllowlistHandler.HandleList)
	r.Method(http.MethodPost, "/allowlist", deps.protected(http.HandlerFunc(deps.AllowlistHandler.HandleAdd)))
	r.Method(http.MethodPut, "/allowlist", deps.protected(http.HandlerFunc(deps.AllowlistHandler.HandleReplace)))
	r.Method(http.MethodDelete, "/allowlist", deps.protected(http.HandlerFunc(deps.AllowlistHandler.HandleDelete)))

	// Secrets policy: same shape as /allowlist (read open, writes operator-key
	// authorized), mounted only when a store is configured.
	if sp := deps.SecretsPolicyHandler; sp != nil {
		r.Get("/secrets-policy", sp.HandleList)
		r.Method(http.MethodPost, "/secrets-policy", deps.protected(http.HandlerFunc(sp.HandlePut)))
		r.Method(http.MethodPut, "/secrets-policy", deps.protected(http.HandlerFunc(sp.HandleReplace)))
		r.Method(http.MethodDelete, "/secrets-policy", deps.protected(http.HandlerFunc(sp.HandleDelete)))
	}

	r.Get("/ca", handleCA(deps.CACertPEM))
	r.Get("/operator-keys", handleOperatorKeys(deps.OperatorKeysPEM))

	return r
}

// protected wraps a write handler with per-source-IP rate limiting and the
// request-body cap. Used for the endpoints an unauthenticated caller can hit
// before any signature check: attestation issuance and allowlist mutations
// (each junk allowlist write costs up to one ECDSA verify per pinned key).
func (deps dependencies) protected(next http.Handler) http.Handler {
	return issuer.RateLimitMiddleware(deps.RateLimiter, capBody(deps.MaxRequestSize, next))
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
