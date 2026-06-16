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

	r.Get("/allowlist", deps.AllowlistHandler.HandleList)
	r.Method(http.MethodPost, "/allowlist", capBody(deps.MaxRequestSize, http.HandlerFunc(deps.AllowlistHandler.HandleAdd)))
	r.Method(http.MethodDelete, "/allowlist", capBody(deps.MaxRequestSize, http.HandlerFunc(deps.AllowlistHandler.HandleDelete)))

	r.Get("/ca", handleCA(deps.CACertPEM))

	return r
}

// protected wraps a write handler with per-source-IP rate limiting and the
// request-body cap. Used for the attestation endpoints an unauthenticated
// caller can hit before any signature check.
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
