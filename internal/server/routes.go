package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/lunal-dev/c8s/internal/attestation"
	"github.com/lunal-dev/c8s/internal/ear"
	"github.com/lunal-dev/c8s/internal/whitelist"
)

// Dependencies groups all handler dependencies for building the router.
type Dependencies struct {
	AttestationHandler attestation.Handler
	WhitelistHandler   whitelist.Handler
	ReadyFn            attestation.ReadinessFunc
	EarIssuer          ear.Issuer
	JWKSFunc           func() []byte // optional dynamic JWKS provider (rotation mode)
}

// NewRouter builds the chi router with all routes wired up.
func NewRouter(deps Dependencies) http.Handler {
	r := chi.NewRouter()
	r.Use(RequestLogger)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r.Get("/readyz", attestation.HandleReadyz(deps.ReadyFn))
	r.Get("/.well-known/jwks.json", HandleJWKS(deps.EarIssuer, deps.JWKSFunc))

	r.Post("/authenticate", deps.AttestationHandler.HandleAuthenticate)
	r.Post("/attest", deps.AttestationHandler.HandleAttest)
	r.Post("/attest-key", deps.AttestationHandler.HandleAttestKey)

	r.Get("/whitelist", deps.WhitelistHandler.HandleList)
	r.Post("/whitelist", deps.WhitelistHandler.HandleAdd)
	r.Delete("/whitelist", deps.WhitelistHandler.HandleDelete)

	return r
}
