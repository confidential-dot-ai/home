package cds

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/lunal-dev/c8s/internal/attestation"
	"github.com/lunal-dev/c8s/internal/ear"
	"github.com/lunal-dev/c8s/internal/server"
	"github.com/lunal-dev/c8s/internal/whitelist"
)

// dependencies bundles everything the cds router needs.
type dependencies struct {
	AttestHandler    AttestHandler
	SignCSRHandler   SignCSRHandler
	WhitelistHandler whitelist.Handler
	ReadyFn          attestation.ReadinessFunc
	EarIssuer        ear.Issuer
	JWKSFunc         func() []byte
	CACertPEM        []byte
	MaxRequestSize   int64 // applied to write endpoints; must be > 0
}

func newRouter(deps dependencies) http.Handler {
	if deps.MaxRequestSize <= 0 {
		panic("cds: dependencies.MaxRequestSize must be positive")
	}
	r := chi.NewRouter()
	r.Use(server.RequestLogger)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/readyz", attestation.HandleReadyz(deps.ReadyFn))
	r.Get("/.well-known/jwks.json", server.HandleJWKS(deps.EarIssuer, deps.JWKSFunc))

	r.Post("/authenticate", attestation.HandleAuthenticate(deps.AttestHandler.Challenges))
	r.Method(http.MethodPost, "/attest", capBody(deps.MaxRequestSize, http.HandlerFunc(deps.AttestHandler.HandleAttest)))
	r.Method(http.MethodPost, "/sign-csr", capBody(deps.MaxRequestSize, http.HandlerFunc(deps.SignCSRHandler.HandleSignCSR)))

	r.Get("/whitelist", deps.WhitelistHandler.HandleList)
	r.Method(http.MethodPost, "/whitelist", capBody(deps.MaxRequestSize, http.HandlerFunc(deps.WhitelistHandler.HandleAdd)))
	r.Method(http.MethodDelete, "/whitelist", capBody(deps.MaxRequestSize, http.HandlerFunc(deps.WhitelistHandler.HandleDelete)))

	r.Get("/ca", handleCA(deps.CACertPEM))

	return r
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
