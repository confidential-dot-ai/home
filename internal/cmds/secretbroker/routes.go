package secretbroker

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/server"
)

// newRouter wires the Vault-compatible API surface. Only the read path and the
// cert-login path are served; everything else 404s, so the broker exposes no
// write or management surface to callers.
func newRouter(b *broker, maxRequestSize int64) http.Handler {
	r := chi.NewRouter()
	r.Use(server.RequestLogger)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r.Get("/v1/sys/health", handleHealth)
	// Vault/OpenBao API writes (including auth logins) use PUT; some clients use
	// POST. Accept both so stock Agent/CSI/SDK tooling works unchanged.
	login := http.MaxBytesHandler(http.HandlerFunc(b.handleCertLogin), maxRequestSize)
	r.Method(http.MethodPost, "/v1/auth/cert/login", login)
	r.Method(http.MethodPut, "/v1/auth/cert/login", login)
	r.Get("/v1/auth/token/lookup-self", b.handleLookupSelf)
	r.Get("/v1/{mount}/data/*", b.handleKVRead)

	return r
}
