package server

import (
	"net/http"

	"github.com/lunal-dev/c8s/internal/ear"
	"github.com/lunal-dev/c8s/pkg/jwks"
)

// HandleJWKS returns a handler that serves the EAR signing key as a JWKS
// document at /.well-known/jwks.json (RFC 7517).
func HandleJWKS(iss ear.Issuer) http.HandlerFunc {
	pub := iss.PublicKey()
	if pub == nil {
		// No signing key configured — serve an empty JWKS.
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"keys":[]}`))
		}
	}

	jwk, err := jwks.FromPublicKey(pub)
	if err != nil {
		panic("jwks: " + err.Error())
	}
	body, err := jwks.MarshalSet(jwk)
	if err != nil {
		panic("jwks: " + err.Error())
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write(body)
	}
}
