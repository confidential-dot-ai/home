package whitelist

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/internal/httputil"
	"github.com/lunal-dev/c8s/pkg/resources"
	"github.com/lunal-dev/c8s/pkg/types"
)

// DefaultMaxWriteBodyBytes is the cap applied when Handler.MaxWriteBodyBytes
// is zero. Mutation payloads are tiny (digest + image), so a small cap is
// fine and protects against a malicious client forcing the handler to buffer
// megabytes just to compute a hash for auth.
const DefaultMaxWriteBodyBytes int64 = 64 * 1024

// Handler holds the dependencies for whitelist HTTP handlers.
type Handler struct {
	Store           *Store
	WriteAuthorizer WriteAuthorizer
	// MaxWriteBodyBytes caps mutation request bodies. Zero means
	// DefaultMaxWriteBodyBytes; negative values are clamped to the default
	// (callers shouldn't pass them but a runtime-bad value shouldn't open
	// the handler up to unbounded reads).
	MaxWriteBodyBytes int64
}

// WriteAuthorizer authorizes a mutation request given the raw request body
// (so the auth check can bind the EAR to the body's SHA-256, defeating
// captured-token replay against a different payload).
type WriteAuthorizer func(r *http.Request, body []byte) error

// HandleList handles GET /whitelist - returns all whitelisted digests.
// Emits a weak ETag derived from the store version; matching
// If-None-Match returns 304.
func (h Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	version, digests, err := h.Store.ListAll()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	etag := `W/"` + version + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(types.WhitelistListResponse{
		Version: version,
		Digests: digests,
	})
}

// HandleAdd handles POST /whitelist - adds an image digest.
func (h Handler) HandleAdd(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	var req types.WhitelistAddRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	if err := h.Store.Add(req.Digest, req.Image); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleDelete handles DELETE /whitelist - deletes image digests atomically.
func (h Handler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}

	var req types.WhitelistDeleteRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	allFound, err := h.Store.Delete(req.Digests)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if !allFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// authorize reads the body (capped) and runs the configured authorizer.
// On success returns the body for downstream decoding.
func (h Handler) authorize(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if h.WriteAuthorizer == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	cap := h.MaxWriteBodyBytes
	if cap <= 0 {
		cap = DefaultMaxWriteBodyBytes
	}
	body, ok := httputil.ReadCappedBody(w, r, cap)
	if !ok {
		return nil, false
	}
	if err := h.WriteAuthorizer(r, body); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}

// EARWriteAuthorizer authorizes whitelist mutation requests with a CDS EAR.
// A valid EAR is not enough by itself: the token's launch measurement must be
// explicitly allowed for resources.WhitelistWrite.
type EARWriteAuthorizer struct {
	PublicKey           func() *ecdsa.PublicKey
	ExpectedIssuer      string
	AllowedMeasurements map[string]bool
	ClockSkew           time.Duration
}

func (a EARWriteAuthorizer) Authorize(r *http.Request, body []byte) error {
	if len(a.AllowedMeasurements) == 0 {
		return fmt.Errorf("no measurements allowed for %s", resources.WhitelistWrite)
	}
	auth := r.Header.Get("Authorization")
	tokenStr, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || tokenStr == "" {
		return fmt.Errorf("missing bearer EAR")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodES256.Alg() {
			return nil, fmt.Errorf("unexpected signing method %s", token.Method.Alg())
		}
		if a.PublicKey == nil {
			return nil, fmt.Errorf("missing EAR public key provider")
		}
		pub := a.PublicKey()
		if pub == nil {
			return nil, fmt.Errorf("missing EAR public key")
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}))
	if err != nil {
		return err
	}
	if !token.Valid {
		return fmt.Errorf("invalid EAR")
	}

	now := time.Now()
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return fmt.Errorf("EAR missing expiration")
	}
	if now.After(exp.Add(a.ClockSkew)) {
		return fmt.Errorf("EAR expired")
	}
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		if iat.After(now.Add(a.ClockSkew)) {
			return fmt.Errorf("EAR issued in the future")
		}
	}
	if a.ExpectedIssuer != "" {
		issuer, err := claims.GetIssuer()
		if err != nil || issuer != a.ExpectedIssuer {
			return fmt.Errorf("unexpected EAR issuer")
		}
	}

	rawSubmods, err := json.Marshal(claims[earclaims.Submods])
	if err != nil {
		return fmt.Errorf("marshal EAR submods: %w", err)
	}
	measurement, err := earclaims.LaunchDigestFromSubmods(rawSubmods)
	if err != nil {
		return err
	}
	if !a.AllowedMeasurements[measurement] {
		return fmt.Errorf("measurement not allowed for %s", resources.WhitelistWrite)
	}

	// Body binding: the EAR's pbh claim must match SHA-256 of the request
	// body the server received. This stops a captured token from being
	// replayed against a different payload within the EAR's TTL.
	pbh, _ := claims[earclaims.PayloadBodyHash].(string)
	if pbh == "" {
		return fmt.Errorf("EAR missing %s claim", earclaims.PayloadBodyHash)
	}
	wantHash := sha256.Sum256(body)
	want := base64.RawURLEncoding.EncodeToString(wantHash[:])
	if subtle.ConstantTimeCompare([]byte(pbh), []byte(want)) != 1 {
		return fmt.Errorf("EAR %s does not match request body", earclaims.PayloadBodyHash)
	}
	return nil
}
