package secretbroker

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// broker holds the wired dependencies the HTTP handlers need.
type broker struct {
	verifier *peerVerifier
	policy   *Policy
	tokens   *tokenStore
	store    *vaultClient
	tokenTTL time.Duration
}

// authResponse is the subset of Vault's login response an Agent consumes.
type authResponse struct {
	Auth struct {
		ClientToken   string            `json:"client_token"`
		LeaseDuration int               `json:"lease_duration"`
		Renewable     bool              `json:"renewable"`
		TokenPolicies []string          `json:"token_policies"`
		Metadata      map[string]string `json:"metadata"`
	} `json:"auth"`
}

// kvResponse is the Vault KV v2 read envelope.
type kvResponse struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Data     map[string]any `json:"data"`
		Metadata map[string]any `json:"metadata"`
	} `json:"data"`
	Auth any `json:"auth"`
}

// handleHealth answers the Agent's preflight against a Vault-shaped health
// endpoint. The broker is "unsealed" whenever it is serving.
func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"initialized": true,
		"sealed":      false,
		"standby":     false,
	})
}

// handleCertLogin verifies the caller's attestation-rooted identity (already
// enforced at the TLS layer), applies the release policy, and mints a token
// scoped to the paths the policy grants. Deny-by-default: no matching rule is a
// 403, never an empty allow-all token.
func (b *broker) handleCertLogin(w http.ResponseWriter, r *http.Request) {
	id, err := b.verifier.Identity(r)
	if err != nil {
		writeVaultError(w, http.StatusForbidden, "caller identity verification failed")
		slog.Warn("login: identity verification failed", "error", err)
		return
	}

	fp, ok := peerCertFP(r)
	if !ok {
		writeVaultError(w, http.StatusForbidden, "client certificate required")
		return
	}

	allowed := b.policy.AllowedPaths(id)
	if len(allowed) == 0 {
		writeVaultError(w, http.StatusForbidden, "no release policy grants access to this workload")
		slog.Warn("login denied: no policy match",
			"workload_id", id.WorkloadID, "measurement", measurementLogValue(id.Measurement),
			"workload_digest", workloadDigestLogValue(id.WorkloadDigest))
		return
	}

	token, err := b.tokens.Issue(id, allowed, fp)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, "token issuance failed")
		slog.Error("login: token issuance failed", "error", err)
		return
	}

	var resp authResponse
	resp.Auth.ClientToken = token
	resp.Auth.LeaseDuration = int(b.tokenTTL.Seconds())
	resp.Auth.Renewable = false
	resp.Auth.TokenPolicies = []string{"c8s-broker"}
	resp.Auth.Metadata = map[string]string{"workload_id": id.WorkloadID}
	writeJSON(w, http.StatusOK, resp)
	slog.Info("login granted",
		"workload_id", id.WorkloadID, "measurement", measurementLogValue(id.Measurement),
		"workload_digest", workloadDigestLogValue(id.WorkloadDigest),
		"granted_paths", len(allowed))
}

// handleKVRead validates the caller's token, checks the requested path against
// the token's grant, and proxies a KV v2 read to the backing store.
func (b *broker) handleKVRead(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.tokens.Lookup(r.Header.Get("X-Vault-Token"))
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}

	// The token is bound to the client cert it was minted for: a read must
	// arrive on that same cert, so one attested workload cannot replay another's
	// token even though both hold valid mesh identities.
	if fp, ok := peerCertFP(r); !ok || fp != sess.certFP {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		slog.Warn("read denied: token presented on a different client cert",
			"workload_id", sess.identity.WorkloadID)
		return
	}

	mount := chi.URLParam(r, "mount")
	path := chi.URLParam(r, "*")
	if mount == "" || path == "" {
		writeVaultError(w, http.StatusNotFound, "not found")
		return
	}

	fullPath := mount + "/data/" + path
	if !pathAllowed(sess.allow, fullPath) {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		slog.Warn("read denied: path not granted",
			"workload_id", sess.identity.WorkloadID, "path", fullPath)
		return
	}

	secret, err := b.store.readKV(r.Context(), mount, path)
	if err != nil {
		writeVaultError(w, http.StatusBadGateway, "backing store error")
		slog.Error("read: backing store error",
			"workload_id", sess.identity.WorkloadID, "path", fullPath, "error", err)
		return
	}

	// Field scoping: a grant of "…/db#password" hands back only that field, so
	// the caller never sees the rest of the item over the wire (metadata is
	// non-secret and passes through). A path granted without a field scope
	// yields all fields.
	data := secret.Data
	if fields, all := allowedFields(sess.allow, fullPath); !all {
		filtered := make(map[string]any, len(fields))
		for name := range fields {
			if v, ok := data[name]; ok {
				filtered[name] = v
			}
		}
		data = filtered
	}

	var resp kvResponse
	resp.Data.Data = data
	resp.Data.Metadata = secret.Metadata
	writeJSON(w, http.StatusOK, resp)
	slog.Info("read granted", "workload_id", sess.identity.WorkloadID, "path", fullPath)
}

// handleLookupSelf lets the Agent confirm its token is live without leaking the
// grant. It returns only coarse token metadata.
func (b *broker) handleLookupSelf(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.tokens.Lookup(r.Header.Get("X-Vault-Token"))
	if !ok {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	ttl := int(time.Until(sess.expiry).Seconds())
	if ttl < 0 {
		ttl = 0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"ttl":      ttl,
			"policies": []string{"c8s-broker"},
			"meta":     map[string]string{"workload_id": sess.identity.WorkloadID},
		},
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeVaultError emits Vault's standard error envelope so stock clients parse
// it as a normal API error.
func writeVaultError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"errors": []string{msg}})
}

// workloadDigestLogValue renders the attested workload digest for logs, "(none)"
// when the caller presented no workload claim.
func workloadDigestLogValue(d []byte) string {
	if len(d) == 0 {
		return "(none)"
	}
	return hex.EncodeToString(d)
}

// measurementLogValue returns a short, safe-to-log form of a measurement.
func measurementLogValue(m string) string {
	if m == "" {
		return "(none)"
	}
	if len(m) > 16 {
		return m[:16] + "…"
	}
	return m
}
