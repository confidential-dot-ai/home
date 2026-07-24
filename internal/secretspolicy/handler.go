package secretspolicy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/pkg/secretspolicy"
)

// DefaultMaxWriteBodyBytes caps mutation request bodies. Policy payloads are
// small; the cap protects the auth path from buffering megabytes just to hash
// a body for the signature check.
const DefaultMaxWriteBodyBytes int64 = 256 * 1024

// WriteAuthorizer authorizes a mutation given the raw request body, so the auth
// check can bind the operator token to the body's SHA-256 (defeating a captured
// token replayed against a different payload). Production wires the same
// operatorauth.Verifier.Authorize the allowlist uses.
type WriteAuthorizer func(r *http.Request, body []byte) error

// Handler serves the secrets policy: an unauthenticated read path and an
// operator-key-authorized write path.
type Handler struct {
	Store             *Store
	WriteAuthorizer   WriteAuthorizer
	MaxWriteBodyBytes int64
}

// ListResponse is the GET /secrets-policy body.
type ListResponse struct {
	Version string              `json:"version"`
	Entries map[string][]string `json:"entries"`
}

// PutRequest adds/replaces one workload's grant. Either workloadDigest or
// workloadImages identifies the workload (see pkg/secretspolicy.Entry).
type PutRequest struct {
	secretspolicy.Entry
}

// ReplaceRequest atomically swaps the whole policy.
type ReplaceRequest struct {
	Entries []secretspolicy.Entry `json:"entries"`
}

// DeleteRequest removes the named workload digests (lowercase hex).
type DeleteRequest struct {
	Digests []string `json:"digests"`
}

// HandleList handles GET /secrets-policy.
func (h Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	version, entries, err := h.Store.ListAll()
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
	_ = json.NewEncoder(w).Encode(ListResponse{Version: version, Entries: entries})
}

// HandlePut handles POST /secrets-policy — add/replace one workload's grant.
func (h Handler) HandlePut(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}
	var req PutRequest
	if !decode(w, body, &req) {
		return
	}
	digest, allow, err := req.Resolve()
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := h.Store.Put(digest, allow); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	slog.Info("secrets-policy entry put", "digest", digest, "paths", len(allow))
	w.WriteHeader(http.StatusNoContent)
}

// HandleReplace handles PUT /secrets-policy — atomic full replace.
func (h Handler) HandleReplace(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}
	var req ReplaceRequest
	if !decode(w, body, &req) {
		return
	}
	if req.Entries == nil {
		http.Error(w, `entries is required (send {"entries":[]} to clear the policy)`, http.StatusUnprocessableEntity)
		return
	}
	entries := map[string][]string{}
	for i := range req.Entries {
		digest, allow, err := req.Entries[i].Resolve()
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		entries[digest] = allow
	}
	if err := h.Store.Replace(entries); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	slog.Info("secrets-policy replaced", "workloads", len(entries))
	w.WriteHeader(http.StatusNoContent)
}

// HandleDelete handles DELETE /secrets-policy.
func (h Handler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authorize(w, r)
	if !ok {
		return
	}
	var req DeleteRequest
	if !decode(w, body, &req) {
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
	slog.Info("secrets-policy entries deleted", "count", len(req.Digests))
	w.WriteHeader(http.StatusNoContent)
}

func decode(w http.ResponseWriter, body []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return false
	}
	return true
}

func (h Handler) authorize(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	max := h.MaxWriteBodyBytes
	if max <= 0 {
		max = DefaultMaxWriteBodyBytes
	}
	body, ok := httputil.ReadCappedBody(w, r, max)
	if !ok {
		return nil, false
	}
	if h.WriteAuthorizer == nil {
		http.Error(w, "writes disabled (no operator keys configured)", http.StatusForbidden)
		return nil, false
	}
	if err := h.WriteAuthorizer(r, body); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}
