// Package allowlist provides types and file loading for image digest allowlists.
package allowlist

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Allowlist represents an image digest allowlist.
// Digests is a map of sha256 digest -> image reference (e.g. "sha256:abc..." -> "docker.io/istio/pilot:1.24.6-distroless").
type Allowlist struct {
	Version string            `json:"version"`
	Digests map[string]string `json:"digests"`
}

// Contains checks if a digest is in the allowlist. The lookup key is
// canonicalized (lowercase hex) so a comparison never misses on case alone;
// a malformed digest is never present in a validated allowlist.
func (w *Allowlist) Contains(digest string) bool {
	parsed, err := types.ParseDigest(digest)
	if err != nil {
		return false
	}
	_, ok := w.Digests[parsed.String()]
	return ok
}

// Canonical returns the canonical byte serialization of the allowlist: Go's
// json.Marshal of the struct (fixed field order, map keys sorted, digests
// already lowercased by ParseJSON) — a function of content, never of the
// source file's formatting.
func (w *Allowlist) Canonical() ([]byte, error) {
	return json.Marshal(w)
}

// CanonicalDigest returns SHA-256 of the canonical serialization
// (docs/ratls.md). This is the value CDS binds into its
// attestation config-claims (ratls.ConfigClaims.SeedDigest) and verifiers pin
// against — anyone holding an equivalent copy of the seed reproduces it.
func (w *Allowlist) CanonicalDigest() ([]byte, error) {
	canonical, err := w.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
}

// ParseJSON parses a allowlist from JSON data. An empty Digests map is
// allowed — callers decide whether emptiness is operationally acceptable.
// Digest keys are canonicalized (lowercase hex) so lookups via Contains match
// regardless of the source's casing.
func ParseJSON(data []byte) (*Allowlist, error) {
	var wl Allowlist
	if err := json.Unmarshal(data, &wl); err != nil {
		return nil, fmt.Errorf("decode allowlist: %w", err)
	}
	if wl.Digests != nil {
		canonical := make(map[string]string, len(wl.Digests))
		for digest, image := range wl.Digests {
			parsed, err := types.ParseDigest(digest)
			if err != nil {
				return nil, fmt.Errorf("invalid digest format: %q (expected sha256:<64 hex chars>)", digest)
			}
			// Case-variant source keys collapse to one canonical key; which
			// image value survived would depend on map iteration order, making
			// CanonicalDigest nondeterministic for the same input bytes.
			if _, dup := canonical[parsed.String()]; dup {
				return nil, fmt.Errorf("duplicate digest %s (case-variant keys canonicalize to the same entry)", parsed.String())
			}
			canonical[parsed.String()] = image
		}
		wl.Digests = canonical
	}
	return &wl, nil
}
