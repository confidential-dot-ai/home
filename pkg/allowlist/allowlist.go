// Package allowlist provides types and file loading for image digest allowlists.
package allowlist

import (
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

// Contains checks if a digest is in the allowlist.
func (w *Allowlist) Contains(digest string) bool {
	_, ok := w.Digests[digest]
	return ok
}

// ParseJSON parses a allowlist from JSON data. An empty Digests map is
// allowed — callers decide whether emptiness is operationally acceptable.
func ParseJSON(data []byte) (*Allowlist, error) {
	var wl Allowlist
	if err := json.Unmarshal(data, &wl); err != nil {
		return nil, fmt.Errorf("decode allowlist: %w", err)
	}
	for digest := range wl.Digests {
		if _, err := types.ParseDigest(digest); err != nil {
			return nil, fmt.Errorf("invalid digest format: %q (expected sha256:<64 hex chars>)", digest)
		}
	}
	return &wl, nil
}
