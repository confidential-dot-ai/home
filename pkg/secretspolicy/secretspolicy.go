// Package secretspolicy is the wire contract for the CDS-served secrets release
// policy: a mapping from an attested workload digest to the KV paths that
// workload may read. It is the operator-key-rooted analogue of the image
// allowlist — where the allowlist answers "may this image run", the secrets
// policy answers "may this workload read this secret path". Serving it from CDS
// (writes gated by the operator key, like the allowlist) moves the release
// decision off the untrusted control-plane ConfigMap and onto the same trust
// root as every other c8s admission input.
//
// The digest is the combined role-hash of a workload's admitted init/main image
// digests (workloadclaims.Digest) — the exact value a caller's mesh cert carries
// in its config-claims — so a broker can match a caller's attested digest
// against this policy directly.
package secretspolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Entry maps one workload identity to the KV paths it may read. Exactly one of
// WorkloadDigest / WorkloadImages identifies the workload:
//
//   - WorkloadDigest: the lowercase-hex combined role-hash directly.
//   - WorkloadImages: the init/main image-digest sets; ParseJSON hashes them
//     with workloadclaims.Digest to the same value, so an author can name images
//     instead of pre-computing the hash.
//
// Allow is a list of KV path globs (see the broker's pathMatch semantics),
// optionally field-scoped with "#field,field".
type Entry struct {
	WorkloadDigest string          `json:"workloadDigest,omitempty"`
	WorkloadImages *WorkloadImages `json:"workloadImages,omitempty"`
	Allow          []string        `json:"allow"`
}

// WorkloadImages names a workload by the container images it is admitted to run,
// split into the pod's init and main sets — the same role partition get-cert
// binds into the config-claims. Each entry is an image digest ("sha256:<hex>").
type WorkloadImages struct {
	Init []string `json:"init,omitempty"`
	Main []string `json:"main"`
}

// SecretsPolicy is the deny-by-default release policy: a workload gets the union
// of Allow globs across every entry whose digest matches.
type SecretsPolicy struct {
	Entries []Entry `json:"entries"`
}

// Resolve validates the entry and returns its effective workload digest
// (lowercase hex) and allow globs. It runs the same checks ParseJSON applies to
// a whole document, so a caller adding a single entry (e.g. the CDS write
// handler) can reuse it as the gate.
func (e Entry) Resolve() (digest string, allow []string, err error) {
	digest, err = e.resolvedDigest()
	if err != nil {
		return "", nil, err
	}
	if len(e.Allow) == 0 {
		return "", nil, fmt.Errorf("entry grants no paths (allow is empty)")
	}
	for _, a := range e.Allow {
		path, rawFields, hasHash := strings.Cut(a, "#")
		if path == "" {
			return "", nil, fmt.Errorf("allow %q has an empty path", a)
		}
		if hasHash && strings.TrimSpace(rawFields) == "" {
			return "", nil, fmt.Errorf("allow %q has a '#' but names no field", a)
		}
	}
	return digest, e.Allow, nil
}

// resolvedDigest returns the entry's effective workload digest (lowercase hex),
// computing it from WorkloadImages when WorkloadDigest is unset.
func (e Entry) resolvedDigest() (string, error) {
	switch {
	case e.WorkloadDigest != "" && e.WorkloadImages != nil:
		return "", fmt.Errorf("entry sets both workloadDigest and workloadImages")
	case e.WorkloadDigest != "":
		d := strings.ToLower(strings.TrimSpace(e.WorkloadDigest))
		if d == "" {
			return "", fmt.Errorf("workloadDigest is empty")
		}
		if _, err := hex.DecodeString(d); err != nil {
			return "", fmt.Errorf("workloadDigest %q is not hex: %w", e.WorkloadDigest, err)
		}
		return d, nil
	case e.WorkloadImages != nil:
		if len(e.WorkloadImages.Main) == 0 {
			return "", fmt.Errorf("workloadImages names no main image")
		}
		dg, err := workloadclaims.Digest(e.WorkloadImages.Init, e.WorkloadImages.Main)
		if err != nil {
			return "", fmt.Errorf("workloadImages: %w", err)
		}
		return hex.EncodeToString(dg), nil
	default:
		return "", fmt.Errorf("entry identifies no workload (set workloadDigest or workloadImages)")
	}
}

// ParseJSON decodes and validates a policy document. Unknown fields are
// rejected, every entry must name a workload and grant at least one path, and a
// '#' with no field is rejected (a scoping typo must not silently widen).
func ParseJSON(data []byte) (*SecretsPolicy, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var p SecretsPolicy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse secrets policy: %w", err)
	}
	for i := range p.Entries {
		if _, _, err := p.Entries[i].Resolve(); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
	}
	return &p, nil
}

// Lookup returns the union of Allow globs granted to workloadDigest (lowercase
// hex). An empty result means the workload is authorized for nothing.
func (p *SecretsPolicy) Lookup(workloadDigest string) []string {
	want := strings.ToLower(strings.TrimSpace(workloadDigest))
	if want == "" {
		return nil
	}
	var allow []string
	for _, e := range p.Entries {
		d, err := e.resolvedDigest()
		if err != nil || d != want {
			continue
		}
		allow = append(allow, e.Allow...)
	}
	return allow
}

// Canonical returns a deterministic JSON encoding: entries keyed and sorted by
// resolved digest, each entry's allow list sorted, so the same logical policy
// always hashes to the same value regardless of authoring order or whether a
// workload was named by digest or by images.
func (p *SecretsPolicy) Canonical() ([]byte, error) {
	type canonEntry struct {
		Digest string   `json:"digest"`
		Allow  []string `json:"allow"`
	}
	entries := make([]canonEntry, 0, len(p.Entries))
	for i := range p.Entries {
		d, err := p.Entries[i].resolvedDigest()
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		allow := append([]string(nil), p.Entries[i].Allow...)
		sort.Strings(allow)
		entries = append(entries, canonEntry{Digest: d, Allow: allow})
	}
	sort.Slice(entries, func(a, b int) bool {
		if entries[a].Digest != entries[b].Digest {
			return entries[a].Digest < entries[b].Digest
		}
		return strings.Join(entries[a].Allow, ",") < strings.Join(entries[b].Allow, ",")
	})
	return json.Marshal(entries)
}

// CanonicalDigest returns the SHA-256 of Canonical — the value a consumer pins
// to detect tampering with the served policy (mirrors allowlist.CanonicalDigest).
func (p *SecretsPolicy) CanonicalDigest() ([]byte, error) {
	c, err := p.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c)
	return sum[:], nil
}
