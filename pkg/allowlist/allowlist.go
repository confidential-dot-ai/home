// Package allowlist defines the CDS-served image allowlist and its deterministic
// canonical serialization.
//
// The allowlist has two layers. Digests is the floor: a digest -> image-label
// map whose images are admitted by digest alone. The measured guest seed and
// standalone/injected component images live here. Workloads carries policy:
// each named entry pins an init/main container set, and every container carries
// entrypoint/cmd (argv) and path policy. Policy is always looked up by container
// digest — the entry name and image labels are informational, never a
// trust-bearing key, because the image reference a pod presents is chosen by the
// untrusted host while the digest is bound to the bytes that run.
//
// Canonical is Go's json.Marshal of the normalized struct: fixed field order,
// map keys sorted by encoding/json, container and path lists sorted by
// normalize. CanonicalDigest (SHA-256 of that) is what CDS binds into its
// attestation config-claims, so any nondeterminism would break the verifier
// pin — normalize exists to remove it.
package allowlist

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Schema identifies the allowlist document format. It is the first field of the
// canonical form, so it is covered by CanonicalDigest and pinned by verifiers.
const Schema = "c8s.allowlist/v1"

// Policy values. Argv policies use Deny/Any/Exact; path policies use
// Deny/Any/Allow.
const (
	PolicyDeny  = "deny"
	PolicyAny   = "any"
	PolicyExact = "exact"
	PolicyAllow = "allow"
)

// Allowlist is the complete image allowlist.
type Allowlist struct {
	Schema    string              `json:"schema"`
	Digests   map[string]string   `json:"digests"`
	Workloads map[string]Workload `json:"workloads"`
}

// Workload is a named policy entry. Label is an informational image reference.
type Workload struct {
	Label          string      `json:"label,omitempty"`
	InitContainers []Container `json:"initContainers"`
	Containers     []Container `json:"containers"`
}

// Container binds a digest to the process and path policy permitted for it.
type Container struct {
	Digest  types.Digest `json:"digest"`
	Image   string       `json:"image,omitempty"`
	Command ArgvPolicy   `json:"command"`
	Args    ArgvPolicy   `json:"args"`
	Paths   PathPolicy   `json:"paths"`
}

// ArgvPolicy governs part of a container's effective argv (the OCI process.args
// a pod actually runs), mirroring the Kubernetes command/args split: Command is
// matched as an exact prefix of the argv, and Args governs the remainder after
// it. Exact requires equality, Any leaves it unconstrained, Deny requires it to
// be empty. An absent policy defaults to Deny.
type ArgvPolicy struct {
	Policy string   `json:"policy"`
	Argv   []string `json:"argv,omitempty"`
}

// PathPolicy grants filesystem read/write globs for key-management integration.
// A write grant implies create and update. Carried and attested; no enforcer
// consumes it yet. See docs/allowlist-and-capabilities.md.
type PathPolicy struct {
	Policy string   `json:"policy"`
	Read   []string `json:"read,omitempty"`
	Write  []string `json:"write,omitempty"`
}

// ParseJSON decodes and validates an allowlist, rejecting unknown fields so a
// malformed or foreign document fails loud instead of parsing as empty. The
// result is normalized (digests lowercased and deduplicated, container and path
// lists sorted) so Canonical is a function of content alone.
func ParseJSON(data []byte) (*Allowlist, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var a Allowlist
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("decode allowlist: %w", err)
	}
	if err := a.normalize(); err != nil {
		return nil, err
	}
	return &a, nil
}

// ParseWorkloadJSON decodes and validates a single workload entry — the body of
// a PUT /allowlist/workloads/{name} — applying the same normalization as
// ParseJSON so a stored entry is canonical.
func ParseWorkloadJSON(data []byte) (*Workload, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w Workload
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("decode workload: %w", err)
	}
	if err := normalizeContainers("entry", "initContainers", w.InitContainers); err != nil {
		return nil, err
	}
	if err := normalizeContainers("entry", "containers", w.Containers); err != nil {
		return nil, err
	}
	sortContainers(w.InitContainers)
	sortContainers(w.Containers)
	return &w, nil
}

// Digests returns every container digest in the workload (init and main), for
// building a digest index.
func (w Workload) Digests() []types.Digest {
	out := make([]types.Digest, 0, len(w.InitContainers)+len(w.Containers))
	for _, c := range w.InitContainers {
		out = append(out, c.Digest)
	}
	for _, c := range w.Containers {
		out = append(out, c.Digest)
	}
	return out
}

// Canonical returns the canonical byte serialization: json.Marshal of the
// normalized struct.
func (a *Allowlist) Canonical() ([]byte, error) {
	return json.Marshal(a)
}

// CanonicalDigest returns SHA-256 of Canonical — the value CDS binds into its
// attestation config-claims (docs/ratls.md) and verifiers pin against.
func (a *Allowlist) CanonicalDigest() ([]byte, error) {
	canonical, err := a.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
}

func (a *Allowlist) normalize() error {
	if a.Schema != Schema {
		return fmt.Errorf("allowlist: unknown schema %q (expected %q)", a.Schema, Schema)
	}
	if a.Digests != nil {
		canon := make(map[string]string, len(a.Digests))
		for d, img := range a.Digests {
			pd, err := types.ParseDigest(d)
			if err != nil {
				return fmt.Errorf("floor digest %q: %w", d, err)
			}
			if _, dup := canon[pd.String()]; dup {
				return fmt.Errorf("duplicate floor digest %s", pd.String())
			}
			canon[pd.String()] = img
		}
		a.Digests = canon
	}
	for name, w := range a.Workloads {
		if !validWorkloadName(name) {
			return fmt.Errorf("workload name %q must match [A-Za-z0-9][A-Za-z0-9._-]* (it is a URL path segment)", name)
		}
		if err := normalizeContainers(name, "initContainers", w.InitContainers); err != nil {
			return err
		}
		if err := normalizeContainers(name, "containers", w.Containers); err != nil {
			return err
		}
		sortContainers(w.InitContainers)
		sortContainers(w.Containers)
		a.Workloads[name] = w
	}
	return nil
}

func normalizeContainers(workload, field string, cs []Container) error {
	for i := range cs {
		c := &cs[i]
		if c.Digest.String() == "" {
			return fmt.Errorf("workload %q %s[%d]: digest is required", workload, field, i)
		}
		if err := normalizeArgv(&c.Command); err != nil {
			return fmt.Errorf("workload %q %s %s command: %w", workload, field, c.Digest, err)
		}
		if err := normalizeArgv(&c.Args); err != nil {
			return fmt.Errorf("workload %q %s %s args: %w", workload, field, c.Digest, err)
		}
		if err := normalizePaths(&c.Paths); err != nil {
			return fmt.Errorf("workload %q %s %s paths: %w", workload, field, c.Digest, err)
		}
	}
	return nil
}

// normalizeArgv validates an argv policy and canonicalizes an absent policy to
// Deny, so a minimally-specified container is maximally restrictive.
func normalizeArgv(p *ArgvPolicy) error {
	switch p.Policy {
	case PolicyDeny, PolicyAny:
		if len(p.Argv) != 0 {
			return fmt.Errorf("%s policy takes no argv", p.Policy)
		}
		p.Argv = nil
	case PolicyExact:
		if len(p.Argv) == 0 {
			return fmt.Errorf("exact policy requires a non-empty argv")
		}
	case "":
		p.Policy = PolicyDeny
		p.Argv = nil
	default:
		return fmt.Errorf("unknown argv policy %q (want deny, any, or exact)", p.Policy)
	}
	return nil
}

func normalizePaths(p *PathPolicy) error {
	switch p.Policy {
	case PolicyDeny, "":
		if len(p.Read) != 0 || len(p.Write) != 0 {
			return fmt.Errorf("deny policy grants no paths")
		}
		p.Policy = PolicyDeny
		p.Read, p.Write = nil, nil
	case PolicyAny:
		p.Read, p.Write = nil, nil
	case PolicyAllow:
		read, err := normalizeGlobs(p.Read)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		write, err := normalizeGlobs(p.Write)
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}
		if len(read) == 0 && len(write) == 0 {
			return fmt.Errorf("allow policy requires at least one read or write path")
		}
		p.Read, p.Write = read, write
	default:
		return fmt.Errorf("unknown paths policy %q (want deny, any, or allow)", p.Policy)
	}
	return nil
}

// normalizeGlobs validates that every path is absolute and clean, dedupes, and
// sorts. A trailing "/**" (subtree match) is the only wildcard form permitted.
func normalizeGlobs(globs []string) ([]string, error) {
	seen := make(map[string]struct{}, len(globs))
	out := make([]string, 0, len(globs))
	for _, g := range globs {
		if !strings.HasPrefix(g, "/") {
			return nil, fmt.Errorf("path %q must be absolute", g)
		}
		base := strings.TrimSuffix(g, "/**")
		if base == "" {
			base = "/"
		}
		if strings.Contains(base, "*") {
			return nil, fmt.Errorf("path %q: the only wildcard is a trailing /**", g)
		}
		if path.Clean(base) != base {
			return nil, fmt.Errorf("path %q is not clean (no . or ..)", g)
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// sortContainers orders a container list by digest, then by a stable rendering
// of its policy, so a set is serialized identically regardless of input order.
// Duplicate digests are permitted: one image may run under several argv policies
// (e.g. a shared base image invoked differently by different workloads).
func sortContainers(cs []Container) {
	sort.SliceStable(cs, func(i, j int) bool {
		di, dj := cs[i].Digest.String(), cs[j].Digest.String()
		if di != dj {
			return di < dj
		}
		return policyKey(cs[i]) < policyKey(cs[j])
	})
}

func policyKey(c Container) string {
	b, _ := json.Marshal([]any{c.Command, c.Args, c.Paths})
	return string(b)
}

// validWorkloadName restricts entry names to a URL-safe segment so a name can be
// used verbatim as a path parameter without escaping ambiguity.
func validWorkloadName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case (b == '.' || b == '_' || b == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}
