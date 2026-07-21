package secretbroker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// PeerIdentity is the attestation-rooted identity the broker derives from a
// verified caller TLS connection:
//
//   - Measurement: lowercase-hex SHA-384 launch digest. Set only in
//     --peer-verify=ratls mode, where the hardware chain has been verified.
//   - WorkloadID: the caller's CDS-issued SAN. Set only in --peer-verify=ca
//     mode, where the mesh CA chain-verified the leaf. An RA-TLS leaf is
//     self-signed and its REPORTDATA binds only the key, not the SAN, so in
//     ratls mode the SAN is caller-asserted and is left unset — a
//     workloadId-scoped rule fails closed there.
//   - WorkloadDigest: the attested combined role-hash of the caller's admitted
//     container images (workloadclaims.Digest), read off the leaf's config-claims.
//     Bound by the evidence REPORTDATA in ratls mode and CDS-vouched at issuance
//     in ca mode, so it is the one identity trustworthy in BOTH modes. nil when
//     the caller presented no workload claim.
type PeerIdentity struct {
	Measurement    string
	WorkloadID     string
	WorkloadDigest []byte
}

// Rule is one entry in the release policy. A rule matches a PeerIdentity when
// every constraint it sets is satisfied (AND):
//
//   - Measurements: if non-empty, the caller's measurement must be one of these
//     (a rule that constrains on measurement can therefore never match in
//     --peer-verify=ca mode, where no measurement is available — fail closed).
//   - WorkloadID: if non-empty and not "*", must equal the caller's WorkloadID
//     (never matches in --peer-verify=ratls mode, where WorkloadID is unset —
//     fail closed).
//   - WorkloadImages: if set, the caller's attested WorkloadDigest must equal the
//     combined role-hash of these init/main image digests (workloadclaims.Digest).
//     This is the pod-identity bind: only the workload whose whole admitted image
//     set hashes to this value is released the secret, and a caller carrying no
//     workload claim fails closed.
//
// Allow lists the KV v2 read grants (see pathMatch for path glob semantics).
// Each entry is a path pattern optionally suffixed with a field scope:
//
//   - "secret/data/api/db"                — every field at the path
//   - "secret/data/api/db#password"       — only the "password" field
//   - "secret/data/api/*#password,api_key" — those two fields, any secret under api
//
// The broker filters the KV read down to the granted fields (handleKVRead), so
// a field-scoped grant does not hand the caller the rest of the item. The
// union of Allow across all matching rules is the caller's permitted set; a
// path granted without a field scope by any matching entry yields all fields.
type Rule struct {
	Measurements   []string        `json:"measurements,omitempty"`
	WorkloadID     string          `json:"workloadId,omitempty"`
	WorkloadImages *WorkloadImages `json:"workloadImages,omitempty"`
	Allow          []string        `json:"allow"`

	// expectedWorkloadDigest is the combined role-hash of WorkloadImages,
	// precomputed by LoadPolicy (workloadclaims.Digest); nil when WorkloadImages
	// is unset. Compared byte-equal against the caller's attested WorkloadDigest.
	expectedWorkloadDigest []byte
}

// WorkloadImages names a workload by the container images it is admitted to run,
// split into the pod's init and main sets — the same role partition get-cert
// binds into the RA-TLS config-claims. Each entry is an image digest
// ("sha256:<hex>"); the broker hashes them with workloadclaims.Digest to the
// combined value the caller's cert attests. At least one main image is required.
type WorkloadImages struct {
	Init []string `json:"init,omitempty"`
	Main []string `json:"main"`
}

// Policy is the deny-by-default release policy.
type Policy struct {
	Rules []Rule `json:"rules"`
}

// LoadPolicy reads and validates a JSON policy file. A policy with no rules is
// rejected: an empty policy denies everything, which is almost certainly a
// misconfiguration rather than an intent to run a broker that releases nothing.
func LoadPolicy(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("policy has no rules (would deny everything)")
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if len(r.Allow) == 0 {
			return nil, fmt.Errorf("policy rule %d grants no paths (allow is empty)", i)
		}
		for _, entry := range r.Allow {
			pat, fields := splitAllowEntry(entry)
			if pat == "" {
				return nil, fmt.Errorf("policy rule %d has an allow entry with an empty path (%q)", i, entry)
			}
			// A '#' with no usable field is a scoping typo, not "all fields" —
			// silently widening to all fields would invert the operator's
			// least-privilege intent, so reject it.
			if strings.Contains(entry, "#") && len(fields) == 0 {
				return nil, fmt.Errorf("policy rule %d allow entry %q has a '#' but names no field", i, entry)
			}
			for _, f := range fields {
				if f == "" {
					return nil, fmt.Errorf("policy rule %d allow entry %q has an empty field name", i, entry)
				}
			}
		}
		for _, m := range r.Measurements {
			if normalizeMeasurement(m) == "" {
				return nil, fmt.Errorf("policy rule %d has an empty measurement", i)
			}
		}
		if r.WorkloadImages != nil {
			if len(r.WorkloadImages.Main) == 0 {
				return nil, fmt.Errorf("policy rule %d workloadImages names no main image", i)
			}
			// Digest validates every image digest (types.ParseDigest) and is the
			// single hashing path the caller's cert also committed to, so the
			// precomputed value compares byte-equal with an honest peer's claim.
			dg, err := workloadclaims.Digest(r.WorkloadImages.Init, r.WorkloadImages.Main)
			if err != nil {
				return nil, fmt.Errorf("policy rule %d workloadImages: %w", i, err)
			}
			r.expectedWorkloadDigest = dg
		}
	}
	return &p, nil
}

// AllowedPaths returns the union of Allow globs from every rule matching id.
// An empty result means the caller is authorized for nothing (deny-by-default).
func (p *Policy) AllowedPaths(id PeerIdentity) []string {
	var allowed []string
	for _, r := range p.Rules {
		if ruleMatches(r, id) {
			allowed = append(allowed, r.Allow...)
		}
	}
	return allowed
}

func ruleMatches(r Rule, id PeerIdentity) bool {
	if len(r.Measurements) > 0 {
		if id.Measurement == "" {
			return false
		}
		found := false
		for _, m := range r.Measurements {
			if normalizeMeasurement(m) == id.Measurement {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.WorkloadID != "" && r.WorkloadID != "*" && r.WorkloadID != id.WorkloadID {
		return false
	}
	// A workload-pinned rule releases only to the exact attested image set.
	// bytes.Equal(expected, nil) is false, so a caller carrying no workload
	// claim (id.WorkloadDigest == nil) fails closed.
	if len(r.expectedWorkloadDigest) > 0 && !bytes.Equal(r.expectedWorkloadDigest, id.WorkloadDigest) {
		return false
	}
	return true
}

// splitAllowEntry separates an allow entry "pattern[#field,field]" into its
// path pattern and its field scope (nil = all fields at the path).
func splitAllowEntry(entry string) (pattern string, fields []string) {
	pattern, rawFields, ok := strings.Cut(entry, "#")
	if !ok || rawFields == "" {
		return pattern, nil
	}
	for _, f := range strings.Split(rawFields, ",") {
		fields = append(fields, strings.TrimSpace(f))
	}
	return pattern, fields
}

// pathAllowed reports whether reqPath is granted by any entry in allowed
// (ignoring field scope — field filtering happens in allowedFields).
func pathAllowed(allowed []string, reqPath string) bool {
	for _, entry := range allowed {
		pat, _ := splitAllowEntry(entry)
		if pathMatch(pat, reqPath) {
			return true
		}
	}
	return false
}

// allowedFields returns the field scope for reqPath across all matching allow
// entries. allFields is true when any matching entry grants the path without a
// field scope (a broader grant wins, as with allow-lists generally); otherwise
// fields is the union of the field scopes of the matching entries.
func allowedFields(allowed []string, reqPath string) (fields map[string]struct{}, allFields bool) {
	fields = map[string]struct{}{}
	for _, entry := range allowed {
		pat, fs := splitAllowEntry(entry)
		if !pathMatch(pat, reqPath) {
			continue
		}
		if len(fs) == 0 {
			return nil, true
		}
		for _, f := range fs {
			fields[f] = struct{}{}
		}
	}
	return fields, false
}

// pathMatch matches a slash-delimited request path against a glob pattern with
// segment semantics:
//
//   - "*" matches exactly one path segment (no "/").
//   - "**" matches any number of trailing segments and must be the last
//     pattern segment.
//   - all other segments match literally.
//
// Examples: "secret/data/api/*" matches "secret/data/api/db" but not
// "secret/data/api/db/pw"; "secret/data/team/**" matches both.
func pathMatch(pattern, path string) bool {
	pat := strings.Split(strings.Trim(pattern, "/"), "/")
	seg := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range pat {
		if p == "**" {
			return true // matches the remaining segments (including none)
		}
		if i >= len(seg) {
			return false
		}
		if p == "*" {
			continue
		}
		if p != seg[i] {
			return false
		}
	}
	return len(pat) == len(seg)
}

// normalizeMeasurement lowercases and trims a hex measurement, returning "" for
// blank input. Kept local so the policy package does not pull in the issuer.
func normalizeMeasurement(m string) string {
	return strings.ToLower(strings.TrimSpace(m))
}
