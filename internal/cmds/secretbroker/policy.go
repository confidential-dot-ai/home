package secretbroker

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// PeerIdentity is the attestation-rooted identity the broker derives from a
// verified caller TLS connection. Measurement is the lowercase-hex SHA-384
// launch digest (set only in --peer-verify=ratls mode, where the hardware
// chain has been verified); WorkloadID is the caller's CDS-issued SAN/CN.
type PeerIdentity struct {
	Measurement string
	WorkloadID  string
}

// Rule is one entry in the release policy. A rule matches a PeerIdentity when
// every constraint it sets is satisfied:
//
//   - Measurements: if non-empty, the caller's measurement must be one of these
//     (a rule that constrains on measurement can therefore never match in
//     --peer-verify=ca mode, where no measurement is available — fail closed).
//   - WorkloadID: if non-empty and not "*", must equal the caller's WorkloadID.
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
	Measurements []string `json:"measurements,omitempty"`
	WorkloadID   string   `json:"workloadId,omitempty"`
	Allow        []string `json:"allow"`
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
	for i, r := range p.Rules {
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
