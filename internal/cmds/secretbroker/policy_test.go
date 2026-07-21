package secretbroker

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestPathMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"secret/data/api/*", "secret/data/api/db", true},
		{"secret/data/api/*", "secret/data/api/db/pw", false}, // * is one segment
		{"secret/data/api/*", "secret/data/other/db", false},
		{"secret/data/team/**", "secret/data/team/a", true},
		{"secret/data/team/**", "secret/data/team/a/b/c", true},
		{"secret/data/team/**", "secret/data/other/a", false},
		{"secret/data/exact", "secret/data/exact", true},
		{"secret/data/exact", "secret/data/exact/more", false},
		{"secret/data/*", "secret/data", false}, // pattern longer than path
	}
	for _, c := range cases {
		if got := pathMatch(c.pattern, c.path); got != c.want {
			t.Errorf("pathMatch(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestRuleMatchesMeasurementGating(t *testing.T) {
	measRule := Rule{Measurements: []string{"AABBCC"}, Allow: []string{"secret/data/x"}}

	// ratls-mode caller with matching measurement (note: normalized to lower).
	if !ruleMatches(measRule, PeerIdentity{Measurement: "aabbcc", WorkloadID: "api"}) {
		t.Error("expected match for correct measurement")
	}
	// Wrong measurement: deny.
	if ruleMatches(measRule, PeerIdentity{Measurement: "ddeeff"}) {
		t.Error("expected deny for wrong measurement")
	}
	// ca-mode caller (no measurement) against a measurement-constrained rule:
	// must fail closed.
	if ruleMatches(measRule, PeerIdentity{WorkloadID: "api"}) {
		t.Error("expected deny when rule requires measurement but caller has none")
	}
}

func TestRuleMatchesWorkloadID(t *testing.T) {
	if !ruleMatches(Rule{WorkloadID: "*", Allow: []string{"x"}}, PeerIdentity{WorkloadID: "anything"}) {
		t.Error("wildcard workloadId should match any caller")
	}
	if ruleMatches(Rule{WorkloadID: "api", Allow: []string{"x"}}, PeerIdentity{WorkloadID: "evil"}) {
		t.Error("workloadId mismatch should deny")
	}
	// A ratls-mode caller carries no WorkloadID (the self-signed SAN is not read
	// as identity), so a workloadId-scoped rule must fail closed rather than
	// match on the empty value.
	if ruleMatches(Rule{WorkloadID: "api", Allow: []string{"x"}}, PeerIdentity{Measurement: "aabbcc"}) {
		t.Error("workloadId rule must fail closed for a caller with no WorkloadID")
	}
}

// testDigest returns a valid "sha256:" image digest whose last hex pair is b,
// so different b give distinct-but-well-formed digests.
func testDigest(b byte) string {
	return "sha256:" + strings.Repeat("ab", 31) + hexByte(b)
}

func hexByte(b byte) string {
	const hexdigits = "0123456789abcdef"
	return string([]byte{hexdigits[b>>4], hexdigits[b&0xf]})
}

func TestRuleMatchesWorkloadDigest(t *testing.T) {
	main := testDigest(0x01)
	dg, err := workloadclaims.Digest(nil, []string{main})
	if err != nil {
		t.Fatal(err)
	}
	rule := Rule{expectedWorkloadDigest: dg, Allow: []string{"secret/data/auth/*"}}

	// Caller presenting the bound attested digest: allow.
	if !ruleMatches(rule, PeerIdentity{WorkloadDigest: dg}) {
		t.Error("expected match for the bound workload digest")
	}
	// A different attested digest: deny.
	other := append([]byte(nil), dg...)
	other[0] ^= 0xff
	if ruleMatches(rule, PeerIdentity{WorkloadDigest: other}) {
		t.Error("expected deny for a different workload digest")
	}
	// No workload claim at all (ratls caller before its app is admitted, or a
	// ca leaf carrying no claims): fail closed.
	if ruleMatches(rule, PeerIdentity{WorkloadID: "auth"}) {
		t.Error("expected deny when a rule pins a workload but the caller has no digest")
	}
}

func TestLoadPolicyWorkloadImagesPrecompute(t *testing.T) {
	main := testDigest(0x02)
	path := filepath.Join(t.TempDir(), "policy.json")
	body := `{"rules":[{"workloadImages":{"main":["` + main + `"]},"allow":["secret/data/auth/db#password"]}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := workloadclaims.Digest(nil, []string{main})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Rules[0].expectedWorkloadDigest, want) {
		t.Fatal("LoadPolicy did not precompute the workload digest")
	}
}

func TestLoadPolicyWorkloadImagesRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"malformed digest": `{"rules":[{"workloadImages":{"main":["not-a-digest"]},"allow":["secret/data/x"]}]}`,
		"no main image":    `{"rules":[{"workloadImages":{"init":["` + testDigest(0x03) + `"]},"allow":["secret/data/x"]}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPolicy(path); err == nil {
				t.Fatalf("expected LoadPolicy to reject %s", name)
			}
		})
	}
}

func TestAllowedPathsDenyByDefault(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{WorkloadID: "api", Allow: []string{"secret/data/api/*"}},
		{WorkloadID: "*", Allow: []string{"secret/data/shared/*"}},
	}}

	// api caller gets its own paths plus the shared rule (union).
	got := p.AllowedPaths(PeerIdentity{WorkloadID: "api"})
	if len(got) != 2 {
		t.Fatalf("expected 2 granted globs for api, got %v", got)
	}
	// Unknown caller still matches the wildcard rule only.
	got = p.AllowedPaths(PeerIdentity{WorkloadID: "stranger"})
	if len(got) != 1 || got[0] != "secret/data/shared/*" {
		t.Fatalf("stranger should only get shared, got %v", got)
	}
	if pathAllowed(got, "secret/data/api/db") {
		t.Error("stranger must not reach api paths")
	}
}

// allowedFields decides what handleKVRead filters to: an unscoped matching
// entry grants everything; otherwise the union of the matching entries' fields.
func TestAllowedFields(t *testing.T) {
	tests := []struct {
		name     string
		allow    []string
		path     string
		wantAll  bool
		wantSet  []string
		checkSet bool
	}{
		{name: "unscoped path grants all fields", allow: []string{"secret/data/api/*"}, path: "secret/data/api/db", wantAll: true},
		{name: "single field scope", allow: []string{"secret/data/api/*#password"}, path: "secret/data/api/db", wantSet: []string{"password"}, checkSet: true},
		{name: "multi-field union across entries", allow: []string{"secret/data/api/db#password", "secret/data/api/*#api_key"}, path: "secret/data/api/db", wantSet: []string{"password", "api_key"}, checkSet: true},
		{name: "unscoped entry wins over scoped", allow: []string{"secret/data/api/db#password", "secret/data/api/db"}, path: "secret/data/api/db", wantAll: true},
		{name: "non-matching entry ignored", allow: []string{"secret/data/other/*#password"}, path: "secret/data/api/db", checkSet: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields, all := allowedFields(tt.allow, tt.path)
			if all != tt.wantAll {
				t.Fatalf("allFields = %v, want %v", all, tt.wantAll)
			}
			if tt.checkSet {
				if len(fields) != len(tt.wantSet) {
					t.Fatalf("fields = %v, want %v", fields, tt.wantSet)
				}
				for _, f := range tt.wantSet {
					if _, ok := fields[f]; !ok {
						t.Fatalf("missing field %q in %v", f, fields)
					}
				}
			}
		})
	}

	// pathAllowed must match on the path portion, ignoring the field scope.
	if !pathAllowed([]string{"secret/data/api/*#password"}, "secret/data/api/db") {
		t.Error("field-scoped entry must still grant its path")
	}
}

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.json")
	mustWrite(t, good, `{"rules":[{"workloadId":"api","allow":["secret/data/api/*","secret/data/api/db#password"]}]}`)
	if _, err := LoadPolicy(good); err != nil {
		t.Fatalf("good policy rejected: %v", err)
	}

	emptyField := filepath.Join(dir, "emptyfield.json")
	mustWrite(t, emptyField, `{"rules":[{"workloadId":"api","allow":["secret/data/api/db#"]}]}`)
	if _, err := LoadPolicy(emptyField); err == nil {
		t.Error("allow entry with a trailing '#' but no field must be rejected")
	}
	emptyField2 := filepath.Join(dir, "emptyfield2.json")
	mustWrite(t, emptyField2, `{"rules":[{"workloadId":"api","allow":["secret/data/api/db#password,"]}]}`)
	if _, err := LoadPolicy(emptyField2); err == nil {
		t.Error("allow entry with an empty field in the list must be rejected")
	}

	empty := filepath.Join(dir, "empty.json")
	mustWrite(t, empty, `{"rules":[]}`)
	if _, err := LoadPolicy(empty); err == nil {
		t.Error("empty policy must be rejected (denies everything)")
	}

	noAllow := filepath.Join(dir, "noallow.json")
	mustWrite(t, noAllow, `{"rules":[{"workloadId":"api","allow":[]}]}`)
	if _, err := LoadPolicy(noAllow); err == nil {
		t.Error("rule with empty allow must be rejected")
	}

	unknown := filepath.Join(dir, "unknown.json")
	mustWrite(t, unknown, `{"rules":[{"workloadId":"api","allow":["x"]}],"oops":1}`)
	if _, err := LoadPolicy(unknown); err == nil {
		t.Error("unknown fields must be rejected")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
