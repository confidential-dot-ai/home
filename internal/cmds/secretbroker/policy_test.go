package secretbroker

import (
	"os"
	"path/filepath"
	"testing"
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

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.json")
	mustWrite(t, good, `{"rules":[{"workloadId":"api","allow":["secret/data/api/*"]}]}`)
	if _, err := LoadPolicy(good); err != nil {
		t.Fatalf("good policy rejected: %v", err)
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
