package ratlsmesh

import (
	"testing"
)

func TestBuildRules(t *testing.T) {
	rules := buildRules(15001, 15006, 1337, nil)

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	// Rule 1: ports 1:14999
	r1 := rules[0]
	if r1.table != "nat" || r1.chain != chainName {
		t.Errorf("rule 1: table=%q chain=%q, want nat/%s", r1.table, r1.chain, chainName)
	}
	if r1.label != "1:14999" {
		t.Errorf("rule 1: label=%q, want %q", r1.label, "1:14999")
	}
	assertContains(t, "rule 1", r1.args, "--dport", "1:14999")
	assertContains(t, "rule 1", r1.args, "--uid-owner", "1337")
	assertContains(t, "rule 1", r1.args, "--to-port", "15001")

	// Rule 2: ports 15007:65535
	r2 := rules[1]
	if r2.label != "15007:65535" {
		t.Errorf("rule 2: label=%q, want %q", r2.label, "15007:65535")
	}
	assertContains(t, "rule 2", r2.args, "--dport", "15007:65535")
	assertContains(t, "rule 2", r2.args, "--to-port", "15001")
}

func TestBuildRulesCustomPorts(t *testing.T) {
	rules := buildRules(20001, 20006, 1000, nil)

	r1 := rules[0]
	assertContains(t, "rule 1", r1.args, "--dport", "1:19999")
	assertContains(t, "rule 1", r1.args, "--uid-owner", "1000")
	assertContains(t, "rule 1", r1.args, "--to-port", "20001")

	r2 := rules[1]
	assertContains(t, "rule 2", r2.args, "--dport", "20007:65535")
}

func TestBuildRulesUseCustomChain(t *testing.T) {
	rules := buildRules(15001, 15006, 1337, nil)
	for i, r := range rules {
		if r.chain != chainName {
			t.Errorf("rule %d: chain=%q, want %q", i, r.chain, chainName)
		}
	}
}

func TestBuildRulesExcludeUIDs(t *testing.T) {
	rules := buildRules(15001, 15006, 1337, []int{0})

	// First rule should be the UID exclusion RETURN rule
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules (1 exclude + 2 redirect), got %d", len(rules))
	}
	r0 := rules[0]
	if r0.label != "exclude-uid-0" {
		t.Errorf("exclude rule: label=%q, want %q", r0.label, "exclude-uid-0")
	}
	assertContains(t, "exclude", r0.args, "--uid-owner", "0")
	assertContains(t, "exclude", r0.args, "-j", "RETURN")

	// Redirect rules still present after the exclude
	assertContains(t, "rule 1", rules[1].args, "--dport", "1:14999")
	assertContains(t, "rule 2", rules[2].args, "--dport", "15007:65535")
}

func TestBuildRulesMultipleExcludeUIDs(t *testing.T) {
	rules := buildRules(15001, 15006, 1337, []int{0, 65534})

	if len(rules) != 4 {
		t.Fatalf("expected 4 rules (2 exclude + 2 redirect), got %d", len(rules))
	}
	assertContains(t, "exclude-0", rules[0].args, "--uid-owner", "0")
	assertContains(t, "exclude-65534", rules[1].args, "--uid-owner", "65534")
}

func TestJumpRule(t *testing.T) {
	jump := jumpRule()
	if jump.table != "nat" {
		t.Errorf("jump rule: table=%q, want nat", jump.table)
	}
	if jump.chain != "OUTPUT" {
		t.Errorf("jump rule: chain=%q, want OUTPUT", jump.chain)
	}
	assertContains(t, "jump", jump.args, "-j", chainName)
}

// assertContains checks that args contains the flag followed by the expected value.
func assertContains(t *testing.T, label string, args []string, flag, want string) {
	t.Helper()
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == want {
			return
		}
	}
	t.Errorf("%s: args %v missing %s %s", label, args, flag, want)
}
