//go:build linux

package ratlsmesh

import (
	"strconv"
	"testing"
)

func TestBuildPodIPSetRules(t *testing.T) {
	rules := mustBuildPodIPSetRules(t, 15001, 1337, nil)

	if len(rules) != 4 {
		t.Fatalf("expected 4 rules (2 OUTPUT + 2 PREROUTING), got %d", len(rules))
	}

	// Rule 1: IPv4 OUTPUT all TCP ports.
	r1 := rules[0]
	if r1.table != "nat" || r1.chain != chainName {
		t.Errorf("rule 1: table=%q chain=%q, want nat/%s", r1.table, r1.chain, chainName)
	}
	if r1.family != iptablesFamilyIPv4 {
		t.Errorf("rule 1: family=%q, want IPv4", r1.family)
	}
	if r1.label != "output-pod-ipset-1:65535" {
		t.Errorf("rule 1: label=%q, want %q", r1.label, "output-pod-ipset-1:65535")
	}
	assertContains(t, "rule 1", r1.args, "--match-set", podIPSetName4)
	assertContains(t, "rule 1", r1.args, "--dport", "1:65535")
	assertContains(t, "rule 1", r1.args, "--uid-owner", "1337")
	assertContains(t, "rule 1", r1.args, "--to-port", "15001")

	// Rule 2: IPv4 PREROUTING all TCP ports. PREROUTING cannot use owner
	// matching, so it is constrained by source and destination pod ipsets.
	r2 := rules[1]
	if r2.chain != preroutingChainName {
		t.Errorf("rule 2: chain=%q, want %q", r2.chain, preroutingChainName)
	}
	if r2.family != iptablesFamilyIPv4 {
		t.Errorf("rule 2: family=%q, want IPv4", r2.family)
	}
	if r2.label != "prerouting-pod-ipset-1:65535" {
		t.Errorf("rule 2: label=%q, want %q", r2.label, "prerouting-pod-ipset-1:65535")
	}
	assertContains(t, "rule 2", r2.args, "--match-set", localPodIPSetName4)
	assertContains(t, "rule 2", r2.args, "--match-set", podIPSetName4)
	assertContains(t, "rule 2", r2.args, "--dport", "1:65535")
	assertContains(t, "rule 2", r2.args, "--to-port", "15001")
	assertNotContains(t, "rule 2", r2.args, "--uid-owner")

	// Rule 3: IPv6 OUTPUT all TCP ports.
	r3 := rules[2]
	if r3.family != iptablesFamilyIPv6 {
		t.Errorf("rule 3: family=%q, want IPv6", r3.family)
	}
	assertContains(t, "rule 3", r3.args, "--match-set", podIPSetName6)
}

func TestBuildPodIPSetRulesExcludeUIDs(t *testing.T) {
	tests := []struct {
		name        string
		excludeUIDs []uint32
	}{
		{name: "single", excludeUIDs: []uint32{0}},
		{name: "multiple", excludeUIDs: []uint32{0, 65534}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := mustBuildPodIPSetRules(t, 15001, 1337, tt.excludeUIDs)
			if want := len(tt.excludeUIDs) + 4; len(rules) != want {
				t.Fatalf("got %d rules, want %d (%d exclude + 4 ipset redirects)", len(rules), want, len(tt.excludeUIDs))
			}
			for i, uid := range tt.excludeUIDs {
				r := rules[i]
				uidStr := strconv.Itoa(int(uid))
				wantLabel := "exclude-uid-" + uidStr
				if r.label != wantLabel {
					t.Errorf("exclude rule %d: label=%q, want %q", i, r.label, wantLabel)
				}
				assertContains(t, wantLabel, r.args, "--uid-owner", uidStr)
				assertContains(t, wantLabel, r.args, "-j", "RETURN")
			}
			// Redirect rules still present after the excludes.
			redirects := rules[len(tt.excludeUIDs):]
			assertContains(t, "rule 1", redirects[0].args, "--dport", "1:65535")
			assertContains(t, "rule 2", redirects[1].args, "--dport", "1:65535")
		})
	}
}

func TestJumpRules(t *testing.T) {
	jumps := jumpRules()
	if len(jumps) != 2 {
		t.Fatalf("expected 2 jump rules, got %d", len(jumps))
	}
	if jumps[0].table != "nat" {
		t.Errorf("output jump rule: table=%q, want nat", jumps[0].table)
	}
	if jumps[0].chain != "OUTPUT" {
		t.Errorf("output jump rule: chain=%q, want OUTPUT", jumps[0].chain)
	}
	assertContains(t, "output jump", jumps[0].args, "-j", chainName)

	if jumps[1].table != "nat" {
		t.Errorf("prerouting jump rule: table=%q, want nat", jumps[1].table)
	}
	if jumps[1].chain != "PREROUTING" {
		t.Errorf("prerouting jump rule: chain=%q, want PREROUTING", jumps[1].chain)
	}
	assertContains(t, "prerouting jump", jumps[1].args, "-j", preroutingChainName)
}

// TestJumpRulesArgsShape guards the assumption isJumpAtHead relies on: each
// jump's args is exactly {"-j", chain}. Any matcher (e.g. -m comment, conntrack)
// would let iptables -S renormalize tokens, defeat the literal string compare
// in isJumpAtHead, and turn the watchdog into a reinsert-every-tick loop. Catch
// the regression here instead of in a noisy production race.
func TestJumpRulesArgsShape(t *testing.T) {
	for i, jump := range jumpRules() {
		if len(jump.args) != 2 || jump.args[0] != "-j" {
			t.Fatalf("jump %d args = %v; isJumpAtHead requires {\"-j\", <chain>}", i, jump.args)
		}
	}
}

func mustBuildPodIPSetRules(t *testing.T, outboundPort, uid int, excludeUIDs []uint32) []iptablesRule {
	t.Helper()
	return buildPodIPSetRules(outboundPort, uid, excludeUIDs)
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

func assertNotContains(t *testing.T, label string, args []string, value string) {
	t.Helper()
	for _, a := range args {
		if a == value {
			t.Errorf("%s: args %v unexpectedly contain %s", label, args, value)
		}
	}
}
