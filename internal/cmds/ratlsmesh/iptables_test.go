//go:build linux

package ratlsmesh

import (
	"strconv"
	"testing"
)

func TestBuildPodIPSetRulesDualStack(t *testing.T) {
	rules := mustBuildPodIPSetRules(t, 15001, 1337, nil, map[iptablesFamily]string{
		iptablesFamilyIPv4: "10.0.0.1",
		iptablesFamilyIPv6: "fd00::10",
	})

	if len(rules) != 4 {
		t.Fatalf("expected 4 rules (2 OUTPUT + 2 PREROUTING DNAT), got %d", len(rules))
	}

	// Rule 1: IPv4 OUTPUT REDIRECT, owner exclusion for the proxy UID.
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
	assertContains(t, "rule 1", r1.args, "-j", "REDIRECT")
	assertContains(t, "rule 1", r1.args, "--to-port", "15001")

	// Rule 2: IPv4 PREROUTING DNAT to nodeIP:15001. PREROUTING has no socket
	// owner so no UID exclusion; loop prevention comes from the LOCAL-PODS
	// src match (the proxy on hostNetwork has src=nodeIP, not in the set).
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
	assertContains(t, "rule 2", r2.args, "-j", "DNAT")
	assertContains(t, "rule 2", r2.args, "--to-destination", "10.0.0.1:15001")
	assertArgNotContains(t, "rule 2", r2.args, "REDIRECT")
	assertArgNotContains(t, "rule 2", r2.args, "--to-port")
	assertArgNotContains(t, "rule 2", r2.args, "--uid-owner")

	// Rule 3: IPv6 OUTPUT REDIRECT.
	r3 := rules[2]
	if r3.family != iptablesFamilyIPv6 {
		t.Errorf("rule 3: family=%q, want IPv6", r3.family)
	}
	assertContains(t, "rule 3", r3.args, "--match-set", podIPSetName6)
	assertContains(t, "rule 3", r3.args, "-j", "REDIRECT")

	// Rule 4: IPv6 PREROUTING DNAT to [nodeIP]:15001.
	r4 := rules[3]
	if r4.chain != preroutingChainName || r4.family != iptablesFamilyIPv6 {
		t.Errorf("rule 4: chain=%q family=%q, want %s/IPv6", r4.chain, r4.family, preroutingChainName)
	}
	assertContains(t, "rule 4", r4.args, "-j", "DNAT")
	assertContains(t, "rule 4", r4.args, "--to-destination", "[fd00::10]:15001")
	assertArgNotContains(t, "rule 4", r4.args, "REDIRECT")
}

// TestBuildPodIPSetRulesIPv4Only asserts that an IPv4-only node IP installs
// IPv4 OUTPUT+PREROUTING but skips the IPv6 PREROUTING rule entirely — no
// REDIRECT fallback, which would silently reintroduce the AKS bug for IPv6.
func TestBuildPodIPSetRulesIPv4Only(t *testing.T) {
	rules := mustBuildPodIPSetRules(t, 15001, 1337, nil, map[iptablesFamily]string{
		iptablesFamilyIPv4: "10.0.0.1",
	})

	if len(rules) != 3 {
		t.Fatalf("expected 3 rules (2 OUTPUT + 1 IPv4 PREROUTING), got %d", len(rules))
	}
	assertContains(t, "ipv4 prerouting", rules[1].args, "-j", "DNAT")
	assertContains(t, "ipv4 prerouting", rules[1].args, "--to-destination", "10.0.0.1:15001")
	for _, r := range rules {
		if r.chain == preroutingChainName && r.family == iptablesFamilyIPv6 {
			t.Fatalf("IPv6 PREROUTING rule must not be emitted without an IPv6 node IP; got %+v", r)
		}
	}
}

// TestBuildPodIPSetRulesIPv6Only mirrors the v4-only case for v6 single-stack.
func TestBuildPodIPSetRulesIPv6Only(t *testing.T) {
	rules := mustBuildPodIPSetRules(t, 15001, 1337, nil, map[iptablesFamily]string{
		iptablesFamilyIPv6: "fd00::10",
	})

	if len(rules) != 3 {
		t.Fatalf("expected 3 rules (2 OUTPUT + 1 IPv6 PREROUTING), got %d", len(rules))
	}
	for _, r := range rules {
		if r.chain == preroutingChainName && r.family == iptablesFamilyIPv4 {
			t.Fatalf("IPv4 PREROUTING rule must not be emitted without an IPv4 node IP; got %+v", r)
		}
	}
	var ipv6Prerouting *iptablesRule
	for i, r := range rules {
		if r.chain == preroutingChainName && r.family == iptablesFamilyIPv6 {
			ipv6Prerouting = &rules[i]
		}
	}
	if ipv6Prerouting == nil {
		t.Fatal("expected an IPv6 PREROUTING DNAT rule")
	}
	assertContains(t, "ipv6 prerouting", ipv6Prerouting.args, "-j", "DNAT")
	assertContains(t, "ipv6 prerouting", ipv6Prerouting.args, "--to-destination", "[fd00::10]:15001")
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
			rules := mustBuildPodIPSetRules(t, 15001, 1337, tt.excludeUIDs, map[iptablesFamily]string{
				iptablesFamilyIPv4: "10.0.0.1",
				iptablesFamilyIPv6: "fd00::10",
			})
			if want := len(tt.excludeUIDs) + 4; len(rules) != want {
				t.Fatalf("got %d rules, want %d (%d exclude + 4 ipset rules)", len(rules), want, len(tt.excludeUIDs))
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
			// Ipset rules still present after the excludes.
			ipsetRules := rules[len(tt.excludeUIDs):]
			assertContains(t, "rule 1", ipsetRules[0].args, "--dport", "1:65535")
			assertContains(t, "rule 2", ipsetRules[1].args, "--dport", "1:65535")
		})
	}
}

func TestMakeDNATRulePanicsOnEmptyDestination(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("makeDNATRule with empty toDestination should panic; it did not")
		}
	}()
	_ = makeDNATRule(dnatRuleSpec{
		chain:       preroutingChainName,
		family:      iptablesFamilyIPv4,
		labelPrefix: "test",
		dportRange:  "1:65535",
	})
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
	for i, jump := range append(jumpRules(), cwJumpRule()) {
		if len(jump.args) != 2 || jump.args[0] != "-j" {
			t.Fatalf("jump %d args = %v; isJumpAtHead requires {\"-j\", <chain>}", i, jump.args)
		}
	}
}

func TestCWJumpRule(t *testing.T) {
	jump := cwJumpRule()
	if jump.table != "filter" {
		t.Errorf("cw jump: table=%q, want filter", jump.table)
	}
	if jump.chain != "FORWARD" {
		t.Errorf("cw jump: chain=%q, want FORWARD", jump.chain)
	}
	assertContains(t, "cw jump", jump.args, "-j", cwChainName)
}

func TestBuildCWGuardRules(t *testing.T) {
	rules := buildCWGuardRules()
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules (RETURN + DROP per family), got %d", len(rules))
	}
	for _, spec := range []struct {
		family  iptablesFamily
		setName string
		ret     iptablesRule
		drop    iptablesRule
	}{
		{iptablesFamilyIPv4, cwPodIPSetName4, rules[0], rules[1]},
		{iptablesFamilyIPv6, cwPodIPSetName6, rules[2], rules[3]},
	} {
		for _, r := range []iptablesRule{spec.ret, spec.drop} {
			if r.table != "filter" || r.chain != cwChainName {
				t.Errorf("%s: table=%q chain=%q, want filter/%s", spec.family, r.table, r.chain, cwChainName)
			}
			if r.family != spec.family {
				t.Errorf("rule family=%q, want %q", r.family, spec.family)
			}
			assertContains(t, "cw guard", r.args, "--match-set", spec.setName)
			// No -p match: non-TCP inbound to a cw pod is unmeshed by
			// definition and must also be dropped.
			assertArgNotContains(t, "cw guard", r.args, "-p")
		}
		// The conntrack RETURN must precede the DROP so replies to cw-pod
		// egress pass.
		assertContains(t, "cw return", spec.ret.args, "--ctstate", "ESTABLISHED,RELATED")
		assertContains(t, "cw return", spec.ret.args, "-j", "RETURN")
		assertContains(t, "cw drop", spec.drop.args, "-j", "DROP")
		assertArgNotContains(t, "cw drop", spec.drop.args, "--ctstate")
	}
}

func mustBuildPodIPSetRules(t *testing.T, outboundPort, uid int, excludeUIDs []uint32, nodeIPs map[iptablesFamily]string) []iptablesRule {
	t.Helper()
	return buildPodIPSetRules(outboundPort, uid, excludeUIDs, nodeIPs)
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

// assertArgNotContains rejects any args entry equal to value or that starts
// with `value=`. The `value=` check catches single-token flag forms
// (e.g. `--to-port=15001`) which a substring-only matcher misses. Pass the
// exact token; iptables flag values (IPs, ports, UIDs) never begin with a
// flag-like prefix in this codebase, so the check is unambiguous in
// practice. To assert a value is absent (e.g. the literal "REDIRECT"),
// pass the token form, not a fragment.
func assertArgNotContains(t *testing.T, label string, args []string, value string) {
	t.Helper()
	prefix := value + "="
	for _, a := range args {
		if a == value || (len(a) > len(prefix) && a[:len(prefix)] == prefix) {
			t.Errorf("%s: args %v unexpectedly contain %s", label, args, value)
			return
		}
	}
}
