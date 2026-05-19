package ratlsmesh

import (
	"fmt"
	"strconv"
)

// chainName is the dedicated iptables chain for ratls-mesh rules. Using a
// custom chain allows atomic flush-and-replace on startup, preventing stale
// rules from persisting after crashes or version changes.
const chainName = "RATLS-MESH"

type iptablesRule struct {
	table string
	chain string
	label string
	args  []string
}

// buildRules computes the two NAT rules that redirect all TCP traffic
// (except from the mesh UID) to the outbound listener port. The port range
// [outboundPort-1, inboundPort] is excluded to avoid redirecting mesh traffic.
// Rules are placed in the custom RATLS-MESH chain, not directly in OUTPUT.
func buildRules(outboundPort, inboundPort, uid int, excludeUIDs []int) []iptablesRule {
	portStr := strconv.Itoa(outboundPort)
	uidStr := strconv.Itoa(uid)
	lowRange := fmt.Sprintf("1:%d", outboundPort-2)
	highRange := fmt.Sprintf("%d:65535", inboundPort+1)

	var rules []iptablesRule

	// Exclude system UIDs (e.g. root/0) so kubelet, containerd, and other
	// host daemons can reach container registries without being redirected.
	for _, euid := range excludeUIDs {
		rules = append(rules, iptablesRule{
			table: "nat",
			chain: chainName,
			label: fmt.Sprintf("exclude-uid-%d", euid),
			args: []string{
				"-p", "tcp",
				"-m", "owner", "--uid-owner", strconv.Itoa(euid),
				"-j", "RETURN",
			},
		})
	}

	makeRule := func(dportRange string) iptablesRule {
		return iptablesRule{
			table: "nat",
			chain: chainName,
			label: dportRange,
			args: []string{
				"-p", "tcp",
				"-m", "owner", "!", "--uid-owner", uidStr,
				"--dport", dportRange,
				"-j", "REDIRECT", "--to-port", portStr,
			},
		}
	}

	rules = append(rules, makeRule(lowRange), makeRule(highRange))
	return rules
}

// jumpRule returns the rule that jumps from OUTPUT to the custom RATLS-MESH chain.
func jumpRule() iptablesRule {
	return iptablesRule{
		table: "nat",
		chain: "OUTPUT",
		label: "jump-to-" + chainName,
		args:  []string{"-j", chainName},
	}
}
