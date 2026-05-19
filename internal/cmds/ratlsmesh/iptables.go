//go:build linux

package ratlsmesh

import (
	"fmt"
	"strconv"
)

// chainName is the dedicated iptables chain for locally generated traffic.
// preroutingChainName handles forwarded pod traffic entering the host network
// namespace from pod veth interfaces. Keeping them separate avoids using the
// owner match in PREROUTING, where packets do not have a local socket owner.
const chainName = "RATLS-MESH"
const preroutingChainName = "RATLS-MESH-PREROUTING"

const (
	podIPSetName4      = "RATLS-MESH-PODS"
	podIPSetName6      = "RATLS-MESH-PODS6"
	localPodIPSetName4 = "RATLS-MESH-LOCAL-PODS"
	localPodIPSetName6 = "RATLS-MESH-LOCAL-PODS6"
)

// defaultProxyUID is the UID under which the ratls-mesh sidecar proxy runs.
// Traffic from this UID is excluded from iptables redirect to avoid loops.
// This follows the Istio/Envoy convention of UID 1337.
const defaultProxyUID = 1337

const defaultIPSetMaxElem = 262144

type iptablesRule struct {
	table  string
	chain  string
	label  string
	family iptablesFamily
	args   []string
}

type iptablesFamily string

const (
	iptablesFamilyAll  iptablesFamily = ""
	iptablesFamilyIPv4 iptablesFamily = "ipv4"
	iptablesFamilyIPv6 iptablesFamily = "ipv6"
)

// buildPodIPSetRules computes NAT rules that redirect pod TCP traffic through
// the mesh. OUTPUT rules cover host-originated packets to pod IPs and can use
// owner matching; PREROUTING rules cover pod veth traffic and require both the
// source and destination to be known pod IPs.
func buildPodIPSetRules(outboundPort, uid int, excludeUIDs []uint32) []iptablesRule {
	portStr := strconv.Itoa(outboundPort)
	uidStr := strconv.Itoa(uid)
	allPortsRange := "1:65535"

	rules := buildExcludeUIDRules(chainName, excludeUIDs)

	for _, spec := range []struct {
		family       iptablesFamily
		dstSetName   string
		localSetName string
	}{
		{iptablesFamilyIPv4, podIPSetName4, localPodIPSetName4},
		{iptablesFamilyIPv6, podIPSetName6, localPodIPSetName6},
	} {
		rules = append(rules, makeRedirectRule(redirectRuleSpec{
			chain:              chainName,
			family:             spec.family,
			labelPrefix:        "output-pod-ipset",
			matchArgs:          []string{"-m", "set", "--match-set", spec.dstSetName, "dst"},
			withOwnerExclusion: true,
			uidStr:             uidStr,
			portStr:            portStr,
			dportRange:         allPortsRange,
		}))
		rules = append(rules, makeRedirectRule(redirectRuleSpec{
			chain:       preroutingChainName,
			family:      spec.family,
			labelPrefix: "prerouting-pod-ipset",
			matchArgs: []string{
				"-m", "set", "--match-set", spec.localSetName, "src",
				"-m", "set", "--match-set", spec.dstSetName, "dst",
			},
			uidStr:     uidStr,
			portStr:    portStr,
			dportRange: allPortsRange,
		}))
	}
	return rules
}

// buildExcludeUIDRules emits RETURN rules so system UIDs (e.g. root/0) skip
// the redirect, letting kubelet, containerd, and other host daemons reach
// container registries without going through the mesh.
func buildExcludeUIDRules(chain string, excludeUIDs []uint32) []iptablesRule {
	var rules []iptablesRule
	for _, euid := range excludeUIDs {
		rules = append(rules, iptablesRule{
			table: "nat",
			chain: chain,
			label: fmt.Sprintf("exclude-uid-%d", euid),
			args: []string{
				"-p", "tcp",
				"-m", "owner", "--uid-owner", strconv.FormatUint(uint64(euid), 10),
				"-j", "RETURN",
			},
		})
	}
	return rules
}

type redirectRuleSpec struct {
	chain              string
	family             iptablesFamily
	labelPrefix        string
	matchArgs          []string
	withOwnerExclusion bool
	uidStr             string
	portStr            string
	dportRange         string
}

func makeRedirectRule(spec redirectRuleSpec) iptablesRule {
	label := spec.dportRange
	if spec.labelPrefix != "" {
		label = spec.labelPrefix + "-" + spec.dportRange
	}
	args := []string{"-p", "tcp"}
	args = append(args, spec.matchArgs...)
	if spec.withOwnerExclusion {
		args = append(args, "-m", "owner", "!", "--uid-owner", spec.uidStr)
	}
	args = append(args,
		"--dport", spec.dportRange,
		"-j", "REDIRECT", "--to-port", spec.portStr,
	)
	return iptablesRule{
		table:  "nat",
		chain:  spec.chain,
		label:  label,
		family: spec.family,
		args:   args,
	}
}

// jumpRules returns the base-chain jumps into ratls-mesh managed chains.
func jumpRules() []iptablesRule {
	return []iptablesRule{
		{
			table: "nat",
			chain: "OUTPUT",
			label: "jump-output-to-" + chainName,
			args:  []string{"-j", chainName},
		},
		{
			table: "nat",
			chain: "PREROUTING",
			label: "jump-prerouting-to-" + preroutingChainName,
			args:  []string{"-j", preroutingChainName},
		},
	}
}
