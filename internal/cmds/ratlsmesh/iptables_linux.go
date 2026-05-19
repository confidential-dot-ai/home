//go:build linux

package ratlsmesh

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/lunal-dev/c8s/pkg/certutil"
)

// defaultProxyUID is the UID under which the ratls-mesh sidecar proxy runs.
// Traffic from this UID is excluded from iptables redirect to avoid loops.
// This follows the Istio/Envoy convention of UID 1337.
const defaultProxyUID = 1337

func parseIptablesFlags(name string, args []string) ([]iptablesRule, iptablesRule, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	outboundPort := fs.Int("outbound-port", 15001, "outbound listener port")
	inboundPort := fs.Int("inbound-port", 15006, "inbound listener port")
	uid := fs.Int("uid", defaultProxyUID, "UID to exclude from redirect")
	excludeUIDsStr := fs.String("exclude-uids", "0", "comma-separated UIDs to skip (e.g. root=0 so kubelet/containerd can reach registries)")
	if err := fs.Parse(args); err != nil {
		return nil, iptablesRule{}, err
	}

	var excludeUIDs []int
	for _, s := range strings.Split(*excludeUIDsStr, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			return nil, iptablesRule{}, fmt.Errorf("invalid exclude-uid %q: %w", s, err)
		}
		excludeUIDs = append(excludeUIDs, v)
	}

	return buildRules(*outboundPort, *inboundPort, *uid, excludeUIDs), jumpRule(), nil
}

// iptablesBinaries lists the binaries for IPv4 and IPv6 NAT rules.
// Both must be configured to prevent IPv6 traffic from bypassing the mesh.
var iptablesBinaries = []string{"iptables", "ip6tables"}

func iptablesSetup(args []string) error {
	logger := certutil.NewJSONLogger("info")
	rules, jump, err := parseIptablesFlags("iptables-setup", args)
	if err != nil {
		return err
	}

	for _, bin := range iptablesBinaries {
		if err := runIptablesCmd(bin, []string{"-t", "nat", "-N", chainName}); err != nil {
			logger.Debug("chain already exists (expected on restart)", "bin", bin, "chain", chainName)
		} else {
			logger.Info("chain created", "bin", bin, "chain", chainName)
		}

		// Flush the chain so a restart after a crash with stale rules
		// (possibly from a different port config) starts clean.
		if err := runIptablesCmd(bin, []string{"-t", "nat", "-F", chainName}); err != nil {
			return fmt.Errorf("flush chain on %s: %w", bin, err)
		}
		logger.Info("chain flushed", "bin", bin, "chain", chainName)

		for _, r := range rules {
			addArgs := append([]string{"-t", r.table, "-A", r.chain}, r.args...)
			if err := runIptablesCmd(bin, addArgs); err != nil {
				return fmt.Errorf("install %s rule on %s: %w", r.label, bin, err)
			}
			logger.Info("rule installed", "bin", bin, "chain", r.chain, "dport", r.label)
		}

		// Ensure OUTPUT jumps to our chain (idempotent: check before add).
		checkArgs := append([]string{"-t", jump.table, "-C", jump.chain}, jump.args...)
		if runIptablesCmd(bin, checkArgs) == nil {
			logger.Info("jump rule already exists", "bin", bin)
			continue
		}
		addArgs := append([]string{"-t", jump.table, "-A", jump.chain}, jump.args...)
		if err := runIptablesCmd(bin, addArgs); err != nil {
			return fmt.Errorf("install jump rule on %s: %w", bin, err)
		}
		logger.Info("jump rule installed", "bin", bin, "chain", jump.chain)
	}
	return nil
}

func iptablesCleanup(args []string) error {
	logger := certutil.NewJSONLogger("info")
	_, jump, err := parseIptablesFlags("iptables-cleanup", args)
	if err != nil {
		return err
	}

	for _, bin := range iptablesBinaries {
		deleteArgs := append([]string{"-t", jump.table, "-D", jump.chain}, jump.args...)
		if err := runIptablesCmd(bin, deleteArgs); err != nil {
			logger.Warn("jump rule not found", "bin", bin, "label", jump.label)
		} else {
			logger.Info("jump rule removed", "bin", bin, "chain", jump.chain)
		}

		if err := runIptablesCmd(bin, []string{"-t", "nat", "-F", chainName}); err != nil {
			logger.Warn("flush chain failed (may not exist)", "bin", bin, "chain", chainName)
		}
		if err := runIptablesCmd(bin, []string{"-t", "nat", "-X", chainName}); err != nil {
			logger.Warn("delete chain failed (may not exist)", "bin", bin, "chain", chainName)
		} else {
			logger.Info("chain removed", "bin", bin, "chain", chainName)
		}
	}
	return nil
}

func runIptablesCmd(binary string, args []string) error {
	cmd := exec.Command(binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
