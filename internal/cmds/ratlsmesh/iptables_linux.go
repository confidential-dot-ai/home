//go:build linux

package ratlsmesh

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/coreos/go-iptables/iptables"

	"github.com/lunal-dev/c8s/pkg/certutil"
)

func parseExcludeUIDs(excludeUIDsStr string) ([]uint32, error) {
	var excludeUIDs []uint32
	for _, s := range strings.Split(excludeUIDsStr, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude-uid %q: %w", s, err)
		}
		excludeUIDs = append(excludeUIDs, uint32(v))
	}
	return excludeUIDs, nil
}

var managedChainNames = []string{chainName, preroutingChainName}

// iptablesV4 and iptablesV6 are the per-protocol netfilter clients used for
// every NAT-table mutation. Set once at the top of runIptablesSync /
// runIptablesCleanup and treated as immutable thereafter.
var (
	iptablesV4 *iptables.IPTables
	iptablesV6 *iptables.IPTables
)

func initIptablesClients() error {
	v4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return fmt.Errorf("init iptables (ipv4): %w", err)
	}
	v6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return fmt.Errorf("init iptables (ipv6): %w", err)
	}
	iptablesV4, iptablesV6 = v4, v6
	return nil
}

func iptablesClients() []*iptables.IPTables {
	return []*iptables.IPTables{iptablesV4, iptablesV6}
}

func familyForIPT(ipt *iptables.IPTables) iptablesFamily {
	if ipt.Proto() == iptables.ProtocolIPv6 {
		return iptablesFamilyIPv6
	}
	return iptablesFamilyIPv4
}

func iptablesLabel(ipt *iptables.IPTables) string {
	if ipt.Proto() == iptables.ProtocolIPv6 {
		return "ip6tables"
	}
	return "iptables"
}

func installIptablesRules(logger *slog.Logger, rules []iptablesRule, jumps []iptablesRule) error {
	// Flush handles the crash-without-preStop restart where stale rules
	// linger and Append would duplicate. Redundant when reconcileLiveSetMaxElem
	// just ran, but cheap.
	if err := flushManagedIptablesChains(logger); err != nil {
		return err
	}
	for _, ipt := range iptablesClients() {
		family := familyForIPT(ipt)
		for _, r := range rules {
			if r.family != iptablesFamilyAll && r.family != family {
				continue
			}
			if err := ipt.Append(r.table, r.chain, r.args...); err != nil {
				return fmt.Errorf("install %s rule on %s: %w", r.label, iptablesLabel(ipt), err)
			}
			logger.Info("rule installed", "bin", iptablesLabel(ipt), "chain", r.chain, "dport", r.label)
		}

		if err := ensureIptablesJumpsForBinary(logger, ipt, jumps); err != nil {
			return err
		}
	}
	return nil
}

// flushManagedIptablesChains creates (idempotent) and flushes our managed
// chains. Exported so the ipset reconciler can call it before destroying live
// sets that may still be referenced by stale rules from a previous process
// that exited abruptly.
func flushManagedIptablesChains(logger *slog.Logger) error {
	for _, ipt := range iptablesClients() {
		bin := iptablesLabel(ipt)
		for _, chain := range managedChainNames {
			if err := ipt.NewChain("nat", chain); err != nil {
				logger.Debug("chain already exists (expected on restart)", "bin", bin, "chain", chain)
			} else {
				logger.Info("chain created", "bin", bin, "chain", chain)
			}
			if err := ipt.ClearChain("nat", chain); err != nil {
				return fmt.Errorf("flush chain %s on %s: %w", chain, bin, err)
			}
			logger.Info("chain flushed", "bin", bin, "chain", chain)
		}
	}
	return nil
}

func ensureIptablesJumps(logger *slog.Logger, jumps []iptablesRule) error {
	for _, ipt := range iptablesClients() {
		if err := ensureIptablesJumpsForBinary(logger, ipt, jumps); err != nil {
			return err
		}
	}
	return nil
}

// ensureIptablesJumpsForBinary keeps base-chain jumps at position 1 so the
// mesh rules run before kube-proxy's service DNAT. If a jump is already at
// position 1 the call is a cheap no-op; otherwise the jump is re-inserted
// at the head. Two separate counters distinguish:
//   - jumpPositionViolations: confirmed-misplaced jumps (real kube-proxy race)
//   - jumpPositionCheckErrors: transient List failures where the watchdog
//     still reinserts defensively but the position couldn't be read
//
// Keeping the violation counter clean makes
// rate(ratls_mesh_iptables_jump_position_violations_total) a usable alert
// signal for kube-proxy contention without the noise of shell-call blips.
func ensureIptablesJumpsForBinary(logger *slog.Logger, ipt *iptables.IPTables, jumps []iptablesRule) error {
	bin := iptablesLabel(ipt)
	family := familyForIPT(ipt)
	for _, jump := range jumps {
		if jump.family != iptablesFamilyAll && jump.family != family {
			continue
		}
		atHead, present, err := isJumpAtHead(ipt, jump)
		if err != nil {
			logger.Debug("position check failed; will reinstall defensively", "bin", bin, "chain", jump.chain, "error", err)
			jumpPositionCheckErrors.Add(1)
			publishIptablesMetrics(logger)
		}
		if atHead {
			continue
		}
		deleteAllIptablesRules(logger, ipt, jump)
		if addErr := ipt.Insert(jump.table, jump.chain, 1, jump.args...); addErr != nil {
			return fmt.Errorf("install %s jump rule on %s: %w", jump.label, bin, addErr)
		}
		// Only count as a violation when we know the jump was demoted; a
		// position-check error or an absent jump during clean startup would
		// inflate the count and drown the kube-proxy-race signal in noise.
		if err == nil && present {
			jumpPositionViolations.Add(1)
			publishIptablesMetrics(logger)
		}
		logger.Warn("jump rule restored at chain head", "bin", bin, "chain", jump.chain, "target", jump.label, "present_before_restore", present, "check_error", err)
	}
	return nil
}

// isJumpAtHead reports whether the given jump rule is present and whether it
// is the first appended rule of its base chain. The literal compare against
// strings.Join(jump.args, " ") only round-trips while jump.args stays at {"-j",
// chainName}; adding matchers (`-m comment`, conntrack, etc.) would let the
// kernel renormalize tokens and make the compare always false, causing the
// watchdog to reinsert every tick.
func isJumpAtHead(ipt *iptables.IPTables, jump iptablesRule) (atHead bool, present bool, err error) {
	lines, err := ipt.List(jump.table, jump.chain)
	if err != nil {
		return false, false, err
	}
	atHead, present = parseJumpAtHead(strings.Join(lines, "\n"), jump)
	return atHead, present, nil
}

func parseJumpAtHead(out string, jump iptablesRule) (atHead bool, present bool) {
	prefix := "-A " + jump.chain + " "
	want := strings.Join(jump.args, " ")
	firstRule := true
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		got := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		if got == want {
			return firstRule, true
		}
		firstRule = false
	}
	return false, false
}

// jumpPositionViolations counts confirmed kube-proxy races: the watchdog
// observed our jump demoted out of position 1 and reinserted it. Exposed as
// ratls_mesh_iptables_jump_position_violations_total.
var jumpPositionViolations atomic.Int64

// jumpPositionCheckErrors counts ticks where the position check itself failed
// (e.g. iptables.List returned an error). The watchdog still reinserts
// defensively, but the cause is environmental, not a real race. Exposed as
// ratls_mesh_iptables_jump_position_check_errors_total so operators can
// alert on the two signals independently.
var jumpPositionCheckErrors atomic.Int64

func iptablesJumpPositionViolations() int64 {
	return jumpPositionViolations.Load()
}

func iptablesJumpPositionCheckErrors() int64 {
	return jumpPositionCheckErrors.Load()
}

func runIptablesCleanup() error {
	logger := certutil.NewJSONLogger("info")
	if err := initIptablesClients(); err != nil {
		return err
	}
	jumps := jumpRules()

	for _, ipt := range iptablesClients() {
		bin := iptablesLabel(ipt)
		for _, jump := range jumps {
			deleteAllIptablesRules(logger, ipt, jump)
		}

		for _, chain := range managedChainNames {
			if err := ipt.ClearChain("nat", chain); err != nil {
				logger.Warn("flush chain failed (may not exist)", "bin", bin, "chain", chain)
			}
			if err := ipt.DeleteChain("nat", chain); err != nil {
				logger.Warn("delete chain failed (may not exist)", "bin", bin, "chain", chain)
			} else {
				logger.Info("chain removed", "bin", bin, "chain", chain)
			}
		}
	}
	cleanupPodIPSets(logger)
	return nil
}

// deleteAllIptablesRules removes every instance of rule from its chain. The
// loop exits when iptables returns "rule does not exist" (the idempotent
// happy path) or any other error (logged as stop_reason).
func deleteAllIptablesRules(logger *slog.Logger, ipt *iptables.IPTables, rule iptablesRule) {
	bin := iptablesLabel(ipt)
	deleted := 0
	var stopErr error
	for {
		err := ipt.Delete(rule.table, rule.chain, rule.args...)
		if err == nil {
			deleted++
			continue
		}
		// IsNotExist is the expected end of an idempotent delete loop and
		// must not surface as a stop_reason; treat it as a clean break.
		var iptErr *iptables.Error
		if errors.As(err, &iptErr) && iptErr.IsNotExist() {
			break
		}
		stopErr = err
		break
	}
	if deleted == 0 {
		logger.Debug("rule not found", "bin", bin, "chain", rule.chain, "target", rule.label, "stop_reason", stopErr)
		return
	}
	logger.Info("rule removed", "bin", bin, "chain", rule.chain, "target", rule.label, "count", deleted, "stop_reason", stopErr)
}
