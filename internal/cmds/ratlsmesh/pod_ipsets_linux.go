//go:build linux

package ratlsmesh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/lunal-dev/c8s/pkg/certutil"
)

// ipsetOverflows counts reconcile cycles that observed more pod IPs than the
// configured --ipset-maxelem. Exposed via ratls_mesh_iptables_ipset_overflow_total
// so a silently-degrading sync is observable rather than warn-only.
var ipsetOverflows atomic.Int64

func iptablesIPSetOverflows() int64 {
	return ipsetOverflows.Load()
}

func runIptablesSync(ctx context.Context, cfg *iptablesSyncConfig) error {
	if err := validatePort("--outbound-port", cfg.outboundPort); err != nil {
		return err
	}
	if cfg.resyncPeriod <= 0 {
		return fmt.Errorf("resync-period must be positive")
	}
	if cfg.watchdogPeriod <= 0 {
		return fmt.Errorf("watchdog-period must be positive")
	}
	if cfg.ipsetMaxElem <= 0 {
		return fmt.Errorf("ipset-maxelem must be positive")
	}
	if len(cfg.nodeIPs) == 0 {
		if env := os.Getenv("NODE_IP"); env != "" {
			cfg.nodeIPs = []string{env}
		}
	}
	if len(cfg.nodeIPs) == 0 {
		return fmt.Errorf("node IP required: set --node-ip or NODE_IP env var")
	}
	nodeIPsByFamily, err := parseNodeIPs(cfg.nodeIPs)
	if err != nil {
		return err
	}
	if err := verifyNodeIPsLocal(nodeIPsByFamily); err != nil {
		return err
	}
	cfg.nodeIPs = canonicalNodeIPs(nodeIPsByFamily)
	excludeUIDs, err := parseExcludeUIDs(cfg.excludeUIDs)
	if err != nil {
		return err
	}
	rules := buildPodIPSetRules(cfg.outboundPort, cfg.uid, excludeUIDs, nodeIPsByFamily)
	jumps := jumpRules()

	logger := certutil.NewJSONLogger(cfg.logLevel)
	if err := initIptablesClients(); err != nil {
		return err
	}
	configureIptablesMetricsFile(cfg.metricsFile)
	publishIptablesMetrics(logger)
	if err := resetReadyFile(cfg.readyFile); err != nil {
		return err
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("k8s in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("k8s clientset: %w", err)
	}
	excludedSourceNamespaces := parseExcludedNamespaces(cfg.excludeSourceNamespaces)

	factory := informers.NewSharedInformerFactory(clientset, 0)
	podInformer := factory.Core().V1().Pods().Informer()
	syncCh := make(chan struct{}, 1)
	notifySync := func(interface{}) {
		select {
		case syncCh <- struct{}{}:
		default:
		}
	}
	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    notifySync,
		UpdateFunc: func(_, obj interface{}) { notifySync(obj) },
		DeleteFunc: notifySync,
	}); err != nil {
		return fmt.Errorf("iptables sync: add pod event handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return fmt.Errorf("iptables sync: pod cache sync failed")
	}
	if err := reconcileLiveSetMaxElem(logger, cfg.ipsetMaxElem); err != nil {
		return err
	}
	if err := reconcilePodIPSets(podInformer.GetStore(), cfg.nodeIPs, excludedSourceNamespaces, cfg.ipsetMaxElem, logger); err != nil {
		return err
	}
	if err := installIptablesRules(logger, rules, jumps); err != nil {
		return err
	}
	publishIptablesMetrics(logger)
	if cfg.readyFile != "" {
		if err := os.WriteFile(cfg.readyFile, []byte("ready\n"), 0o600); err != nil {
			return fmt.Errorf("write ready file: %w", err)
		}
	}
	logger.Info("iptables sync ready",
		"resync_period", cfg.resyncPeriod.String(),
		"watchdog_period", cfg.watchdogPeriod.String())

	// Jump watchdog: kube-proxy can reinsert KUBE-SERVICES at PREROUTING
	// position 1 during its periodic reconciliation, demoting our jump.
	// Re-asserting at a tight interval bounds the window in which Service
	// VIP traffic could be DNAT'd before our chain runs.
	go runJumpWatchdog(ctx, logger, jumps, cfg.watchdogPeriod)

	ticker := time.NewTicker(cfg.resyncPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-syncCh:
		}
		if err := reconcilePodIPSets(podInformer.GetStore(), cfg.nodeIPs, excludedSourceNamespaces, cfg.ipsetMaxElem, logger); err != nil {
			logger.Warn("pod ipset sync failed", "error", err)
			continue
		}
		publishIptablesMetrics(logger)
	}
}

func resetReadyFile(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale ready file %q: %w", path, err)
	}
	return nil
}

func runJumpWatchdog(ctx context.Context, logger *slog.Logger, jumps []iptablesRule, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := ensureIptablesJumps(logger, jumps); err != nil {
			logger.Warn("iptables jump watchdog failed", "error", err)
		}
	}
}

func reconcilePodIPSets(store cache.Store, nodeIPs []string, excludedSourceNamespaces map[string]struct{}, ipsetMaxElem int, logger *slog.Logger) error {
	sets := collectPodIPSetMembers(store.List(), nodeIPs, excludedSourceNamespaces)
	if sets.exceeds(ipsetMaxElem) {
		ipsetOverflows.Add(1)
		publishIptablesMetrics(logger)
	}
	for _, spec := range []struct {
		name    string
		family  string
		members []string
		label   string
	}{
		{podIPSetName4, "inet", sets.allIPv4, "IPv4 pod ipset"},
		{podIPSetName6, "inet6", sets.allIPv6, "IPv6 pod ipset"},
		{localPodIPSetName4, "inet", sets.localIPv4, "local IPv4 pod ipset"},
		{localPodIPSetName6, "inet6", sets.localIPv6, "local IPv6 pod ipset"},
	} {
		if err := replaceIPSetMembers(logger, spec.name, spec.family, spec.members, ipsetMaxElem); err != nil {
			return fmt.Errorf("sync %s: %w", spec.label, err)
		}
	}
	logger.Debug("pod ipsets reconciled", "ipv4", len(sets.allIPv4), "ipv6", len(sets.allIPv6), "local_ipv4", len(sets.localIPv4), "local_ipv6", len(sets.localIPv6))
	return nil
}

type podIPSetMembers struct {
	allIPv4   []string
	allIPv6   []string
	localIPv4 []string
	localIPv6 []string
}

func (m podIPSetMembers) exceeds(maxElem int) bool {
	return len(m.allIPv4) > maxElem ||
		len(m.allIPv6) > maxElem ||
		len(m.localIPv4) > maxElem ||
		len(m.localIPv6) > maxElem
}

func collectPodIPSetMembers(objs []interface{}, nodeIPs []string, excludedSourceNamespaces map[string]struct{}) podIPSetMembers {
	ourNodeIPs := make(map[string]struct{}, len(nodeIPs))
	for _, ip := range nodeIPs {
		if canon := normalizeIP(ip); canon != "" {
			ourNodeIPs[canon] = struct{}{}
		}
	}
	v4Set := make(map[string]struct{})
	v6Set := make(map[string]struct{})
	localV4Set := make(map[string]struct{})
	localV6Set := make(map[string]struct{})
	add := func(value string, v4Target, v6Target map[string]struct{}) {
		ip := net.ParseIP(value)
		if ip == nil {
			return
		}
		if ip.To4() != nil {
			v4Target[ip.String()] = struct{}{}
			return
		}
		v6Target[ip.String()] = struct{}{}
	}

	for _, obj := range objs {
		pod, ok := obj.(*corev1.Pod)
		if !ok || !podEligibleForMeshEndpoint(pod) {
			continue
		}
		localSource := podIsLocal(pod, ourNodeIPs) && podEligibleForMeshSource(pod, excludedSourceNamespaces)
		for _, ip := range podStatusIPs(pod) {
			add(ip, v4Set, v6Set)
			if localSource {
				add(ip, localV4Set, localV6Set)
			}
		}
	}

	return podIPSetMembers{
		allIPv4:   sortedKeys(v4Set),
		allIPv6:   sortedKeys(v6Set),
		localIPv4: sortedKeys(localV4Set),
		localIPv6: sortedKeys(localV6Set),
	}
}

// podIsLocal reports whether pod is scheduled on a node whose IP is in
// ourNodeIPs. Prefers Status.HostIPs (dual-stack list, k8s 1.27+) and falls
// back to Status.HostIP for older API objects. ourNodeIPs is keyed by the
// canonical net.IP.String() form so callers must pre-normalize.
func podIsLocal(pod *corev1.Pod, ourNodeIPs map[string]struct{}) bool {
	if len(ourNodeIPs) == 0 {
		return false
	}
	for _, h := range pod.Status.HostIPs {
		if _, ok := ourNodeIPs[normalizeIP(h.IP)]; ok {
			return true
		}
	}
	if pod.Status.HostIP != "" {
		if _, ok := ourNodeIPs[normalizeIP(pod.Status.HostIP)]; ok {
			return true
		}
	}
	return false
}

// parseNodeIPs validates raw --node-ip values and groups them by family.
// Rejects: empty input, invalid literals, unspecified (0.0.0.0 / ::),
// loopback (DNAT to loopback needs route_localnet=1 which we don't set),
// zone-scoped IPv6 (`fe80::1%eth0` — DNAT has no defined target for a
// zone-scoped address), IPv4-in-IPv6 literals in any RFC 4291 form
// (IPv4-mapped `::ffff:10.0.0.1` and its hex/expanded/mixed-case variants
// caught by netip.Addr.Is4In6, plus the deprecated IPv4-compatible
// `::1.2.3.4` caught by the dot-in-IPv6 heuristic — both ambiguous family;
// operator should pass the IPv4 form directly), and more than one address
// per family (the DNAT rule takes a single --to-destination per family).
func parseNodeIPs(raw []string) (map[iptablesFamily]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("at least one --node-ip required")
	}
	out := make(map[iptablesFamily]string, 2)
	for i, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, fmt.Errorf("--node-ip[%d]: empty value", i)
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("--node-ip[%d] %q: not a valid IP address", i, s)
		}
		if addr.Zone() != "" {
			return nil, fmt.Errorf("--node-ip[%d] %q: zone-scoped IPv6 is not supported; pass a global-scope address", i, s)
		}
		// Is4In6 covers RFC 4291 §2.5.5.2 IPv4-mapped in every notation
		// (dotted, hex-only, expanded, mixed-case). The dot-in-IPv6 check
		// catches the deprecated §2.5.5.1 IPv4-compatible form (`::1.2.3.4`),
		// which has no 0xff/0xff prefix so Is4In6 returns false.
		if addr.Is4In6() || (addr.Is6() && strings.ContainsRune(s, '.')) {
			return nil, fmt.Errorf("--node-ip[%d] %q: IPv4-in-IPv6 literal is ambiguous; pass the IPv4 form", i, s)
		}
		if addr.IsUnspecified() {
			return nil, fmt.Errorf("--node-ip[%d] %q: unspecified address (not a routable target for DNAT)", i, s)
		}
		if addr.IsLoopback() {
			return nil, fmt.Errorf("--node-ip[%d] %q: loopback address (DNAT to loopback requires route_localnet=1 on the input interface, which is not enabled)", i, s)
		}
		var family iptablesFamily
		if addr.Is4() {
			family = iptablesFamilyIPv4
		} else {
			family = iptablesFamilyIPv6
		}
		canonical := addr.String()
		if existing, dup := out[family]; dup {
			return nil, fmt.Errorf("--node-ip: multiple %s addresses (%s and %s); pass at most one per family", family, existing, canonical)
		}
		out[family] = canonical
	}
	return out, nil
}

// verifyNodeIPsLocal confirms each parsed nodeIP is bound to a local
// interface. DNAT to a non-local IP silently misroutes traffic off-node;
// REDIRECT's prior self-healing property (always retargeted the receive
// interface) is gone with DNAT, so we must catch a misconfigured --node-ip
// at startup rather than at first packet.
func verifyNodeIPsLocal(byFamily map[iptablesFamily]string) error {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("enumerate local interface addresses: %w", err)
	}
	return nodeIPsAreLocal(byFamily, addrs)
}

// nodeIPsAreLocal is the pure half of verifyNodeIPsLocal: given the parsed
// node IPs and a pre-fetched list of local interface addresses, return an
// error if any node IP is not bound locally. Extracted so the comparison
// can be unit-tested without manipulating real interfaces.
//
// byFamily values are assumed canonical (parseNodeIPs invariant) and
// net.IP.String() returns canonical form, so the two sides match directly
// without an extra normalize pass.
func nodeIPsAreLocal(byFamily map[iptablesFamily]string, localAddrs []net.Addr) error {
	local := make(map[string]struct{}, len(localAddrs))
	for _, a := range localAddrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if len(ip) > 0 {
			local[ip.String()] = struct{}{}
		}
	}
	for family, ip := range byFamily {
		if _, ok := local[ip]; !ok {
			return fmt.Errorf("--node-ip %s (%s) is not bound to any local interface; DNAT would misroute traffic off-node", ip, family)
		}
	}
	return nil
}

// canonicalNodeIPs returns the validated, family-grouped node IPs as a flat
// slice in deterministic order (IPv4 first, then IPv6). Used to repopulate
// cfg.nodeIPs with canonical forms after validation.
func canonicalNodeIPs(byFamily map[iptablesFamily]string) []string {
	out := make([]string, 0, len(byFamily))
	for _, f := range []iptablesFamily{iptablesFamilyIPv4, iptablesFamilyIPv6} {
		if ip, ok := byFamily[f]; ok {
			out = append(out, ip)
		}
	}
	return out
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// reconcileLiveSetMaxElem destroys any pre-existing managed ipset whose
// maxelem differs from what we want to write. The restore script uses
// `create … -exist` which silently succeeds only when params match; on a
// Helm upgrade that changes --ipset-maxelem after the prior pod exited
// abruptly (i.e. preStop never ran and cleanupPodIPSets didn't fire), the
// stale live set would otherwise block every reconcile.
//
// The destroy fails if any iptables rule still references the set, so we
// flush our managed chains between the probe and the destroy. The function
// returns early when no maxelem changed; installIptablesRules handles
// chain flushing on every other path.
func reconcileLiveSetMaxElem(logger *slog.Logger, desiredMaxElem int) error {
	names := []string{podIPSetName4, podIPSetName6, localPodIPSetName4, localPodIPSetName6}
	mismatched := make([]string, 0, len(names))
	priorMaxElem := make(map[string]int, len(names))
	for _, name := range names {
		actual, exists, err := readIPSetMaxElem(name)
		if err != nil {
			return fmt.Errorf("inspect ipset %s: %w", name, err)
		}
		if !exists || actual == desiredMaxElem {
			continue
		}
		logger.Info("ipset maxelem changed since last run", "set", name, "old_maxelem", actual, "new_maxelem", desiredMaxElem)
		mismatched = append(mismatched, name)
		priorMaxElem[name] = actual
	}
	if len(mismatched) == 0 {
		return nil
	}
	if err := flushManagedIptablesChains(logger); err != nil {
		return fmt.Errorf("pre-flush iptables chains for ipset rebuild: %w", err)
	}
	for _, name := range mismatched {
		if stderr, err := runIPSetCmdQuiet([]string{"destroy", name}); err != nil {
			return fmt.Errorf("destroy ipset %s for maxelem rebuild: %w (stderr=%q)", name, err, strings.TrimSpace(stderr))
		}
		logger.Info("destroyed live ipset to apply new maxelem", "set", name, "old_maxelem", priorMaxElem[name], "new_maxelem", desiredMaxElem)
	}
	return nil
}

// readIPSetMaxElem parses the `maxelem` field from `ipset list -t <name>`.
// Returns (0, false, nil) when the set does not exist; that's the common
// case on a clean start.
func readIPSetMaxElem(name string) (int, bool, error) {
	stdout, stderr, err := runIPSetCmdCapture([]string{"list", "-t", name})
	if err != nil {
		if strings.Contains(stderr, "does not exist") {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("ipset list -t %s: %w (stderr=%q)", name, err, strings.TrimSpace(stderr))
	}
	v, perr := parseIPSetMaxElemHeader(stdout)
	if perr != nil {
		return 0, true, fmt.Errorf("ipset %s: %w", name, perr)
	}
	return v, true, nil
}

// parseIPSetMaxElemHeader pulls `maxelem N` out of `ipset list -t` output.
// Header line shape is: `Header: family inet hashsize 1024 maxelem 262144 …`
// across ipset 6.x/7.x; field order is stable but the surrounding fields
// vary (e.g. comment, counters, skbinfo), so scan rather than hardcoding
// positions.
func parseIPSetMaxElemHeader(out string) (int, error) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Header:") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "maxelem" && i+1 < len(fields) {
				v, err := strconv.Atoi(fields[i+1])
				if err != nil {
					return 0, fmt.Errorf("parse maxelem %q: %w", fields[i+1], err)
				}
				return v, nil
			}
		}
		return 0, fmt.Errorf("header missing maxelem field: %q", line)
	}
	return 0, fmt.Errorf("no header line in ipset output")
}

func replaceIPSetMembers(logger *slog.Logger, name, family string, ips []string, maxElem int) error {
	tmpName := name + "-TMP"
	restoreScript, err := buildIPSetRestoreScript(name, family, ips, maxElem)
	if err != nil {
		return err
	}
	// A tmp set left behind by a crash may have been created with an older
	// maxelem. Destroy it first so the restore creates it with the requested
	// capacity. "Doesn't exist" is the common case and intentionally silent;
	// anything else is a real ipset error worth surfacing so a stuck pre-destroy
	// is not hidden behind the subsequent restore failure. A successful destroy
	// means a TMP set actually existed — log at Info so a prior crash leaves a
	// trace the operator can correlate, instead of vanishing into the silent path.
	switch stderr, err := runIPSetCmdQuiet([]string{"destroy", tmpName}); {
	case err == nil:
		logger.Info("destroyed stale ipset TMP from prior reconcile", "set", tmpName)
	case strings.Contains(stderr, "does not exist"):
		// expected on a clean reconcile; nothing to log
	default:
		logger.Warn("pre-destroy of stale ipset TMP failed", "set", tmpName, "error", err, "stderr", strings.TrimSpace(stderr))
	}
	return runIPSetRestore(restoreScript)
}

func buildIPSetRestoreScript(name, family string, ips []string, maxElem int) (string, error) {
	if maxElem <= 0 {
		return "", fmt.Errorf("ipset maxelem must be positive")
	}
	if len(ips) > maxElem {
		return "", fmt.Errorf("ipset %s has %d members, exceeds maxelem %d", name, len(ips), maxElem)
	}
	tmpName := name + "-TMP"
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "create %s hash:ip family %s maxelem %d -exist\n", name, family, maxElem)
	fmt.Fprintf(&buf, "create %s hash:ip family %s maxelem %d\n", tmpName, family, maxElem)
	fmt.Fprintf(&buf, "flush %s\n", tmpName)
	for _, ip := range ips {
		fmt.Fprintf(&buf, "add %s %s -exist\n", tmpName, ip)
	}
	fmt.Fprintf(&buf, "swap %s %s\n", tmpName, name)
	fmt.Fprintf(&buf, "destroy %s\n", tmpName)
	return buf.String(), nil
}

func cleanupPodIPSets(logger *slog.Logger) {
	for _, name := range []string{
		podIPSetName4, podIPSetName6,
		localPodIPSetName4, localPodIPSetName6,
		podIPSetName4 + "-TMP", podIPSetName6 + "-TMP",
		localPodIPSetName4 + "-TMP", localPodIPSetName6 + "-TMP",
	} {
		if err := runIPSetCmd([]string{"destroy", name}); err != nil {
			logger.Warn("delete ipset failed (may not exist)", "set", name, "error", err)
		} else {
			logger.Info("ipset removed", "set", name)
		}
	}
}

// runIPSetCmd runs `ipset <args>` and folds captured stderr into the error
// so callers logging "error" get the underlying ipset diagnostic rather than
// just the exit status. stdout is irrelevant for the destroy/create calls
// that flow through this helper.
func runIPSetCmd(args []string) error {
	_, stderr, err := runIPSetCmdCapture(args)
	if err != nil {
		return ipsetError(strings.Join(args, " "), stderr, err)
	}
	return nil
}

// runIPSetCmdCapture runs ipset with both streams captured. Used wherever
// the caller needs to inspect output (e.g. parse the maxelem header) instead
// of just classifying the error.
func runIPSetCmdCapture(args []string) (stdout, stderr string, err error) {
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.Command("ipset", args...)
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err = cmd.Run()
	return stdoutBuf.String(), stderrBuf.String(), err
}

// runIPSetCmdQuiet is a thin wrapper around runIPSetCmdCapture for callers
// that only need to distinguish "set does not exist" (expected) from a real
// failure via stderr; stdout is dropped.
func runIPSetCmdQuiet(args []string) (string, error) {
	_, stderr, err := runIPSetCmdCapture(args)
	return stderr, err
}

func runIPSetRestore(script string) error {
	var stderrBuf bytes.Buffer
	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = bytes.NewBufferString(script)
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		return ipsetError("restore", stderrBuf.String(), err)
	}
	return nil
}

func ipsetError(op, stderr string, err error) error {
	trimmed := strings.TrimSpace(stderr)
	if trimmed == "" {
		return fmt.Errorf("ipset %s: %w", op, err)
	}
	return fmt.Errorf("ipset %s: %w (stderr=%q)", op, err, trimmed)
}
