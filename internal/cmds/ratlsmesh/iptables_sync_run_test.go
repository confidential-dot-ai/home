//go:build linux

package ratlsmesh

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// localIPv4 returns a non-loopback IPv4 address bound to a local interface,
// or skips the test if none exists (runIptablesSync verifies node-IP
// locality against real interfaces).
func localIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("net.InterfaceAddrs: %v", err)
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		return ip.String()
	}
	t.Skip("no non-loopback IPv4 interface address available")
	return ""
}

func defaultTestSyncConfig() *iptablesSyncConfig {
	return &iptablesSyncConfig{
		outboundPort:            15001,
		uid:                     defaultProxyUID,
		excludeUIDs:             "0",
		excludeSourceNamespaces: defaultMeshExcludedSourceNamespacesCSV(),
		resyncPeriod:            30 * time.Second,
		watchdogPeriod:          2 * time.Second,
		ipsetMaxElem:            defaultIPSetMaxElem,
		cwInboundPassthrough:    formatCWPassthrough(defaultCWPassthrough),
		logLevel:                "error",
	}
}

func TestRunIptablesSyncValidationErrors(t *testing.T) {
	t.Setenv("NODE_IP", "")
	tests := []struct {
		name    string
		mutate  func(*iptablesSyncConfig)
		env     string // NODE_IP value ("" = unset)
		wantErr string
	}{
		{"bad outbound port", func(c *iptablesSyncConfig) { c.outboundPort = 0 }, "", "out of range"},
		{"bad resync period", func(c *iptablesSyncConfig) { c.resyncPeriod = 0 }, "", "resync-period must be positive"},
		{"bad watchdog period", func(c *iptablesSyncConfig) { c.watchdogPeriod = -time.Second }, "", "watchdog-period must be positive"},
		{"bad ipset maxelem", func(c *iptablesSyncConfig) { c.ipsetMaxElem = 0 }, "", "ipset-maxelem must be positive"},
		{"missing node IP", func(c *iptablesSyncConfig) {}, "", "node IP required"},
		{"node IP from env invalid", func(c *iptablesSyncConfig) {}, "not-an-ip", "not a valid IP address"},
		{"node IP not local", func(c *iptablesSyncConfig) { c.nodeIPs = []string{"203.0.113.7"} }, "", "not bound to any local interface"},
		{"bad exclude uids", func(c *iptablesSyncConfig) {
			c.nodeIPs = []string{localIPv4(t)}
			c.excludeUIDs = "root"
		}, "", "invalid exclude-uid"},
		{"bad cw passthrough", func(c *iptablesSyncConfig) {
			c.nodeIPs = []string{localIPv4(t)}
			c.cwInboundPassthrough = "icmp:1"
		}, "", "invalid cw-inbound-passthrough protocol"},
		{"bad log level", func(c *iptablesSyncConfig) {
			c.nodeIPs = []string{localIPv4(t)}
			c.logLevel = "shouty"
		}, "", "--log-level"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NODE_IP", tt.env)
			cfg := defaultTestSyncConfig()
			tt.mutate(cfg)
			err := runIptablesSync(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runIptablesSync() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunIptablesSyncFullLifecycle(t *testing.T) {
	nodeIP := localIPv4(t)
	env := installFakeNetfilter(t)
	// A stale live set with a different maxelem forces the
	// reconcileLiveSetMaxElem destroy-and-rebuild path.
	env.seedIpset(t, podIPSetName4, "999")
	// A stale TMP set left by a "crashed" prior reconcile exercises the
	// pre-destroy path in replaceIPSetMembers.
	env.seedIpset(t, podIPSetName4+ipSetTmpSuffix, "999")

	clientset := k8sfake.NewSimpleClientset(
		testPod("local-web", "default", "10.244.0.10", nodeIP, nil),
		testPod("cw-remote", "default", "10.244.9.9", "10.0.0.99", map[string]string{labelConfidentialWorkload: "tenant"}),
		testPod("excluded", "kube-system", "10.244.0.11", nodeIP, nil),
	)
	stubKubeClientset(t, clientset, nil)

	dir := t.TempDir()
	readyFile := filepath.Join(dir, "ready")
	metricsFile := filepath.Join(dir, "metrics.json")

	cfg := defaultTestSyncConfig()
	cfg.nodeIPs = []string{nodeIP}
	cfg.resyncPeriod = 25 * time.Millisecond
	cfg.watchdogPeriod = 10 * time.Millisecond
	cfg.ipsetMaxElem = 100
	cfg.readyFile = readyFile
	cfg.metricsFile = metricsFile

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runIptablesSync(ctx, cfg) }()

	assertEventually(t, 10*time.Second, func() bool {
		_, err := os.Stat(readyFile)
		return err == nil
	}, "ready file never written")

	// Event-driven resync: a new cw pod appears, entering the cw set and
	// triggering the newMembers conntrack flush path.
	if _, err := clientset.CoreV1().Pods("default").Create(ctx,
		testPod("cw-new", "default", "10.244.0.12", nodeIP, map[string]string{labelConfidentialWorkload: "x"}),
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Let a few resync ticks and watchdog ticks run.
	time.Sleep(120 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runIptablesSync() = %v, want nil on cancel", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runIptablesSync did not stop after cancel")
	}

	// The managed sets were (re)created with the configured maxelem.
	if !env.ipsetExists(podIPSetName4) {
		t.Errorf("%s ipset missing after sync", podIPSetName4)
	}
	got, exists, err := readIPSetMaxElem(podIPSetName4)
	if err != nil || !exists || got != 100 {
		t.Errorf("readIPSetMaxElem(%s) = (%d, %v, %v), want (100, true, nil)", podIPSetName4, got, exists, err)
	}
	// The NAT chains carry the redirect rules and the jumps sit at head.
	if rules := env.chainRules(t, "iptables", "nat", chainName); len(rules) == 0 {
		t.Errorf("no rules installed in %s", chainName)
	}
	out := env.chainRules(t, "iptables", "nat", "OUTPUT")
	if len(out) == 0 || out[0] != "-j "+chainName {
		t.Errorf("OUTPUT jump not at head: %v", out)
	}
	fwd := env.chainRules(t, "iptables", "filter", "FORWARD")
	if len(fwd) == 0 || fwd[0] != "-j "+cwChainName {
		t.Errorf("FORWARD cw jump not at head: %v", fwd)
	}
	// The metrics file was published.
	snap, err := readIptablesMetricsFile(metricsFile)
	if err != nil {
		t.Fatalf("read published metrics file: %v", err)
	}
	if snap.UpdatedAtUnixNano == 0 {
		t.Error("published metrics snapshot has zero timestamp")
	}
	// The fake -L stats feed 7 DROP packets per family.
	if drops := iptablesCWInboundDrops(); drops != 14 {
		t.Errorf("cw inbound drops = %d, want 14", drops)
	}
}

func TestEnsureIptablesJumpsViolationAndCheckError(t *testing.T) {
	env := installFakeNetfilter(t)
	if err := initIptablesClients(); err != nil {
		t.Fatal(err)
	}
	logger := testLogger()
	jumps := jumpRules()

	// Seed OUTPUT with a foreign rule ahead of our jump so the jump is
	// present but demoted: a confirmed position violation.
	if err := iptablesV4.Append("nat", "OUTPUT", "-j", "KUBE-SERVICES"); err != nil {
		t.Fatal(err)
	}
	if err := iptablesV4.Append("nat", "OUTPUT", "-j", chainName); err != nil {
		t.Fatal(err)
	}
	before := iptablesJumpPositionViolations()
	if err := ensureIptablesJumps(logger, jumps); err != nil {
		t.Fatalf("ensureIptablesJumps: %v", err)
	}
	if got := iptablesJumpPositionViolations(); got != before+1 {
		t.Errorf("jump violations = %d, want %d", got, before+1)
	}
	out := env.chainRules(t, "iptables", "nat", "OUTPUT")
	if len(out) == 0 || out[0] != "-j "+chainName {
		t.Errorf("jump not restored at head: %v", out)
	}

	// A failing List is a check error, not a violation.
	t.Setenv("FAKE_IPT_LIST_FAIL", "1")
	beforeCheck := iptablesJumpPositionCheckErrors()
	beforeViol := iptablesJumpPositionViolations()
	if err := ensureIptablesJumps(logger, jumps); err != nil {
		t.Fatalf("ensureIptablesJumps with failing list: %v", err)
	}
	if got := iptablesJumpPositionCheckErrors(); got <= beforeCheck {
		t.Errorf("check errors did not increase: %d", got)
	}
	if got := iptablesJumpPositionViolations(); got != beforeViol {
		t.Errorf("violations changed on check error: %d != %d", got, beforeViol)
	}
}

func TestReadIPSetMaxElemStates(t *testing.T) {
	env := installFakeNetfilter(t)
	if _, exists, err := readIPSetMaxElem(podIPSetName4); err != nil || exists {
		t.Errorf("missing set: got exists=%v err=%v, want false,nil", exists, err)
	}
	env.seedIpset(t, podIPSetName4, "4096")
	got, exists, err := readIPSetMaxElem(podIPSetName4)
	if err != nil || !exists || got != 4096 {
		t.Errorf("seeded set: got (%d,%v,%v), want (4096,true,nil)", got, exists, err)
	}
	env.seedIpset(t, podIPSetName6, "bogus")
	if _, _, err := readIPSetMaxElem(podIPSetName6); err == nil {
		t.Error("expected parse error for non-numeric maxelem")
	}
}

func TestRunIPSetCmdFailure(t *testing.T) {
	installFakeNetfilter(t)
	t.Setenv("FAKE_IPSET_FAIL", "1")
	err := runIPSetCmd([]string{"destroy", "whatever"})
	if err == nil || !strings.Contains(err.Error(), "kernel says no") {
		t.Fatalf("runIPSetCmd error = %v, want stderr folded in", err)
	}
	if err := runIPSetRestore("create X hash:ip family inet maxelem 8\n"); err == nil {
		t.Fatal("runIPSetRestore should fail when ipset fails")
	}
}

func TestIpsetErrorFormatting(t *testing.T) {
	base := errors.New("exit status 2")
	if got := ipsetError("destroy X", "", base); !strings.Contains(got.Error(), "ipset destroy X") || strings.Contains(got.Error(), "stderr") {
		t.Errorf("empty-stderr form wrong: %v", got)
	}
	if got := ipsetError("destroy X", " boom \n", base); !strings.Contains(got.Error(), `stderr="boom"`) {
		t.Errorf("stderr form wrong: %v", got)
	}
}

func TestCleanupPodIPSetsRemovesSeededSets(t *testing.T) {
	env := installFakeNetfilter(t)
	env.seedIpset(t, podIPSetName4, "128")
	env.seedIpset(t, cwPodIPSetName6+ipSetTmpSuffix, "128")
	cleanupPodIPSets(testLogger())
	if env.ipsetExists(podIPSetName4) || env.ipsetExists(cwPodIPSetName6+ipSetTmpSuffix) {
		t.Error("cleanupPodIPSets left seeded sets behind")
	}
}

func TestRunJumpWatchdogTicks(t *testing.T) {
	installFakeNetfilter(t)
	if err := initIptablesClients(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runJumpWatchdog(ctx, testLogger(), jumpRules(), 5*time.Millisecond)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not stop on cancel")
	}
}

func TestStringSetAndNewMembers(t *testing.T) {
	prev := stringSet([]string{"a", "b"})
	curr := stringSet([]string{"b", "c", "d"})
	got := newMembers(prev, curr)
	if len(got) != 2 {
		t.Fatalf("newMembers = %v, want 2 elements", got)
	}
	seen := stringSet(got)
	if _, ok := seen["c"]; !ok {
		t.Errorf("missing c in %v", got)
	}
	if _, ok := seen["d"]; !ok {
		t.Errorf("missing d in %v", got)
	}
}

func TestPodIPSetMembersExceeds(t *testing.T) {
	m := podIPSetMembers{allIPv4: []string{"1.1.1.1", "2.2.2.2"}}
	if !m.exceeds(1) {
		t.Error("exceeds(1) = false, want true")
	}
	if m.exceeds(2) {
		t.Error("exceeds(2) = true, want false")
	}
	if (podIPSetMembers{cwIPv6: []string{"fd00::1", "fd00::2"}}).exceeds(1) != true {
		t.Error("cwIPv6 overflow not detected")
	}
}

func TestCanonicalNodeIPs(t *testing.T) {
	got := canonicalNodeIPs(map[iptablesFamily]string{
		iptablesFamilyIPv6: "fd00::1",
		iptablesFamilyIPv4: "10.0.0.1",
	})
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "fd00::1" {
		t.Errorf("canonicalNodeIPs = %v, want IPv4 first then IPv6", got)
	}
}

func TestVerifyNodeIPsLocal(t *testing.T) {
	ip := localIPv4(t)
	if err := verifyNodeIPsLocal(map[iptablesFamily]string{iptablesFamilyIPv4: ip}); err != nil {
		t.Errorf("verifyNodeIPsLocal(%s) = %v, want nil", ip, err)
	}
	if err := verifyNodeIPsLocal(map[iptablesFamily]string{iptablesFamilyIPv4: "203.0.113.9"}); err == nil {
		t.Error("verifyNodeIPsLocal should reject a non-local IP")
	}
}

func TestFlushCWConntrackBestEffort(t *testing.T) {
	// Unprivileged conntrack deletes fail; the function must stay best-effort
	// and not panic. The empty and unparseable inputs cover the early exits.
	flushCWConntrack(testLogger(), nil)
	flushCWConntrack(testLogger(), []string{"not-an-ip"})
	flushCWConntrack(testLogger(), []string{"10.0.0.1", "fd00::1"})
	if inetFamilyLabel(2) != "ipv4" { // unix.AF_INET
		t.Error("inetFamilyLabel(AF_INET) != ipv4")
	}
	if inetFamilyLabel(10) != "ipv6" { // unix.AF_INET6
		t.Error("inetFamilyLabel(AF_INET6) != ipv6")
	}
}

func TestInstallIptablesRulesAndDeleteAll(t *testing.T) {
	env := installFakeNetfilter(t)
	if err := initIptablesClients(); err != nil {
		t.Fatal(err)
	}
	logger := testLogger()
	rules := buildInGuestIptablesRules(15001, 15006, 15021, nil)
	if err := installIptablesRules(logger, rules, jumpRules()); err != nil {
		t.Fatalf("installIptablesRules: %v", err)
	}
	if got := env.chainRules(t, "iptables", "nat", chainName); len(got) == 0 {
		t.Fatal("no rules in managed chain after install")
	}
	// Second install is idempotent thanks to the pre-flush.
	if err := installIptablesRules(logger, rules, jumpRules()); err != nil {
		t.Fatalf("re-install: %v", err)
	}
	// deleteAllIptablesRules drains duplicate jumps.
	jump := jumpRules()[0]
	if err := iptablesV4.Append(jump.table, jump.chain, jump.args...); err != nil {
		t.Fatal(err)
	}
	deleteAllIptablesRules(logger, iptablesV4, jump)
	for _, line := range env.chainRules(t, "iptables", "nat", "OUTPUT") {
		if line == strings.Join(jump.args, " ") {
			t.Errorf("jump still present after deleteAll: %v", line)
		}
	}
}
