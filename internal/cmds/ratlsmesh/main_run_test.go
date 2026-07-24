//go:build linux

package ratlsmesh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// defaultTestProxyConfig returns a proxyConfig populated with the flag
// defaults, exactly as cobra would after parsing zero args.
func defaultTestProxyConfig(t *testing.T) *proxyConfig {
	t.Helper()
	var cfg proxyConfig
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	bindProxyFlags(fs, &cfg)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	return &cfg
}

// stubKubeClientset swaps the package-level clientset factory for the
// duration of the test.
func stubKubeClientset(t *testing.T, cs kubernetes.Interface, err error) {
	t.Helper()
	old := newKubeClientset
	newKubeClientset = func() (kubernetes.Interface, error) { return cs, err }
	t.Cleanup(func() { newKubeClientset = old })
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// writeSelfSignedCertPEM writes a throwaway self-signed certificate to a
// temp file and returns its path (for --ca-cert loading).
func writeSelfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testPod(name, ns, podIP, hostIP string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID("uid-" + name), Labels: labels},
		Status: corev1.PodStatus{
			Phase:  corev1.PodRunning,
			PodIP:  podIP,
			HostIP: hostIP,
		},
	}
}

func TestRunProxyConfigErrors(t *testing.T) {
	t.Setenv("NODE_IP", "")
	fakeCS := k8sfake.NewSimpleClientset()
	stubKubeClientset(t, fakeCS, nil)

	valid48 := strings.Repeat("ab", 48)
	tests := []struct {
		name    string
		mutate  func(*proxyConfig)
		wantErr string
	}{
		{"bad log level", func(c *proxyConfig) { c.logLevel = "bogus" }, "--log-level"},
		{"missing node IP", func(c *proxyConfig) {}, "node IP required"},
		{"invalid node IP", func(c *proxyConfig) { c.nodeIP = "not-an-ip" }, "must be a valid IP address"},
		{"invalid configuration", func(c *proxyConfig) { c.nodeIP = "127.0.0.1" }, "invalid configuration"},
		{"invalid measurement hex", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.measurements = "zz"
		}, "invalid measurement hex"},
		{"invalid measurement length", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.measurements = "abcd"
		}, "invalid measurement length"},
		{"missing CA cert file", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.caCertPath = "/nonexistent/ca.pem"
		}, "load CA certificate"},
		{"invalid cert mode", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.certMode = "bogus"
		}, "invalid --cert-mode"},
		{"cds mode requires urls", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.certMode = "cds"
		}, "--cds-url and --attestation-api-url are required"},
		{"unsupported platform", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.platform = "frobnitz"
		}, "unsupported --platform"},
		{"empty platform", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.platform = ""
		}, "--platform is required"},
		{"invalid cds measurements", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.platform = "sev-snp"
			c.cdsMeasurements = "zz"
		}, "--cds-measurements"},
		{"valid cds measurements but bad mesh policy", func(c *proxyConfig) {
			c.nodeIP = "127.0.0.1"
			c.attestationApiURL = "http://127.0.0.1:1"
			c.measurements = valid48 + ",zz"
		}, "invalid measurement hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultTestProxyConfig(t)
			cfg.logLevel = "error"
			cfg.localCIDRBootTimeout = time.Millisecond
			tt.mutate(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := runProxy(ctx, cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runProxy() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunProxyClientsetError(t *testing.T) {
	t.Setenv("NODE_IP", "10.0.0.9")
	stubKubeClientset(t, nil, fmt.Errorf("k8s in-cluster config: nope"))
	cfg := defaultTestProxyConfig(t)
	cfg.logLevel = "error"
	cfg.attestationApiURL = "http://127.0.0.1:1"
	err := runProxy(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "in-cluster config") {
		t.Fatalf("runProxy() error = %v, want in-cluster config error", err)
	}
}

// TestRunProxyFullLifecycle drives runProxy end to end with a fake
// clientset and local fake CDS / probe / attestation endpoints, then
// cancels the context and expects a clean shutdown.
func TestRunProxyFullLifecycle(t *testing.T) {
	nodeIP := "127.0.0.1"
	pod := testPod("web", "default", "10.244.0.7", nodeIP, nil)
	stubKubeClientset(t, k8sfake.NewSimpleClientset(pod), nil)
	t.Setenv("NODE_IP", "")

	// Fake CDS: everything 404s; the upgrade goroutine retries with backoff.
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer cds.Close()

	// Cert-pipeline probe: first request unhealthy, then healthy, to walk
	// both probe branches.
	var probeCalls atomic.Int64
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if probeCalls.Add(1) == 1 {
			http.Error(w, "warming up", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer probe.Close()

	metricsFile := filepath.Join(t.TempDir(), "iptables-metrics.json")
	if err := writeIptablesMetricsFile(metricsFile, iptablesMetricsSnapshot{
		JumpPositionViolations: 3,
		UpdatedAtUnixNano:      time.Now().UnixNano(),
	}); err != nil {
		t.Fatal(err)
	}

	cfg := defaultTestProxyConfig(t)
	cfg.logLevel = "error"
	cfg.platform = "sev-snp"
	cfg.nodeIP = nodeIP
	cfg.attestationApiURL = "http://127.0.0.1:1" // refused instantly; warm-up failure is non-fatal
	cfg.outboundPort = freePort(t)
	cfg.inboundPort = freePort(t)
	cfg.healthPort = freePort(t)
	cfg.certDNSSAN = "mesh.example"
	cfg.measurements = strings.Repeat("ab", 48)
	cfg.cdsMeasurements = strings.Repeat("cd", 48)
	cfg.caCertPath = writeSelfSignedCertPEM(t)
	cfg.certMode = "cds"
	cfg.cdsURL = cds.URL
	cfg.certPipelineProbeURL = probe.URL + "/readyz"
	cfg.certPipelineProbeInterval = 20 * time.Millisecond
	cfg.certPipelineProbeTimeout = time.Second
	cfg.caPollInterval = 20 * time.Millisecond
	cfg.cdsRetryBackoff = 20 * time.Millisecond
	cfg.cdsRetryMaxBackoff = 40 * time.Millisecond
	cfg.cdsOpTimeout = 500 * time.Millisecond
	cfg.rotationTimeout = 300 * time.Millisecond
	cfg.metricsUpdateInterval = 10 * time.Millisecond
	cfg.localCIDRBootTimeout = time.Millisecond
	cfg.iptablesMetricsFile = metricsFile
	cfg.maxConns = 8
	cfg.maxConnsPerSource = 4
	cfg.drainTimeout = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runProxy(ctx, cfg) }()

	healthURL := fmt.Sprintf("http://127.0.0.1:%d/live", cfg.healthPort)
	assertEventually(t, 10*time.Second, func() bool {
		resp, err := http.Get(healthURL)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "health server never came up")

	// Let the metric ticker read the sidecar file at least once, then remove
	// it so the read-after-success warning path runs too.
	time.Sleep(50 * time.Millisecond)
	os.Remove(metricsFile)
	time.Sleep(80 * time.Millisecond)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runProxy() = %v, want nil on context cancel", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runProxy did not shut down after cancel")
	}
}

func TestRunCLIDispatch(t *testing.T) {
	if err := Run([]string{"--help"}); err != nil {
		t.Fatalf("Run(--help) = %v, want nil", err)
	}
	if err := Run([]string{"--no-such-flag"}); err == nil {
		t.Fatal("Run with unknown flag should error")
	}
}

func TestRunIptablesSyncCommandValidation(t *testing.T) {
	t.Setenv("NODE_IP", "")
	// Dispatched through the real CLI so newIptablesSyncCommand's RunE and
	// flag binding are exercised.
	err := Run([]string{"iptables-sync", "--resync-period=0"})
	if err == nil || !strings.Contains(err.Error(), "resync-period must be positive") {
		t.Fatalf("Run(iptables-sync --resync-period=0) = %v", err)
	}
}

func TestRunIptablesCleanupCommand(t *testing.T) {
	t.Run("removes installed chains, jumps, and ipsets", func(t *testing.T) {
		env := installFakeNetfilter(t)
		if err := initIptablesClients(); err != nil {
			t.Fatal(err)
		}
		// Install real state via the production path so the cleanup has
		// something to tear down: managed chains with rules, the base-chain
		// jumps (including the cw guard jump), and live pod ipsets.
		jumps := append(jumpRules(), cwJumpRule())
		rules := buildInGuestIptablesRules(15001, 15006, 15021, nil)
		if err := installIptablesRules(testLogger(), rules, jumps); err != nil {
			t.Fatalf("installIptablesRules: %v", err)
		}
		for _, name := range managedIPSetNames {
			env.seedIpset(t, name, "1024")
			env.seedIpset(t, name+ipSetTmpSuffix, "1024")
		}

		// Sanity-check the state actually exists before cleanup, so the
		// "gone afterwards" assertions below cannot pass vacuously.
		for _, bin := range []string{"iptables", "ip6tables"} {
			for _, mc := range managedChains {
				if !fakeChainExists(env, bin, mc.table, mc.chain) {
					t.Fatalf("chain %s/%s not installed on %s before cleanup", mc.table, mc.chain, bin)
				}
			}
			for _, jump := range jumps {
				if !containsRule(env.chainRules(t, bin, jump.table, jump.chain), jump.args) {
					t.Fatalf("jump %s missing from %s/%s on %s before cleanup", jump.label, jump.table, jump.chain, bin)
				}
			}
		}
		if got := env.chainRules(t, "iptables", "nat", chainName); len(got) == 0 {
			t.Fatalf("no rules in %s before cleanup", chainName)
		}
		for _, name := range managedIPSetNames {
			if !env.ipsetExists(name) {
				t.Fatalf("ipset %s not seeded before cleanup", name)
			}
		}

		if err := Run([]string{"iptables-cleanup"}); err != nil {
			t.Fatalf("Run(iptables-cleanup) = %v, want nil", err)
		}

		for _, bin := range []string{"iptables", "ip6tables"} {
			for _, mc := range managedChains {
				if fakeChainExists(env, bin, mc.table, mc.chain) {
					t.Errorf("chain %s/%s still present on %s after cleanup: %v",
						mc.table, mc.chain, bin, env.chainRules(t, bin, mc.table, mc.chain))
				}
			}
			for _, jump := range jumps {
				if containsRule(env.chainRules(t, bin, jump.table, jump.chain), jump.args) {
					t.Errorf("jump %s still present in %s/%s on %s after cleanup", jump.label, jump.table, jump.chain, bin)
				}
			}
		}
		for _, name := range managedIPSetNames {
			if env.ipsetExists(name) {
				t.Errorf("ipset %s still present after cleanup", name)
			}
			if env.ipsetExists(name + ipSetTmpSuffix) {
				t.Errorf("ipset %s still present after cleanup", name+ipSetTmpSuffix)
			}
		}
	})

	t.Run("tolerates absent chains", func(t *testing.T) {
		env := installFakeNetfilter(t)
		if err := Run([]string{"iptables-cleanup"}); err != nil {
			t.Fatalf("Run(iptables-cleanup) on empty state = %v, want nil", err)
		}
		if rules := env.chainRules(t, "iptables", "nat", chainName); rules != nil {
			t.Errorf("chain %s present after cleanup of empty state: %v", chainName, rules)
		}
	})
}

// fakeChainExists reports whether the fake-iptables state file for the chain
// exists at all. chainRules cannot distinguish a missing chain from an empty
// one (both read as nil), so chain existence is checked on the state file.
func fakeChainExists(env *fakeNetfilterEnv, bin, table, chain string) bool {
	_, err := os.Stat(filepath.Join(env.iptState, bin, table+"__"+chain))
	return err == nil
}

// containsRule reports whether any fake-iptables rule line equals the joined
// rule args.
func containsRule(lines []string, args []string) bool {
	want := strings.Join(args, " ")
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}
