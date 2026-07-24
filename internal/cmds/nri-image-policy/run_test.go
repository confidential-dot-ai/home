package nriimagepolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/internal/cache"
	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// nriDefaultSocket is the runtime NRI socket the stub dials when running as an
// external plugin. The Run tests below rely on it being absent so plugin.Run
// fails fast instead of registering with a real runtime.
const nriDefaultSocket = "/var/run/nri/nri.sock"

func skipIfNRISocketPresent(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(nriDefaultSocket); err == nil {
		t.Skipf("real NRI socket present at %s; test requires it absent", nriDefaultSocket)
	}
}

func writeRunConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// deadResolver returns a real containerd resolver whose socket nobody listens
// on: construction is lazy, every RPC fails fast with a connection error.
func deadResolver(t *testing.T) *ctrdresolver.Resolver {
	t.Helper()
	r, err := ctrdresolver.NewResolver(filepath.Join(t.TempDir(), "ctr.sock"), "k8s.io")
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// --- Run: CLI/config error paths ---

func TestRun_FlagParseError(t *testing.T) {
	if err := Run([]string{"--definitely-not-a-flag"}); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestRun_MissingConfigFile(t *testing.T) {
	err := Run([]string{"-config", "/nonexistent/image-policy.yaml"})
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_InvalidLogLevel(t *testing.T) {
	cfgPath := writeRunConfig(t, `
allowlist:
  always_allow:
    "`+pushDigestA+`": "image-a"
logging:
  level: bogus
`)
	err := Run([]string{"-config", cfgPath})
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
	if !strings.Contains(err.Error(), "log level") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Run: full startup, plugin dies on the missing NRI socket ---

func TestRun_StaticAllowlist_PluginDies(t *testing.T) {
	skipIfNRISocketPresent(t)

	tmp := t.TempDir()
	cfgPath := writeRunConfig(t, `
allowlist:
  always_allow:
    "`+pushDigestA+`": "image-a"
policy:
  mode: fail-closed
  enforce_existing: true
containerd:
  socket: `+filepath.Join(tmp, "ctr.sock")+`
logging:
  level: debug
`)
	err := Run([]string{
		"-config", cfgPath,
		"-health-addr", "unix://" + filepath.Join(tmp, "health.sock"),
	})
	if err == nil {
		t.Fatal("expected error when the NRI socket is absent")
	}
	if !strings.Contains(err.Error(), "plugin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_PullEnabled_PluginDies(t *testing.T) {
	skipIfNRISocketPresent(t)

	origRetries, origDelay := allowlistApiMaxRetries, allowlistApiInitialDelay
	allowlistApiMaxRetries, allowlistApiInitialDelay = 1, time.Millisecond
	defer func() {
		allowlistApiMaxRetries, allowlistApiInitialDelay = origRetries, origDelay
	}()

	tmp := t.TempDir()
	// Pull points at a closed local port: the fetch fails fast, and the NRI
	// stub dies on the missing socket. Either failure ends Run with an error.
	cfgPath := writeRunConfig(t, `
plugin:
  health_addr: unix://`+filepath.Join(tmp, "health.sock")+`
allowlist:
  always_allow:
    "`+pushDigestA+`": "image-a"
  pull:
    url: https://127.0.0.1:1
    attestation_api_url: http://127.0.0.1:1
containerd:
  socket: `+filepath.Join(tmp, "ctr.sock")+`
`)
	if err := Run([]string{"-config", cfgPath}); err == nil {
		t.Fatal("expected error when the NRI socket is absent")
	}
}

func TestRun_WorkloadClaimsBroker_StartsOrFails(t *testing.T) {
	skipIfNRISocketPresent(t)

	tmp := t.TempDir()
	cfgPath := writeRunConfig(t, `
allowlist:
  always_allow:
    "`+pushDigestA+`": "image-a"
workload_claims:
  socket_dir: `+tmp+`
containerd:
  socket: `+filepath.Join(tmp, "ctr.sock")+`
`)
	// As non-root the broker socket chgrp fails and Run returns the broker
	// error; as root the broker starts and Run returns the plugin error.
	// Either way Run must fail without the NRI socket.
	if err := Run([]string{
		"-config", cfgPath,
		"-health-addr", "unix://" + filepath.Join(tmp, "health2.sock"),
	}); err == nil {
		t.Fatal("expected error when the NRI socket is absent")
	}
}

// --- newPlugin ---

func TestNewPlugin_External_DefaultProcRoot(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	t.Setenv("NRI_PLUGIN_IDX", "")

	cfg := &config{
		Policy:         policyConfig{Mode: ModeFailClosed},
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
	}
	p, err := newPlugin(cfg, &ctrdresolver.Resolver{}, cache.NewPolicyCache(), audit.NewLogger(), discardLogger())
	if err != nil {
		t.Fatalf("newPlugin: %v", err)
	}
	if p.stub == nil {
		t.Fatal("expected a non-nil NRI stub")
	}
	if p.broker == nil {
		t.Fatal("expected the workload-claims broker to be enabled")
	}
	if p.broker.procRoot != "/proc" {
		t.Fatalf("broker procRoot = %q, want /proc", p.broker.procRoot)
	}
}

func TestNewPlugin_PreInstalledEnv(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", pluginName)
	t.Setenv("NRI_PLUGIN_IDX", pluginIdx)

	cfg := &config{
		Policy:         policyConfig{Mode: ModeFailClosed},
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir(), ProcRoot: "/custom/proc"},
	}
	p, err := newPlugin(cfg, &ctrdresolver.Resolver{}, cache.NewPolicyCache(), audit.NewLogger(), discardLogger())
	if err != nil {
		t.Fatalf("newPlugin: %v", err)
	}
	if p.stub == nil {
		t.Fatal("expected a non-nil NRI stub")
	}
	if p.broker.procRoot != "/custom/proc" {
		t.Fatalf("broker procRoot = %q, want /custom/proc", p.broker.procRoot)
	}
}

// --- plugin.Run via a fake stub ---

// fakeStub embeds the Stub interface so only the methods plugin.Run touches
// need real implementations.
type fakeStub struct {
	stub.Stub
	stopped atomic.Bool
}

func (f *fakeStub) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeStub) Stop() { f.stopped.Store(true) }

func TestPluginRun_StopsOnContextCancel(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	fs := &fakeStub{}
	p.stub = fs

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- p.Run(ctx) }()

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !fs.stopped.Load() {
		if time.Now().After(deadline) {
			t.Fatal("stub.Stop was not called on context cancellation")
		}
		time.Sleep(time.Millisecond)
	}
}

// --- RemoveContainer / Configure with broker ---

func TestRemoveContainer_EvictsFromBroker(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.broker = newWorkloadBroker(t.TempDir())
	p.broker.record(cidApp1, "sandbox-1", "app", digestApp)

	ctr := &api.Container{Id: cidApp1, PodSandboxId: "sandbox-1", Name: "app"}
	if err := p.RemoveContainer(context.Background(), &api.PodSandbox{Id: "sandbox-1"}, ctr); err != nil {
		t.Fatalf("RemoveContainer: %v", err)
	}
	if _, ok := p.broker.containers[cidApp1]; ok {
		t.Fatal("container not evicted from the broker")
	}
}

func TestRemoveContainer_NoBroker_NoOp(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	ctr := &api.Container{Id: "some-id"}
	if err := p.RemoveContainer(context.Background(), &api.PodSandbox{}, ctr); err != nil {
		t.Fatalf("RemoveContainer without broker: %v", err)
	}
}

func TestConfigure_BrokerAddsRemoveContainerMask(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.broker = newWorkloadBroker(t.TempDir())

	mask, err := p.Configure(context.Background(), "", "containerd", "1.7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var want api.EventMask
	want.Set(api.Event_CREATE_CONTAINER)
	want.Set(api.Event_REMOVE_CONTAINER)
	if mask != want {
		t.Fatalf("mask = %v, want %v", mask, want)
	}
}

// --- resolver-error paths (containerd socket nobody listens on) ---

func TestCheckImage_ResolveFails_Denies(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.resolver = deadResolver(t)

	// The containerd RPC blocks until the dial deadline; bound it so the
	// failure path is exercised without a multi-second wait.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	verdict, reason := p.checkImage(ctx, p.cfg, "default", "pod", "ctr", "registry/repo:latest")
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny when digest resolution fails, got %d", verdict)
	}
	if !strings.Contains(reason, "cannot resolve digest") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestRecordForBroker_ResolveFails_RecordsEmptyDigest(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.resolver = deadResolver(t)
	p.broker = newWorkloadBroker(t.TempDir())

	ctr := &api.Container{Id: "ctr-id", PodSandboxId: "sandbox-1", Name: "app"}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p.recordForBroker(ctx, ctr, "registry/repo:latest")

	rec, ok := p.broker.containers["ctr-id"]
	if !ok {
		t.Fatal("container not recorded for the broker")
	}
	if rec.digest != "" {
		t.Fatalf("recorded digest = %q, want empty (fail-closed at query time)", rec.digest)
	}
}

func TestCheckExisting_KillFails_Counted(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: true},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.resolver = deadResolver(t)
	p.SetReady()

	pod := makePod("default", "pod1")
	denied := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	// StopContainer fails against the dead socket; checkExisting must count
	// the failure and finish rather than panic or abort.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := p.Synchronize(ctx, []*api.PodSandbox{pod}, []*api.Container{denied}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- startWorkloadClaimsBroker ---

func TestStartWorkloadClaimsBroker_ListenError(t *testing.T) {
	b := newWorkloadBroker(t.TempDir())
	err := startWorkloadClaimsBroker(context.Background(), discardLogger(), b,
		filepath.Join(t.TempDir(), "no-such-dir", "workload-claims.sock"))
	if err == nil {
		t.Fatal("expected error for unbindable socket path")
	}
}

// --- allowlistPullHTTPClient success paths ---

func TestAllowlistPullHTTPClient_ValidMeasurements(t *testing.T) {
	client, err := allowlistPullHTTPClient(pullConfig{
		CDSMeasurements:   []string{strings.Repeat("ab", 48)}, // 48-byte SHA-384 digest
		AttestationApiURL: "http://127.0.0.1:30840",
		Timeout:           7 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.Timeout != 7*time.Second {
		t.Fatalf("client timeout = %s, want 7s", client.Timeout)
	}
}

func TestAllowlistPullHTTPClient_EmptyMeasurementsWarnsButSucceeds(t *testing.T) {
	client, err := allowlistPullHTTPClient(pullConfig{
		AttestationApiURL: "http://127.0.0.1:30840",
		Timeout:           time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected a client despite empty measurements")
	}
}

// --- small gap fillers ---

func TestHealthListener_UnixListenError(t *testing.T) {
	if _, err := healthListener("unix:///nonexistent-dir-zzz/health.sock"); err == nil {
		t.Fatal("expected error for unbindable unix socket path")
	}
}

func TestStartupSourceMode_None(t *testing.T) {
	if got := startupSourceMode(&config{}); got != "none" {
		t.Fatalf("startupSourceMode(empty) = %q, want none", got)
	}
}

func TestValidate_PullInvalidURL(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.URL = "https://exa mple.com" // space is invalid in a host
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for unparsable pull URL")
	}
}

func TestValidate_ZeroInterval(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.Interval = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for zero interval")
	}
}

func TestLoadConfig_ValidateError(t *testing.T) {
	path := writeRunConfig(t, `
allowlist:
  always_allow:
    "`+pushDigestA+`": "image-a"
policy:
  mode: bogus
`)
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected validation error for bogus policy mode")
	}
}

func TestBrokerContainersForPeer_CgroupReadError(t *testing.T) {
	b := newWorkloadBroker(t.TempDir())
	b.record(cidApp1, "sandbox-1", "app", digestApp)
	if _, err := b.ContainersForPeer(4242); err == nil {
		t.Fatal("expected error when the caller's cgroup file is unreadable")
	}
}

func TestBrokerRecord_IgnoresEmptyIDs(t *testing.T) {
	b := newWorkloadBroker(t.TempDir())
	b.record("", "sandbox-1", "app", digestApp)
	b.record(cidApp1, "", "app", digestApp)
	if len(b.containers) != 0 {
		t.Fatalf("records with empty IDs must be ignored, got %v", b.containers)
	}
}
