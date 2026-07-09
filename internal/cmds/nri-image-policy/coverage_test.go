package nriimagepolicy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/internal/cache"
	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// newCachedPlugin builds a plugin whose policy cache holds wl. The resolver is
// a zero-value placeholder; tests must only exercise digest-bearing image
// references so resolver.Resolve is never reached (no real containerd socket).
func newCachedPlugin(cfg *config, wl *allowlist.Allowlist) (*plugin, *cache.PolicyCache) {
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		panic(err)
	}
	c := cache.NewPolicyCache()
	c.SetAllowlist(wl)
	return &plugin{
		cfg:      cfg,
		resolver: &ctrdresolver.Resolver{},
		cache:    c,
		audit:    audit.NewLogger(),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, c
}

// --- checkImage: digest-bearing references (no resolver needed) ---

func TestCheckImage_DigestInAllowlist_Allows(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestA
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", imageRef)
	if verdict != verdictAllow {
		t.Fatalf("expected verdictAllow, got %d (reason=%q)", verdict, reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason on allow, got %q", reason)
	}
}

func TestCheckImage_DigestNotInAllowlist_Denies(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestB
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", imageRef)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason on deny")
	}
}

func TestCheckImage_NilAllowlist_Denies(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestA
	p, c := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	c.Clear() // GetAllowlist now returns nil

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", imageRef)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny when allowlist is nil, got %d", verdict)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason when no allowlist is available")
	}
}

func TestCheckImage_ExemptNamespace_WithImage_Skips(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestB // not in allowlist; exemption wins
	p, _ := newCachedPlugin(&config{Policy: policyConfig{
		Mode:             ModeFailClosed,
		ExemptNamespaces: []string{"kube-system"},
	}}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-system", "pod", "ctr", imageRef)
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip for exempt namespace, got %d", verdict)
	}
}

// --- CreateContainer end-to-end through the image allowlist path ---

func makeCtrWithImage(podSandboxID, name, image string) *api.Container {
	return &api.Container{
		Id:           name + "-id",
		PodSandboxId: podSandboxID,
		Name:         name,
		Annotations:  map[string]string{annotationImageName: image},
	}
}

func TestCreateContainer_DigestNotInAllowlist_FailClosed(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestB)

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected denial for image not in allowlist")
	}
}

func TestCreateContainer_DigestNotInAllowlist_AuditAllows(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeAudit},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestB)

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("audit mode should allow despite deny verdict, got: %v", err)
	}
}

func TestCreateContainer_DigestInAllowlist_Allows(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "mypod")
	ctr := makeCtrWithImage(pod.Id, "myctr", "registry/repo@"+pushDigestA)

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected allow for allowlisted digest, got: %v", err)
	}
}

func TestCreateContainer_ImageFromPodAnnotation(t *testing.T) {
	// Container has no image annotation; falls back to the pod annotation.
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "mypod")
	pod.Annotations = map[string]string{annotationImageName: "registry/repo@" + pushDigestA}
	ctr := makeCtr(pod.Id, "myctr") // no annotations

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected pod-annotation fallback to resolve allowlisted digest, got: %v", err)
	}
}

// --- runSweep via deferred sweep (audit mode → no container kill attempted) ---

func TestRunDeferredSweep_AuditMode_NoKill(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy: policyConfig{
			Mode:            ModeAudit, // audit → never calls resolver.StopContainer
			EnforceExisting: true,
		},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "pod1")
	// Container image is NOT in the allowlist → would be denied, but audit
	// mode means runSweep continues without attempting a kill.
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	p.deferredMu.Lock()
	p.deferredPods = []*api.PodSandbox{pod}
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	// Should run the sweep without panicking or touching the (nil) resolver.
	p.RunDeferredSweep(context.Background())
}

func TestRunDeferredSweep_OrphanContainer_Skipped(t *testing.T) {
	// A container whose pod sandbox is absent is skipped (podByID miss).
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeAudit, EnforceExisting: true},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	ctr := makeCtrWithImage("missing-pod-id", "orphan", "registry/repo@"+pushDigestB)
	p.deferredMu.Lock()
	p.deferredPods = nil
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	p.RunDeferredSweep(context.Background())
}

func TestRunDeferredSweep_ExemptNamespace_Skipped(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy: policyConfig{
			Mode:             ModeFailClosed,
			EnforceExisting:  true,
			ExemptNamespaces: []string{"kube-system"},
		},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("kube-system", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)
	p.deferredMu.Lock()
	p.deferredPods = []*api.PodSandbox{pod}
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	// Exempt namespace → checkLabels returns verdictSkip → sweep continues,
	// fail-closed mode but no kill because the container is skipped entirely.
	p.RunDeferredSweep(context.Background())
}

func TestRunDeferredSweep_EnforceExistingDisabled_NoOp(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)
	p.deferredMu.Lock()
	p.deferredPods = []*api.PodSandbox{pod}
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	// EnforceExisting=false → early return before clearing deferred state.
	p.RunDeferredSweep(context.Background())
}

func TestSynchronize_Ready_AuditMode_RunsSweep(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeAudit, EnforceExisting: true},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.SetReady()

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestA) // allowed

	updates, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Fatal("expected nil updates")
	}
}

func TestSynchronize_EnforceExistingDisabled_ReturnsNil(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Policy: policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, &allowlist.Allowlist{Digests: map[string]string{}})
	p.SetReady()

	updates, err := p.Synchronize(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Fatal("expected nil updates when enforce_existing is disabled")
	}
}

// --- Configure ---

func TestConfigure_SetsCreateContainerMask(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	mask, err := p.Configure(context.Background(), "", "containerd", "1.7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var want api.EventMask
	want.Set(api.Event_CREATE_CONTAINER)
	if mask != want {
		t.Fatalf("mask = %v, want %v", mask, want)
	}
}

// --- pure helpers ---

func TestAlwaysAllowAllowlist(t *testing.T) {
	wl := alwaysAllowAllowlist(map[string]string{pushDigestA: "image-a", pushDigestB: "image-b"})
	if len(wl.Digests) != 2 {
		t.Fatalf("expected 2 digests, got %d", len(wl.Digests))
	}
	if wl.Digests[pushDigestA] != "image-a" {
		t.Fatalf("digest A = %q, want image-a", wl.Digests[pushDigestA])
	}
}

func TestAlwaysAllowAllowlist_Empty(t *testing.T) {
	wl := alwaysAllowAllowlist(nil)
	if wl == nil || wl.Digests == nil {
		t.Fatal("expected non-nil allowlist with non-nil Digests map")
	}
	if len(wl.Digests) != 0 {
		t.Fatalf("expected empty digests, got %d", len(wl.Digests))
	}
}

func TestEntriesOf(t *testing.T) {
	if got := entriesOf(nil); got != 0 {
		t.Fatalf("entriesOf(nil) = %d, want 0", got)
	}
	wl := &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "a", pushDigestB: "b"}}
	if got := entriesOf(wl); got != 2 {
		t.Fatalf("entriesOf = %d, want 2", got)
	}
}

func TestLabelOperator(t *testing.T) {
	for _, op := range []string{OpIn, OpNotIn, OpExists, OpDoesNotExist} {
		if _, err := labelOperator(op); err != nil {
			t.Errorf("labelOperator(%q) returned error: %v", op, err)
		}
	}
	if _, err := labelOperator("Bogus"); err == nil {
		t.Fatal("expected error for unknown operator")
	}
}

// --- healthListener / startHealthServer ---

func TestHealthListener_TCP(t *testing.T) {
	l, err := healthListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer l.Close()
	if l.Addr().Network() != "tcp" {
		t.Fatalf("expected tcp listener, got %q", l.Addr().Network())
	}
}

func TestHealthListener_TCPInvalidAddr(t *testing.T) {
	if _, err := healthListener("not-a-valid-addr"); err == nil {
		t.Fatal("expected error for invalid TCP address")
	}
}

func TestHealthListener_Unix(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "health.sock")
	l, err := healthListener("unix://" + sock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer l.Close()
	if l.Addr().Network() != "unix" {
		t.Fatalf("expected unix listener, got %q", l.Addr().Network())
	}
}

func TestHealthListener_UnixRemovesStaleSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "health.sock")
	// Bind once and close to leave a stale socket file behind.
	l1, err := healthListener("unix://" + sock)
	if err != nil {
		t.Fatalf("first bind: %v", err)
	}
	l1.Close()
	// Re-bind must succeed (stale file removed before listen).
	l2, err := healthListener("unix://" + sock)
	if err != nil {
		t.Fatalf("rebind over stale socket: %v", err)
	}
	l2.Close()
}

func TestStartHealthServer_HealthzReflectsReadiness(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "health.sock")
	addr := "unix://" + sock

	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := startHealthServer(ctx, healthServerConfig{
		logger:       discardLogger(),
		plugin:       p,
		addr:         addr,
		readTimeout:  time.Second,
		writeTimeout: time.Second,
	}); err != nil {
		t.Fatalf("startHealthServer: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}

	// Not ready yet → 503.
	resp, err := httpClient.Get("http://unix/healthz")
	if err != nil {
		t.Fatalf("GET /healthz (not ready): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status = %d, want 503", resp.StatusCode)
	}

	p.SetReady()
	resp2, err := httpClient.Get("http://unix/healthz")
	if err != nil {
		t.Fatalf("GET /healthz (ready): %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("ready status = %d, want 200", resp2.StatusCode)
	}

	cancel()
}

func TestStartHealthServer_InvalidAddr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := startHealthServer(ctx, healthServerConfig{
		logger:       discardLogger(),
		plugin:       &plugin{},
		addr:         "not-a-valid-addr",
		readTimeout:  time.Second,
		writeTimeout: time.Second,
	})
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

// --- allowlistPullHTTPClient ---

func TestAllowlistPullHTTPClient_InvalidMeasurements(t *testing.T) {
	_, err := allowlistPullHTTPClient(pullConfig{
		CDSMeasurements:   []string{"not-hex"},
		AttestationApiURL: "http://localhost:30840",
		Timeout:           time.Second,
	})
	if err == nil {
		t.Fatal("expected error for invalid CDS measurements")
	}
}
