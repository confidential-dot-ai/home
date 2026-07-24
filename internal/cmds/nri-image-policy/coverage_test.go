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
	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// mustDigest parses a digest string or fails the test.
func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("ParseDigest(%q): %v", s, err)
	}
	return d
}

// newCachedPlugin builds a plugin whose policy store admits wl (applied as a
// version-1 pull over an empty floor). The resolver is a zero-value placeholder;
// tests must only exercise digest-bearing image references so resolver.Resolve
// is never reached (no real containerd socket).
func newCachedPlugin(cfg *config, wl *allowlist.Allowlist) (*plugin, *policyStore) {
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		panic(err)
	}
	store := newPolicyStore(floorAllowlist(map[string]string{}))
	store.apply(wl, 1)
	return &plugin{
		cfg:      cfg,
		resolver: &ctrdresolver.Resolver{},
		policy:   store,
		audit:    audit.NewLogger(),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, store
}

// --- checkImage: digest-bearing references (no resolver needed) ---

func TestCheckImage_DigestInAllowlist_Allows(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestA
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", imageRef, nil)
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

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", imageRef, nil)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason on deny")
	}
}

func TestCheckImage_NoPolicyLoaded_Denies(t *testing.T) {
	imageRef := "registry/repo@" + pushDigestA
	p, s := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		&allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	s.snap.Store(nil) // no admission snapshot loaded

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", imageRef, nil)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny when no policy is loaded, got %d", verdict)
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

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-system", "pod", "ctr", imageRef, nil)
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip for exempt namespace, got %d", verdict)
	}
}

// --- workload argv policy: floor admits any argv, workload gates on argv ---

// workloadAllowlist builds an allowlist with one workload container pinning the
// given digest to an exact entrypoint. The floor holds floorDigest (digest-only).
func workloadAllowlist(t *testing.T, floorDigest, wlDigest string, entrypoint []string) *allowlist.Allowlist {
	t.Helper()
	return &allowlist.Allowlist{
		Schema:  allowlist.Schema,
		Digests: map[string]string{floorDigest: "floor-image"},
		Workloads: map[string]allowlist.Workload{
			"w": {Containers: []allowlist.Container{{
				Digest:  mustDigest(t, wlDigest),
				Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: entrypoint},
				Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
			}}},
		},
	}
}

func TestCheckImage_FloorDigest_AdmitsAnyArgv(t *testing.T) {
	// A floor digest is admitted regardless of the effective argv.
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr",
		"registry/repo@"+pushDigestA, []string{"/anything", "--wild"})
	if verdict != verdictAllow {
		t.Fatalf("floor digest should admit any argv, got %d (reason=%q)", verdict, reason)
	}
}

func TestCheckImage_WorkloadDigest_ArgvMatchAdmits(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr",
		"registry/repo@"+pushDigestB, []string{"/bin/app", "--serve"})
	if verdict != verdictAllow {
		t.Fatalf("matching argv should admit workload digest, got %d (reason=%q)", verdict, reason)
	}
}

func TestCheckImage_WorkloadDigest_ArgvMismatchDenies(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))

	verdict, _ := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr",
		"registry/repo@"+pushDigestB, []string{"/bin/evil"})
	if verdict != verdictDeny {
		t.Fatalf("non-matching argv should deny workload digest, got %d", verdict)
	}
}

func TestCreateContainer_WorkloadArgv_MatchAndMismatch(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "floor-image"}},
		Policy:    policyConfig{Mode: ModeFailClosed},
	}, workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}))
	p.SetReady()

	pod := makePod("default", "mypod")

	match := makeCtrWithImageArgs(pod.Id, "match", "registry/repo@"+pushDigestB, []string{"/bin/app", "--serve"})
	if _, _, err := p.CreateContainer(context.Background(), pod, match); err != nil {
		t.Fatalf("matching argv should be admitted, got: %v", err)
	}

	mismatch := makeCtrWithImageArgs(pod.Id, "mismatch", "registry/repo@"+pushDigestB, []string{"/bin/evil"})
	if _, _, err := p.CreateContainer(context.Background(), pod, mismatch); err == nil {
		t.Fatal("non-matching argv should be denied")
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

// makeCtrWithImageArgs is makeCtrWithImage plus the container's effective argv
// (NRI folds the OCI process.args into api.Container.Args).
func makeCtrWithImageArgs(podSandboxID, name, image string, args []string) *api.Container {
	ctr := makeCtrWithImage(podSandboxID, name, image)
	ctr.Args = args
	return ctr
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

// --- checkExisting via deferred check (audit mode → no container kill attempted) ---

func TestRunDeferredCheck_AuditMode_NoKill(t *testing.T) {
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
	// mode means checkExisting continues without attempting a kill.
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	p.deferredMu.Lock()
	p.deferredPods = []*api.PodSandbox{pod}
	p.deferredCtrs = []*api.Container{ctr}
	p.deferredMu.Unlock()

	// Should run the check without panicking or touching the (nil) resolver.
	p.RunDeferredCheck(context.Background())
}

func TestRunDeferredCheck_OrphanContainer_Skipped(t *testing.T) {
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

	p.RunDeferredCheck(context.Background())
}

func TestRunDeferredCheck_ExemptNamespace_Skipped(t *testing.T) {
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

	// Exempt namespace → checkLabels returns verdictSkip → check continues,
	// fail-closed mode but no kill because the container is skipped entirely.
	p.RunDeferredCheck(context.Background())
}

func TestRunDeferredCheck_EnforceExistingDisabled_NoOp(t *testing.T) {
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
	p.RunDeferredCheck(context.Background())
}

// --- enforce_existing=false still rebuilds broker state across a restart ---

func TestSynchronize_EnforceExistingDisabled_BrokerRecordsWithoutKilling(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.broker = newWorkloadBroker("/proc")
	p.SetReady()

	pod := makePod("default", "pod1")
	allowed := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestA)
	denied := makeCtrWithImage(pod.Id, "ctr2", "registry/repo@"+pushDigestB)

	// Fail-closed, but enforce_existing off: the denied container must not reach
	// resolver.StopContainer (nil containerd client → panic).
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{allowed, denied}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec, ok := p.broker.containers[allowed.Id]
	if !ok {
		t.Fatalf("allowlisted container not recorded for the broker: %v", p.broker.containers)
	}
	if rec.digest != pushDigestA {
		t.Fatalf("recorded digest = %q, want %q", rec.digest, pushDigestA)
	}
	if _, ok := p.broker.containers[denied.Id]; ok {
		t.Fatal("denied container must not be recorded for the broker")
	}
}

// The restart sequence in full: NRI replays Synchronize before the initial CDS
// pull completes, so recovery runs through the deferred path.
func TestSynchronize_EnforceExistingDisabled_NotReady_DefersThenRecords(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: false},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.broker = newWorkloadBroker("/proc")

	pod := makePod("default", "pod1")
	ctr := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestA)

	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.broker.containers) != 0 {
		t.Fatal("nothing should be recorded before the plugin is ready")
	}

	p.SetReady()
	p.RunDeferredCheck(context.Background())

	if _, ok := p.broker.containers[ctr.Id]; !ok {
		t.Fatalf("deferred check did not record the container: %v", p.broker.containers)
	}
}

func TestSynchronize_Ready_AuditMode_RunsCheck(t *testing.T) {
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
