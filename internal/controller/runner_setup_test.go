package controller

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	v1alpha2 "github.com/confidential-dot-ai/c8s/api/v1alpha2"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

// testRESTMapper is a static mapper covering the kinds the package wires up,
// so manager construction never needs API discovery.
func testRESTMapper() meta.RESTMapper {
	m := meta.NewDefaultRESTMapper(nil)
	for _, gvk := range []schema.GroupVersionKind{
		corev1.SchemeGroupVersion.WithKind("Service"),
		corev1.SchemeGroupVersion.WithKind("Pod"),
		appsv1.SchemeGroupVersion.WithKind("Deployment"),
		appsv1.SchemeGroupVersion.WithKind("StatefulSet"),
		appsv1.SchemeGroupVersion.WithKind("DaemonSet"),
		v1alpha2.GroupVersion.WithKind("ConfidentialWorkload"),
	} {
		m.Add(gvk, meta.RESTScopeNamespace)
	}
	return m
}

// newTestManager builds a real — never started — manager against a dead REST
// endpoint. With the static mapper, construction is fully offline; nothing
// contacts the API server until Start, which these tests never call.
func newTestManager(t *testing.T) manager.Manager {
	t.Helper()
	opts := managerOptions(Options{MetricsAddr: "0", HealthAddr: "0"})
	opts.MapperProvider = func(*rest.Config, *http.Client) (meta.RESTMapper, error) {
		return testRESTMapper(), nil
	}
	// Several tests wire the same controller names onto fresh managers; the
	// uniqueness check is process-global.
	skip := true
	opts.Controller.SkipNameValidation = &skip
	mgr, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, opts)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// stubDirectClient replaces the package's direct-client factory for the test.
func stubDirectClient(t *testing.T, c client.Client, err error) {
	t.Helper()
	orig := newDirectClient
	newDirectClient = func(manager.Manager) (client.Client, error) { return c, err }
	t.Cleanup(func() { newDirectClient = orig })
}

// stubWebhookCertDir redirects serving-cert writes into a temp dir.
func stubWebhookCertDir(t *testing.T) string {
	t.Helper()
	orig := webhookCertDir
	dir := t.TempDir()
	webhookCertDir = dir
	t.Cleanup(func() { webhookCertDir = orig })
	return dir
}

func mutatingWebhookConfig(name string) *admissionv1.MutatingWebhookConfiguration {
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "pods.c8s.dev"},
			{Name: "other.c8s.dev"},
		},
	}
}

func TestSetupManagerFullWiring(t *testing.T) {
	dir := stubWebhookCertDir(t)
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(mutatingWebhookConfig("c8s-mutating")).Build()
	stubDirectClient(t, fc, nil)

	mgr := newTestManager(t)
	opts := Options{
		DisableStatusMirror: true,
		GetCertImage:        "ghcr.io/c8s/c8s:latest",
		CDSURL:              "https://cds.c8s-system.svc",
		KataEnforce:         true,
		HardwarePlatform:    "snp",
		WebhookConfigName:   "c8s-mutating",
		WebhookServiceName:  "c8s-webhook",
		LeaderElectionNS:    "c8s-system",
		ExcludeNamespaces:   []string{"skip-me"},
	}
	if err := setupManager(context.Background(), mgr, nil, opts, logr.Discard()); err != nil {
		t.Fatalf("setupManager: %v", err)
	}

	// The webhook serving certs must be minted on disk.
	for _, f := range []string{"tls.crt", "tls.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("serving cert %s not written: %v", f, err)
		}
	}
	// The CA bundle must be patched onto every webhook entry.
	var got admissionv1.MutatingWebhookConfiguration
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "c8s-mutating"}, &got); err != nil {
		t.Fatal(err)
	}
	for _, wh := range got.Webhooks {
		if len(wh.ClientConfig.CABundle) == 0 {
			t.Fatalf("webhook %q caBundle not patched", wh.Name)
		}
	}
}

func TestSetupManagerStatusMirror(t *testing.T) {
	available := &metav1.APIResourceList{APIResources: []metav1.APIResource{
		{Name: "confidentialworkloads", Kind: "ConfidentialWorkload"},
	}}
	tests := []struct {
		name    string
		dc      *fakeServerResources
		wantErr string
	}{
		{name: "crd available", dc: &fakeServerResources{resources: available}},
		{name: "crd missing", dc: &fakeServerResources{}},
		{name: "discovery error", dc: &fakeServerResources{err: errors.New("boom")},
			wantErr: "discover ConfidentialWorkload CRD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newTestManager(t)
			err := setupManager(context.Background(), mgr, tt.dc, Options{}, logr.Discard())
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("setupManager: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestSetupManagerSurfacesWebhookPKIError(t *testing.T) {
	mgr := newTestManager(t)
	// WebhookConfigName set but no service name: bootstrapWebhookPKI must fail
	// and setupManager must wrap it.
	opts := Options{
		DisableStatusMirror: true,
		KataEnforce:         true,
		WebhookConfigName:   "c8s-mutating",
	}
	err := setupManager(context.Background(), mgr, nil, opts, logr.Discard())
	if err == nil || !strings.Contains(err.Error(), "bootstrap webhook PKI") {
		t.Fatalf("err = %v, want a bootstrap webhook PKI error", err)
	}
}

func TestBootstrapWebhookPKISkipsWithoutConfigName(t *testing.T) {
	if err := bootstrapWebhookPKI(context.Background(), nil, Options{}); err != nil {
		t.Fatalf("bootstrapWebhookPKI without config name: %v", err)
	}
}

func TestBootstrapWebhookPKIRequiresServiceName(t *testing.T) {
	err := bootstrapWebhookPKI(context.Background(), nil, Options{WebhookConfigName: "c8s-mutating"})
	if err == nil || !strings.Contains(err.Error(), "webhook-service-name is required") {
		t.Fatalf("err = %v, want webhook-service-name requirement", err)
	}
}

func TestBootstrapWebhookPKIPatchesBundleAndAddsRotator(t *testing.T) {
	dir := stubWebhookCertDir(t)
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(mutatingWebhookConfig("c8s-mutating")).Build()
	stubDirectClient(t, fc, nil)

	mgr := newTestManager(t)
	opts := Options{
		WebhookConfigName:  "c8s-mutating",
		WebhookServiceName: "c8s-webhook",
		// No WebhookServiceNamespace: exercises the LeaderElectionNS fallback.
		LeaderElectionNS: "c8s-system",
	}
	if err := bootstrapWebhookPKI(context.Background(), mgr, opts); err != nil {
		t.Fatalf("bootstrapWebhookPKI: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls.crt")); err != nil {
		t.Fatalf("serving cert not written: %v", err)
	}
	var got admissionv1.MutatingWebhookConfiguration
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "c8s-mutating"}, &got); err != nil {
		t.Fatal(err)
	}
	for _, wh := range got.Webhooks {
		if len(wh.ClientConfig.CABundle) == 0 {
			t.Fatalf("webhook %q caBundle not patched", wh.Name)
		}
	}
}

func TestBootstrapWebhookPKIDirectClientError(t *testing.T) {
	stubWebhookCertDir(t)
	stubDirectClient(t, nil, errors.New("no client"))
	opts := Options{
		WebhookConfigName:       "c8s-mutating",
		WebhookServiceName:      "c8s-webhook",
		WebhookServiceNamespace: "c8s-system",
	}
	err := bootstrapWebhookPKI(context.Background(), nil, opts)
	if err == nil || !strings.Contains(err.Error(), "build bootstrap client") {
		t.Fatalf("err = %v, want build bootstrap client failure", err)
	}
}

func TestBootstrapWebhookPKIPatchFailure(t *testing.T) {
	stubWebhookCertDir(t)
	// No MutatingWebhookConfiguration in the fake: the patch's Get fails.
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()
	stubDirectClient(t, fc, nil)
	opts := Options{
		WebhookConfigName:       "c8s-mutating",
		WebhookServiceName:      "c8s-webhook",
		WebhookServiceNamespace: "c8s-system",
	}
	err := bootstrapWebhookPKI(context.Background(), nil, opts)
	if err == nil || !strings.Contains(err.Error(), "MutatingWebhookConfiguration") {
		t.Fatalf("err = %v, want a caBundle patch failure", err)
	}
}

func TestWebhookCertRotatorRetriesOnFailure(t *testing.T) {
	ca, err := issuer.NewCA("test webhook", webhook.WebhookCATTL)
	if err != nil {
		t.Fatal(err)
	}
	// certDir under a regular file: BootstrapServingCert cannot create it, so
	// every rotation attempt fails and the retry branch runs.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	certDir := filepath.Join(blocker, "certs")

	var mu sync.Mutex
	failures := 0
	logger := funcr.New(func(prefix, args string) {
		mu.Lock()
		failures++
		mu.Unlock()
	}, funcr.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// Tiny TTL: interval ≈ 20ms and retry = interval/2, so failures accrue fast.
		_ = webhookCertRotator(ca, []string{"svc.ns.svc"}, certDir, 30*time.Millisecond, logger)(ctx)
		close(done)
	}()

	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := failures
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for rotation failures to be retried")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("rotator did not stop after cancel")
	}
}

// writeKubeconfig writes a kubeconfig pointing at a dead endpoint so
// ctrl.GetConfigOrDie succeeds offline.
func writeKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	cfg := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://127.0.0.1:1
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user: {}
`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunFailsWithoutReachableAPIServer(t *testing.T) {
	t.Setenv("KUBECONFIG", writeKubeconfig(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The kubeconfig parses (so GetConfigOrDie succeeds offline), but manager
	// construction needs API discovery for the label-scoped Service cache and
	// the endpoint is dead, so Run must surface the create-manager error.
	err := Run(ctx, Options{DisableStatusMirror: true, MetricsAddr: "0", HealthAddr: "0"})
	if err == nil || !strings.Contains(err.Error(), "create manager") {
		t.Fatalf("err = %v, want create manager failure", err)
	}
}

func TestConfidentialWorkloadSetupWithManager(t *testing.T) {
	mgr := newTestManager(t)
	r := &ConfidentialWorkloadReconciler{Client: mgr.GetClient()}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}
}

func TestWorkloadServiceSetupWithManagerAllKinds(t *testing.T) {
	mgr := newTestManager(t)
	for _, kind := range workloadServiceKinds {
		r := &WorkloadServiceReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: mgr.GetEventRecorder("c8s-operator-test"),
			Kind:     kind,
		}
		if err := r.SetupWithManager(mgr); err != nil {
			t.Fatalf("SetupWithManager(%s): %v", kind, err)
		}
	}
}
