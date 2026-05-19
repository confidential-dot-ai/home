// Package controller hosts the controller-runtime manager, the slim
// ConfidentialWorkload status-mirror reconciler, and the admission webhook.
package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha2 "github.com/lunal-dev/c8s/api/v1alpha2"
	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/internal/webhook"
	"github.com/lunal-dev/c8s/pkg/certutil"
)

// Options configures the controller-manager runtime.
type Options struct {
	MetricsAddr      string
	HealthAddr       string
	LeaderElection   bool
	LeaderElectionID string
	LeaderElectionNS string

	// DisableStatusMirror skips the CRD-backed ConfidentialWorkload status
	// mirror controller. Pod injection does not depend on CRDs.
	DisableStatusMirror bool

	// GetCertImage is the c8s multi-mode binary image the admission webhook
	// injects for get-cert bootstrap and renewal. Empty disables pod injection.
	// Pod-to-pod mTLS is the node-level ratls-mesh DaemonSet's job, so no mesh
	// sidecar is injected.
	GetCertImage string

	// AssamURL points at the assam Service in-cluster (the URL the
	// injected get-cert containers POST evidence + CSR to).
	AssamURL string

	// AttestationServiceURL points at the attestation-service.
	AttestationServiceURL string

	// WebhookConfigName is the MutatingWebhookConfiguration to patch.
	WebhookConfigName string

	WebhookServiceName      string
	WebhookServiceNamespace string

	CertFSGroup         int64
	CertKeyMode         string
	CertRenewInterval   time.Duration
	GetCertRunAsUser    int64
	GetCertRunAsGroup   int64
	GetCertRunAsNonRoot bool
}

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha2.AddToScheme(scheme))
}

// Run boots the manager and blocks until ctx is cancelled or the manager exits.
func Run(ctx context.Context, opts Options) error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	logger := ctrl.Log.WithName("c8s-operator")

	config := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: opts.MetricsAddr},
		HealthProbeBindAddress:  opts.HealthAddr,
		LeaderElection:          opts.LeaderElection,
		LeaderElectionID:        opts.LeaderElectionID,
		LeaderElectionNamespace: opts.LeaderElectionNS,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	if opts.DisableStatusMirror {
		logger.Info("status-mirror controller disabled by configuration")
	} else {
		dc, err := discovery.NewDiscoveryClientForConfig(config)
		if err != nil {
			return fmt.Errorf("create discovery client: %w", err)
		}
		available, err := confidentialWorkloadCRDAvailable(dc)
		if err != nil {
			return fmt.Errorf("discover ConfidentialWorkload CRD: %w", err)
		}
		if available {
			if err := (&ConfidentialWorkloadReconciler{
				Client: mgr.GetClient(),
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("setup ConfidentialWorkload reconciler: %w", err)
			}
			logger.Info("status-mirror controller enabled")
		} else {
			logger.Info("status-mirror controller disabled; ConfidentialWorkload CRD not found")
		}
	}

	// Admission webhook — injects get-cert containers into annotated pods.
	if opts.GetCertImage != "" {
		if err := bootstrapWebhookPKI(ctx, mgr, opts); err != nil {
			return fmt.Errorf("bootstrap webhook PKI: %w", err)
		}
		if err := webhook.Register(mgr, webhook.Config{
			GetCertImage:          opts.GetCertImage,
			AssamURL:              opts.AssamURL,
			AttestationServiceURL: opts.AttestationServiceURL,
			CertFSGroup:           int64Ptr(opts.CertFSGroup),
			CertKeyMode:           opts.CertKeyMode,
			CertRenewInterval:     opts.CertRenewInterval,
			GetCertRunAsUser:      int64Ptr(opts.GetCertRunAsUser),
			GetCertRunAsGroup:     int64Ptr(opts.GetCertRunAsGroup),
			GetCertRunAsNonRoot:   boolPtr(opts.GetCertRunAsNonRoot),
		}); err != nil {
			return fmt.Errorf("register webhook: %w", err)
		}
		logger.Info("pod-injection webhook enabled",
			"image", opts.GetCertImage,
			"assam", opts.AssamURL)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz: %w", err)
	}

	logger.Info("starting manager",
		"metrics", opts.MetricsAddr,
		"health", opts.HealthAddr,
		"leaderElection", opts.LeaderElection)

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}

type serverResourcesForGroupVersion interface {
	ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error)
}

func confidentialWorkloadCRDAvailable(dc serverResourcesForGroupVersion) (bool, error) {
	resources, err := dc.ServerResourcesForGroupVersion(v1alpha2.GroupVersion.String())
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if resources == nil {
		return false, nil
	}
	for _, resource := range resources.APIResources {
		if resource.Name == "confidentialworkloads" && resource.Kind == "ConfidentialWorkload" {
			return true, nil
		}
	}
	return false, nil
}

// bootstrapWebhookPKI mints a fresh CA + serving cert for the admission
// webhook and patches the CA bundle onto the MutatingWebhookConfiguration
// so the API server trusts the webhook.
//
// The CA is ephemeral — re-minted on every operator restart. That's fine
// for the admission webhook (a request path, not a durable trust anchor):
// the restart re-patches the bundle and the API server starts trusting the
// new cert.
func bootstrapWebhookPKI(ctx context.Context, mgr ctrl.Manager, opts Options) error {
	if opts.WebhookConfigName == "" {
		return nil
	}

	svcName := opts.WebhookServiceName
	svcNS := opts.WebhookServiceNamespace
	if svcNS == "" {
		svcNS = opts.LeaderElectionNS
	}
	if svcName == "" {
		return fmt.Errorf("webhook-service-name is required when webhook-config-name is set")
	}

	hostnames := []string{
		fmt.Sprintf("%s.%s.svc", svcName, svcNS),
		fmt.Sprintf("%s.%s.svc.cluster.local", svcName, svcNS),
	}

	ca, err := issuer.NewCA(fmt.Sprintf("%s webhook", svcName), webhook.ServingTLSTTL)
	if err != nil {
		return fmt.Errorf("mint webhook CA: %w", err)
	}
	if err := webhook.BootstrapServingCert(ca, hostnames, webhook.DefaultCertDir); err != nil {
		return err
	}

	// Manager's cache hasn't started yet, so we can't use mgr.GetClient().
	// A direct client tied to the manager's REST config + scheme is the
	// right primitive here — one Update, no informers needed.
	c, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return fmt.Errorf("build bootstrap client: %w", err)
	}
	caPEM := certutil.EncodeCertPEM(ca.Cert.Raw)
	return webhook.PatchCABundle(ctx, c, opts.WebhookConfigName, caPEM)
}

func boolPtr(v bool) *bool {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}
