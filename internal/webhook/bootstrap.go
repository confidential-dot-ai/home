package webhook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// DefaultCertDir is controller-runtime's webhook-server default.
const DefaultCertDir = "/tmp/k8s-webhook-server/serving-certs"

// ServingTLSTTL bounds how long a bootstrapped serving cert (the leaf) is valid
// for. The operator re-mints it before expiry in-process (see the cert-rotator
// runnable in the controller runner), so the webhook no longer depends on a pod
// restart to stay valid — an unrotated leaf would otherwise expire and, with a
// fail-closed admission webhook, block all in-scope Pod creation.
const ServingTLSTTL = 30 * 24 * time.Hour

// WebhookCATTL is the validity of the webhook's ephemeral CA. It is long-lived
// so the CA bundle patched onto the MutatingWebhookConfiguration stays stable
// for the operator pod's lifetime while short-lived leaves rotate under it —
// keeping caBundle churn (and the leaf/bundle mismatch it can cause during a
// rollout) out of the steady state. The CA is still re-minted on operator
// restart, which re-patches the bundle.
const WebhookCATTL = 10 * 365 * 24 * time.Hour

// BootstrapServingCert mints a webhook serving cert from the mesh CA and
// writes it into certDir. Hostnames must include every DNS name the API
// server might use to reach the webhook Service; at minimum the in-cluster
// Service DNS. Passing an empty certDir uses DefaultCertDir.
func BootstrapServingCert(ca *issuer.CA, hostnames []string, certDir string) error {
	if ca == nil {
		return fmt.Errorf("ca is nil")
	}
	if len(hostnames) == 0 {
		return fmt.Errorf("at least one hostname required")
	}
	if certDir == "" {
		certDir = DefaultCertDir
	}

	res, err := ca.Issue(issuer.Request{
		CommonName: hostnames[0],
		DNSNames:   hostnames,
		TTL:        ServingTLSTTL,
	})
	if err != nil {
		return fmt.Errorf("issue webhook serving cert: %w", err)
	}

	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", certDir, err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "tls.crt"), res.CertPEM, 0o644); err != nil {
		return fmt.Errorf("write tls.crt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "tls.key"), res.KeyPEM, 0o600); err != nil {
		return fmt.Errorf("write tls.key: %w", err)
	}
	return nil
}

// PatchCABundle sets .webhooks[*].clientConfig.caBundle on the named
// MutatingWebhookConfiguration so the API server trusts the webhook's
// serving cert. Idempotent — the patch is a no-op when the bundle already
// matches.
func PatchCABundle(ctx context.Context, c client.Client, configName string, caPEM []byte) error {
	var cfg admissionv1.MutatingWebhookConfiguration
	if err := c.Get(ctx, types.NamespacedName{Name: configName}, &cfg); err != nil {
		return fmt.Errorf("get MutatingWebhookConfiguration %q: %w", configName, err)
	}
	changed := false
	for i := range cfg.Webhooks {
		if bytes.Equal(cfg.Webhooks[i].ClientConfig.CABundle, caPEM) {
			continue
		}
		cfg.Webhooks[i].ClientConfig.CABundle = caPEM
		changed = true
	}
	if !changed {
		return nil
	}
	if err := c.Update(ctx, &cfg); err != nil {
		return fmt.Errorf("update MutatingWebhookConfiguration %q: %w", configName, err)
	}
	return nil
}
