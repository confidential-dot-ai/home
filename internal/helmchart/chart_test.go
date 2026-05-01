package helmchart

import (
	"os/exec"
	"strings"
	"testing"
)

func TestChartDefaultRendersReplacementStack(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"kind: MutatingWebhookConfiguration",
		"--operator-image=",
		"--assam-url=http://c8s-assam.c8s-system.svc:8080",
		"app.kubernetes.io/component: assam",
		"app.kubernetes.io/component: cert-issuer",
		"app.kubernetes.io/name: ratls-mesh",
		"app.kubernetes.io/name: nri-image-policy",
		"app.kubernetes.io/name: node-container-whitelist",
		"app.kubernetes.io/name: tee-proxy",
		"app.kubernetes.io/name: tls-lb",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("default chart missing %q\n%s", want, out)
		}
	}
}

func TestChartCanDisableStatusMirror(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !strings.Contains(out, "--status-mirror-enabled=true") {
		t.Fatalf("default chart should enable status mirror\n%s", out)
	}

	out, err = helmTemplate(t, "--set", "statusMirror.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !strings.Contains(out, "--status-mirror-enabled=false") {
		t.Fatalf("statusMirror.enabled=false should disable status mirror\n%s", out)
	}
}

func TestChartWebhookRequiresAssamURL(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "webhook.enabled=true",
		"--set", "assam.enabled=false",
		"--set", "certIssuer.enabled=false",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want assam.url failure\n%s", out)
	}
	if !strings.Contains(out, "assam.url must be set when webhook.enabled=true unless assam.enabled=true") {
		t.Fatalf("missing assam.url error, got:\n%s", out)
	}
}

func TestChartAssamRequiresCertIssuerURL(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "assam.enabled=true",
		"--set", "certIssuer.enabled=false",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want assam.certIssuerURL failure\n%s", out)
	}
	if !strings.Contains(out, "assam.certIssuerURL must be set when assam.enabled=true") {
		t.Fatalf("missing assam.certIssuerURL error, got:\n%s", out)
	}
}

func TestChartAssamRequiresAttestationService(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "assam.enabled=true",
		"--set", "attestationService.enabled=false",
		"--set-string", "assam.certIssuerURL=http://cert-issuer.example.svc:8090",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want attestationService failure\n%s", out)
	}
	if !strings.Contains(out, "assam.enabled requires attestationService.enabled=true so Assam can verify evidence") {
		t.Fatalf("missing attestationService error, got:\n%s", out)
	}
}

func TestChartManagedAssamSatisfiesWebhookAssamURL(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "webhook.enabled=true",
		"--set", "assam.enabled=true",
		"--set-string", "assam.certIssuerURL=http://cert-issuer.c8s-system.svc:8090",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"app.kubernetes.io/component: assam",
		"--assam-url=http://c8s-assam.c8s-system.svc:8080",
		"image: ghcr.io/lunal-dev/assam:dev",
		"--cert-issuer-url=http://cert-issuer.c8s-system.svc:8090",
		"name: C8S_ASSAM_WHITELIST_ADMIN_PASSWORD",
		"confidential.ai/trust-boundary-warning",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "--whitelist-admin-password=") {
		t.Fatalf("Assam manifest should not serialize admin password in args\n%s", out)
	}
}

func TestChartManagedAssamAndCertIssuerWireTogether(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "webhook.enabled=true",
		"--set", "assam.enabled=true",
		"--set", "certIssuer.enabled=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"app.kubernetes.io/component: cert-issuer",
		"name: c8s-cert-issuer-mesh-ca",
		"mesh-ca.key:",
		"image: ghcr.io/lunal-dev/cert-issuer:dev",
		"--cert-issuer-url=http://c8s-cert-issuer.c8s-system.svc:8090",
		"--jwks-url=http://c8s-assam.c8s-system.svc:8080/.well-known/jwks.json",
		"chart-managed mesh CA is bootstrap convenience",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
}

func TestChartWebhookRendersSecretRefAuthAndSecurityKnobs(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "webhook.enabled=true",
		"--set-string", "assam.url=http://assam.example.svc:8080",
		"--set-string", "webhook.apiKeySecret.name=c8s-workload-attestation",
		"--set-string", "webhook.apiKeySecret.key=token",
		"--set", "webhook.certVolume.fsGroup=4242",
		"--set-string", "webhook.certVolume.keyMode=0440",
		"--set", "webhook.initContainer.runAsUser=0",
		"--set", "webhook.initContainer.runAsGroup=0",
		"--set", "webhook.initContainer.runAsNonRoot=false",
		"--set", "assam.enabled=false",
		"--set", "certIssuer.enabled=false",
		"--set", "ratls-mesh.enabled=false",
		"--set", "nri-image-policy.enabled=false",
		"--set", "node-container-whitelist.enabled=false",
		"--set", "tee-proxy.enabled=false",
		"--set", "tls-lb.enabled=false",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"kind: MutatingWebhookConfiguration",
		"--assam-url=http://assam.example.svc:8080",
		"--attestation-service-api-key-secret-name=c8s-workload-attestation",
		"--attestation-service-api-key-secret-key=token",
		"--cert-fs-group=4242",
		"--cert-key-mode=0440",
		"--init-run-as-user=0",
		"--init-run-as-group=0",
		"--init-run-as-non-root=false",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "C8S_ATTESTATION_SERVICE_API_KEY") {
		t.Fatalf("operator manifest should not contain literal API-key env\n%s", out)
	}
}

func TestChartRejectsOperatorReplicaOverride(t *testing.T) {
	out, err := helmTemplate(t, "--set", "operator.replicas=2")
	if err == nil {
		t.Fatalf("helm template succeeded, want operator.replicas failure\n%s", out)
	}
	if !strings.Contains(out, "operator.replicas is unsupported") {
		t.Fatalf("missing operator.replicas error, got:\n%s", out)
	}
}

func TestChartOperatorRBACIsScoped(t *testing.T) {
	out, err := helmTemplate(t, "--set", "webhook.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"resources: [confidentialworkloads]",
		"verbs: [get, list, watch]",
		"resources: [confidentialworkloads/status]",
		"verbs: [get, update, patch]",
		"resources: [pods]",
		"resources: [leases]",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
	for _, unexpected := range []string{
		"resources: [trustdomains]",
		"resources: [trustdomains/status]",
		"resources: [confidentialworkloads/finalizers]",
		"resources: [deployments, statefulsets, daemonsets, replicasets]",
		"resources: [secrets, configmaps]",
		"resources: [nodes]",
		"resources: [events]",
		"resources: [rolebindings]",
		"resources: [mutatingwebhookconfigurations]",
	} {
		if strings.Contains(out, unexpected) {
			t.Fatalf("render contained broad RBAC rule %q\n%s", unexpected, out)
		}
	}
}

func TestChartWebhookAddsCABundleRBAC(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "webhook.enabled=true",
		"--set-string", "assam.url=http://assam.example.svc:8080",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"resources: [mutatingwebhookconfigurations]",
		"verbs: [get, update, patch]",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
}

func TestChartCreatesWorkloadNamespaceSecrets(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "webhook.enabled=true",
		"--set-string", "assam.url=http://assam.example.svc:8080",
		"--set-string", "webhook.apiKeySecret.name=c8s-workload-attestation",
		"--set-string", "webhook.apiKeySecret.key=token",
		"--set", "webhook.apiKeySecret.createInNamespaces={tenant-a,tenant-b}",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"name: c8s-workload-attestation",
		"namespace: tenant-a",
		"namespace: tenant-b",
		"app.kubernetes.io/component: workload-auth",
		"token:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
}

func helmTemplate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	base := []string{
		"template", "c8s", "c8s",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "attestationService.image.tag=dev",
		"--set", "assam.image.tag=dev",
		"--set", "certIssuer.image.tag=dev",
		"--set", "ratls-mesh.image.tag=dev",
		"--set", "nri-image-policy.image.tag=dev",
		"--set", "node-container-whitelist.image.tag=dev",
		"--set", "tee-proxy.image.tag=dev",
		"--set", "tls-lb.initContainer.image.tag=dev",
	}
	cmd := exec.Command("helm", append(base, args...)...)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	return string(out), err
}
