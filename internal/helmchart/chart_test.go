package helmchart

import (
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
		"app.kubernetes.io/name: tee-proxy",
		"port: 443\n      targetPort: 443\n      protocol: TCP\n      name: https",
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

func TestChartRendersManagedClusterKnobs(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "serviceAccount.imagePullSecrets[0].name=ghcr-secret",
		"--set", "attestationService.privileged=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"imagePullSecrets:\n- name: ghcr-secret",
		"securityContext:\n            privileged: true\n            readOnlyRootFilesystem: true",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
}

func TestChartRendersTLSLBPublicTLSAndDiscovery(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "tls-lb.publicTLS.secretName=tls-lb-public-tls",
		"--set-string", "tls-lb.publicTLS.mountPath=/edge-tls",
		"--set-string", "tls-lb.publicTLS.certKey=public.crt",
		"--set-string", "tls-lb.publicTLS.keyKey=public.key",
		"--set", "tls-lb.discovery.enabled=true",
		"--set-string", "tls-lb.meshCA.configMapName=c8s-cert-issuer-mesh-ca",
		"--set-string", "tls-lb.upstream.address=c8s-tee-proxy:443",
		"--set", "tls-lb.upstream.protocol=https",
		"--set", "tls-lb.upstream.tls.verify=true",
		"--set-string", "tls-lb.upstream.tls.serverName=tee-proxy.tee-attestation.svc.cluster.local",
		"--set", "tee-proxy.tls.enabled=true",
		"--set-string", "tee-proxy.tls.secretName=tee-proxy-internal-tls",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"ssl_certificate     /edge-tls/public.crt;",
		"ssl_certificate_key /edge-tls/public.key;",
		"ECDHE-RSA-AES128-GCM-SHA256",
		"location = /v1/discovery",
		"alias /discovery/discovery.json;",
		"location = /.well-known/cds-cert.pem",
		"alias /tls/cert.pem;",
		"location = /.well-known/mesh-ca.pem",
		"alias /mesh-ca/ca.pem;",
		"proxy_ssl_certificate /tls/cert.pem;",
		"proxy_ssl_certificate_key /tls/key.pem;",
		"proxy_ssl_name tee-proxy.tee-attestation.svc.cluster.local;",
		"proxy_ssl_verify on;",
		"proxy_ssl_trusted_certificate /mesh-ca/ca.pem;",
		"proxy_pass https://backend;",
		"--discovery-out=/discovery/discovery.json",
		"--discovery-cds-cert-url=/.well-known/cds-cert.pem",
		"--discovery-public-tls-mode=webpki",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem",
		"--reload-watch=/edge-tls/public.crt",
		"--reload-watch=/edge-tls/public.key",
		"name: public-tls",
		"mountPath: /edge-tls",
		"secretName: tls-lb-public-tls",
		"key: public.crt",
		"path: public.key",
		"name: discovery",
		"name: mesh-ca",
		"name: c8s-cert-issuer-mesh-ca",
		"optional: false",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
}

func TestChartRendersTeeProxyStaticTLSSecret(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "tee-proxy.tls.enabled=true",
		"--set-string", "tee-proxy.tls.secretName=tee-proxy-internal-tls",
		"--set-string", "tls-lb.upstream.address=c8s-tee-proxy:443",
		"--set", "tls-lb.upstream.protocol=https",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"- --tls-dir",
		"- \"/tls\"",
		"mountPath: /tls",
		"name: static-tls",
		"secretName: tee-proxy-internal-tls",
		"key: tls.crt",
		"path: localhost+2.pem",
		"key: tls.key",
		"path: localhost+2-key.pem",
		"port: 443",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
}

func TestChartRejectsManagedTeeProxyHTTPSWithoutTLS(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "tls-lb.upstream.address=c8s-tee-proxy:443",
		"--set", "tls-lb.upstream.protocol=https",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want tee-proxy TLS failure\n%s", out)
	}
	if !strings.Contains(out, "requires tee-proxy.tls.enabled=true or tee-proxy.domain") {
		t.Fatalf("missing tee-proxy TLS error, got:\n%s", out)
	}
}

func TestChartRejectsTLSLBHTTPSWithDefaultTeeProxyHTTPPort(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "tls-lb.upstream.protocol=https",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want tls-lb upstream address failure\n%s", out)
	}
	if !strings.Contains(out, "tls-lb.upstream.protocol=https requires tls-lb.upstream.address to point at a TLS port") {
		t.Fatalf("missing tls-lb upstream address error, got:\n%s", out)
	}
}

func TestTLSLBVerifyDerivesProxySSLNameFromUpstream(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "upstream.address=tee-proxy.tee-attestation.svc.cluster.local:443",
		"--set", "upstream.protocol=https",
		"--set", "upstream.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !strings.Contains(out, "proxy_ssl_name tee-proxy.tee-attestation.svc.cluster.local;") {
		t.Fatalf("render missing derived proxy_ssl_name\n%s", out)
	}
}

func TestTLSLBAdditionalRoutesConfigureNginxLocations(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/whitelist",
		"--set-string", "routes[0].match=exact",
		"--set-string", "routes[0].upstream=http://assam.c8s-system.svc:8080",
		"--set-string", "routes[1].path=/tenant/",
		"--set-string", "routes[1].upstream=http://tenant-router.c8s-system.svc:8080",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	conf := renderedTLSLBNginxConf(t, out)

	for _, tt := range []struct {
		name     string
		location string
		upstream string
	}{
		{
			name:     "exact",
			location: "location = /whitelist {",
			upstream: "http://assam.c8s-system.svc:8080",
		},
		{
			name:     "default-prefix",
			location: "location /tenant/ {",
			upstream: "http://tenant-router.c8s-system.svc:8080",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			block := nginxLocationBlock(t, conf, tt.location)
			want := "proxy_pass " + tt.upstream + ";"
			if !strings.Contains(block, want) {
				t.Fatalf("location block missing %q\n%s", want, block)
			}
		})
	}

	if strings.Contains(nginxLocationBlock(t, conf, "location / {"), "assam.c8s-system.svc") {
		t.Fatalf("default backend location should not inherit route upstreams\n%s", conf)
	}
}

func renderedTLSLBNginxConf(t *testing.T, manifest string) string {
	t.Helper()

	decoder := yaml.NewDecoder(strings.NewReader(manifest))
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("parse rendered manifest: %v\n%s", err, manifest)
		}
		if doc == nil || doc["kind"] != "ConfigMap" {
			continue
		}
		metadata, ok := doc["metadata"].(map[string]any)
		if !ok || metadata["name"] != "tls-lb-nginx" {
			continue
		}
		data, ok := doc["data"].(map[string]any)
		if !ok {
			t.Fatalf("tls-lb nginx ConfigMap missing data\n%s", manifest)
		}
		conf, ok := data["nginx.conf"].(string)
		if !ok || conf == "" {
			t.Fatalf("tls-lb nginx ConfigMap missing nginx.conf\n%s", manifest)
		}
		return conf
	}
	t.Fatalf("rendered manifest missing tls-lb nginx ConfigMap\n%s", manifest)
	return ""
}

func nginxLocationBlock(t *testing.T, conf, location string) string {
	t.Helper()

	start := strings.Index(conf, location)
	if start < 0 {
		t.Fatalf("nginx config missing location %q\n%s", location, conf)
	}
	var block strings.Builder
	for _, line := range strings.Split(conf[start:], "\n") {
		block.WriteString(line)
		block.WriteByte('\n')
		if strings.TrimSpace(line) == "}" {
			return block.String()
		}
	}
	t.Fatalf("nginx config location %q is not closed\n%s", location, conf)
	return ""
}

func TestTLSLBRejectsInvalidRouteMatch(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/whitelist",
		"--set-string", "routes[0].match=regex",
		"--set-string", "routes[0].upstream=http://assam.c8s-system.svc:8080",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want invalid route match failure\n%s", out)
	}
	if !strings.Contains(out, "tls-lb.routes[0].match must be 'exact' or 'prefix'") {
		t.Fatalf("missing route match error, got:\n%s", out)
	}
}

func TestTLSLBRejectsMissingRouteFields(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "path",
			args: []string{
				"--set-string", "routes[0].upstream=http://assam.c8s-system.svc:8080",
			},
			want: "tls-lb.routes[0].path is required",
		},
		{
			name: "upstream",
			args: []string{
				"--set-string", "routes[0].path=/whitelist",
			},
			want: "tls-lb.routes[0].upstream is required",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplateTLSLB(t, tt.args...)
			if err == nil {
				t.Fatalf("helm template succeeded, want missing route field failure\n%s", out)
			}
			if !strings.Contains(out, tt.want) {
				t.Fatalf("missing route field error %q, got:\n%s", tt.want, out)
			}
		})
	}
}

func TestTLSLBRejectsUnsafeRoutePath(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/bad;return",
		"--set-string", "routes[0].upstream=http://assam.c8s-system.svc:8080",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want unsafe route path failure\n%s", out)
	}
	if !strings.Contains(out, "tls-lb.routes[0].path must start with '/'") {
		t.Fatalf("missing route path error, got:\n%s", out)
	}
}

func TestTLSLBRejectsHTTPSRouteUpstream(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/whitelist",
		"--set-string", "routes[0].upstream=https://assam.c8s-system.svc:8443",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want https route upstream failure\n%s", out)
	}
	if !strings.Contains(out, "route-specific HTTPS upstreams are not supported") {
		t.Fatalf("missing route upstream error, got:\n%s", out)
	}
}

func TestTLSLBCustomTrustedCAPathDoesNotMountMeshCA(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "upstream.protocol=https",
		"--set", "upstream.tls.verify=true",
		"--set-string", "upstream.tls.trustedCAPath=/etc/ssl/certs/ca-certificates.crt",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !strings.Contains(out, "proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;") {
		t.Fatalf("render missing custom trusted CA path\n%s", out)
	}
	if strings.Contains(out, "- name: mesh-ca") {
		t.Fatalf("custom trustedCAPath should not mount the chart mesh CA\n%s", out)
	}
}

func TestTLSLBDefaultTrustedCAPathStillMountsMeshCAWhenExplicit(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "upstream.protocol=https",
		"--set", "upstream.tls.verify=true",
		"--set-string", "upstream.tls.trustedCAPath=/mesh-ca/ca.pem",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"proxy_ssl_trusted_certificate /mesh-ca/ca.pem;",
		"- name: mesh-ca",
		"optional: false",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
}

func TestTLSLBDiscoveryRequiresAdvertisedMeshCA(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "discovery.enabled=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem",
		"alias /mesh-ca/ca.pem;",
		"- name: mesh-ca",
		"name: tls-lb-cert-issuer-mesh-ca",
		"optional: false",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
}

func TestTLSLBDiscoveryReportsCDSModeWithoutPublicTLSSecret(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "discovery.enabled=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !strings.Contains(out, "--discovery-public-tls-mode=cds") {
		t.Fatalf("discovery without public TLS Secret should report CDS mode\n%s", out)
	}
}

func TestTLSLBRollsOnNginxConfigChange(t *testing.T) {
	defaultOut, err := helmTemplateTLSLB(t)
	if err != nil {
		t.Fatalf("helm template default config: %v\n%s", err, defaultOut)
	}
	defaultChecksum := renderedValue(t, defaultOut, "checksum/nginx-config")
	if defaultChecksum == "" {
		t.Fatalf("default checksum/nginx-config is empty\n%s", defaultOut)
	}

	changedOut, err := helmTemplateTLSLB(t,
		"--set-string", "upstream.address=other-upstream:8080",
	)
	if err != nil {
		t.Fatalf("helm template changed config: %v\n%s", err, changedOut)
	}
	changedChecksum := renderedValue(t, changedOut, "checksum/nginx-config")
	if changedChecksum == defaultChecksum {
		t.Fatalf("checksum/nginx-config did not change after changing upstream: %s", defaultChecksum)
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

func TestChartRollsAttestationServiceOnConfigChange(t *testing.T) {
	defaultOut, err := helmTemplate(t,
		"--set-string", "attestationService.apiKey=fixed-api-key",
	)
	if err != nil {
		t.Fatalf("helm template default config: %v\n%s", err, defaultOut)
	}
	if !strings.Contains(defaultOut, `api_keys = ["fixed-api-key"]`) {
		t.Fatalf("default attestation-service config missing fixed api key\n%s", defaultOut)
	}
	defaultChecksum := renderedValue(t, defaultOut, "checksum/config")
	if defaultChecksum == "" {
		t.Fatalf("default checksum/config is empty\n%s", defaultOut)
	}

	changedOut, err := helmTemplate(t,
		"--set-string", "attestationService.apiKey=fixed-api-key",
		"--set", "webhook.apiKeySecret.createInNamespaces={tenant-a}",
	)
	if err != nil {
		t.Fatalf("helm template changed config: %v\n%s", err, changedOut)
	}
	changedChecksum := renderedValue(t, changedOut, "checksum/config")
	if changedChecksum == defaultChecksum {
		t.Fatalf("checksum/config did not change after adding workload namespace key: %s", defaultChecksum)
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
		"--set", "tee-proxy.image.tag=dev",
		"--set", "tls-lb.initContainer.image.tag=dev",
	}
	cmd := exec.Command("helm", append(base, args...)...)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func renderedValue(t *testing.T, manifest, key string) string {
	t.Helper()
	prefix := key + ": "
	for _, line := range strings.Split(manifest, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
		}
	}
	t.Fatalf("rendered manifest missing %q\n%s", key, manifest)
	return ""
}

func helmTemplateTLSLB(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	base := []string{
		"template", "tls-lb", "c8s/charts/tls-lb",
		"--namespace", "c8s-system",
		"--set", "initContainer.image.tag=dev",
		"--set", "nginx.image.tag=dev",
	}
	cmd := exec.Command("helm", append(base, args...)...)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	return string(out), err
}
