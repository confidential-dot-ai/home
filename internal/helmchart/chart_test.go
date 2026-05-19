package helmchart

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	webhook "github.com/lunal-dev/c8s/internal/webhook"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

func TestChartDefaultRendersReplacementStack(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !renderedManifestHasKind(t, out, "MutatingWebhookConfiguration") {
		t.Fatalf("default chart missing MutatingWebhookConfiguration\n%s", out)
	}
	for _, want := range []string{
		"app.kubernetes.io/component: assam",
		"app.kubernetes.io/component: cert-issuer",
		"app.kubernetes.io/name: ratls-mesh",
		"app.kubernetes.io/name: nri-image-policy",
		"app.kubernetes.io/name: tee-proxy",
		"port: 443\n      targetPort: 443\n      protocol: TCP\n      name: https",
		"app.kubernetes.io/name: tls-lb",
		"server_name \"c8s-tls-lb.c8s-system.svc\";",
		"Route: /whitelist -> http://c8s-assam.c8s-system.svc:8080",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("default chart missing %q\n%s", want, out)
		}
	}
	assertRenderedDeploymentPodAnnotations(t, out, "c8s-tls-lb", tlsLBAnnotations("c8s-tls-lb.c8s-system.svc", nil))
	if got := renderedDeploymentInitContainers(t, out, "c8s-tls-lb"); len(got) != 0 {
		t.Fatalf("tls-lb should rely on webhook-injected get-cert containers, got %v", got)
	}
	args := renderedOperatorArgs(t, out)
	for _, want := range []string{
		"--get-cert-image=ghcr.io/lunal-dev/c8s-operator:dev",
		"--assam-url=https://c8s-assam.c8s-system.svc:8080",
		"--get-cert-renew-interval=6h",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("operator args missing %q\n%v", want, args)
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

func TestChartWebhookSelectsPlatformPodsWithoutBootstrappingAllPods(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	generalWebhook := renderedMutatingWebhook(t, out, "pods.c8s.confidential.ai")
	excludedNamespaces := selectorExpressionValues(generalWebhook.NamespaceSelector, "kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
	if !slices.Contains(excludedNamespaces, "c8s-system") {
		t.Fatalf("general webhook should exclude the release namespace: %v", excludedNamespaces)
	}
	for _, want := range []string{"kube-system", "kube-public", "kube-node-lease"} {
		if !slices.Contains(excludedNamespaces, want) {
			t.Fatalf("general webhook namespaceSelector missing excluded namespace %q: %v", want, excludedNamespaces)
		}
	}

	platformWebhook := renderedMutatingWebhook(t, out, "platform-pods.c8s.confidential.ai")
	wantPlatformLabels := map[string]string{
		"app.kubernetes.io/name":     "tls-lb",
		"app.kubernetes.io/instance": "c8s",
	}
	for key, want := range wantPlatformLabels {
		if got := platformWebhook.ObjectSelector.MatchLabels[key]; got != want {
			t.Fatalf("platform webhook objectSelector label %s = %q, want %q", key, got, want)
		}
	}
	releaseNamespaces := selectorExpressionValues(platformWebhook.NamespaceSelector, "kubernetes.io/metadata.name", metav1.LabelSelectorOpIn)
	if !slices.Contains(releaseNamespaces, "c8s-system") {
		t.Fatalf("platform webhook should select the release namespace: %v", releaseNamespaces)
	}
	assertRenderedDeploymentPodLabels(t, out, "c8s-tls-lb", wantPlatformLabels)
}

func TestChartManagedAssamSatisfiesWebhookAssamURL(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assamDeployment := renderedDeployment(t, out, "c8s-assam")
	if got := assamDeployment.Spec.Template.Annotations["confidential.ai/trust-boundary-warning"]; got == "" {
		t.Fatalf("c8s-assam Deployment missing confidential.ai/trust-boundary-warning annotation\nannotations: %v", assamDeployment.Spec.Template.Annotations)
	}
	if got := assamDeployment.Labels["app.kubernetes.io/component"]; got != "assam" {
		t.Fatalf("c8s-assam Deployment app.kubernetes.io/component label = %q, want %q", got, "assam")
	}
	assam := renderedDeploymentContainer(t, out, "c8s-assam", "assam")
	if assam.Image != "ghcr.io/lunal-dev/assam:dev" {
		t.Fatalf("assam container image = %q, want ghcr.io/lunal-dev/assam:dev", assam.Image)
	}
	operatorArgs := renderedOperatorArgs(t, out)
	assertContainerHasArg(t, "operator", operatorArgs, "--assam-url=https://c8s-assam.c8s-system.svc:8080")
	assertContainerHasArg(t, "assam", assam.Args, "--cert-issuer-url=https://c8s-cert-issuer.c8s-system.svc:8090")
	assertContainerNoArgPrefix(t, "assam", assam.Args, "--cert-issuer-url=http://")
}

func TestChartManagedAssamRendersResourceMap(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "assam.resourceMap.allowed[0]=assam/whitelist-write",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"name: c8s-assam-resource-map",
		"resource-map.json:",
		"\"allowed\": [",
		"\"assam/whitelist-write\"",
		"--resource-map=/etc/assam/resource-map.json",
		"mountPath: /etc/assam",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
}

func TestChartManagedAssamAndCertIssuerWireTogether(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	certIssuer := renderedDeployment(t, out, "c8s-cert-issuer")
	if got := certIssuer.Labels["app.kubernetes.io/component"]; got != "cert-issuer" {
		t.Fatalf("c8s-cert-issuer Deployment app.kubernetes.io/component label = %q, want %q", got, "cert-issuer")
	}
	if got := certIssuer.Spec.Template.Annotations["confidential.ai/trust-root-mode"]; got != "inMemory" {
		t.Fatalf("c8s-cert-issuer pod confidential.ai/trust-root-mode = %q, want %q", got, "inMemory")
	}
	if !renderedManifestHasNamedKind(t, out, "PersistentVolumeClaim", "c8s-cert-issuer-public-bundle") {
		t.Fatalf("missing PersistentVolumeClaim/c8s-cert-issuer-public-bundle\n%s", out)
	}
	container := renderedDeploymentContainer(t, out, "c8s-cert-issuer", "cert-issuer")
	if container.Image != "ghcr.io/lunal-dev/cert-issuer:dev" {
		t.Fatalf("cert-issuer container image = %q, want ghcr.io/lunal-dev/cert-issuer:dev", container.Image)
	}
	assertContainerHasArg(t, "cert-issuer", container.Args, "--ca-rotation-interval=720h")
	assertContainerHasArg(t, "cert-issuer", container.Args, "--ca-repo-dir=/var/lib/cert-issuer/public-bundle")
	assertContainerHasArg(t, "cert-issuer", container.Args, "--jwks-url=https://c8s-assam.c8s-system.svc:8080/.well-known/jwks.json")
	assam := renderedDeploymentContainer(t, out, "c8s-assam", "assam")
	assertContainerHasArg(t, "assam", assam.Args, "--cert-issuer-url=https://c8s-cert-issuer.c8s-system.svc:8090")
	assertContainerNoArgPrefix(t, "assam", assam.Args, "--cert-issuer-url=http://")
	for _, prefix := range []string{"--ca-key=", "--ca-cert="} {
		assertContainerNoArgPrefix(t, "cert-issuer", container.Args, prefix)
	}
	if renderedManifestHasKind(t, out, "Secret") {
		t.Fatalf("chart-managed cert-issuer should not render any Secret (mesh CA key stays in process memory)")
	}
}

// TestChartAssamServesRATLS proves the Assam container is wired to serve
// RA-TLS — without --ratls-platform set, /attest is plain HTTP and
// ratls-mesh's bootstrap-channel MITM defence (H1) is bypassed.
func TestChartAssamServesRATLS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assamArgs := renderedDeploymentContainer(t, out, "c8s-assam", "assam").Args
	if !slices.Contains(assamArgs, "--ratls-platform=snp") {
		t.Fatalf("assam container missing --ratls-platform=snp\nargs: %v", assamArgs)
	}
	for _, arg := range assamArgs {
		if strings.HasPrefix(arg, "--ratls-platform=") && arg != "--ratls-platform=snp" {
			t.Fatalf("assam --ratls-platform = %q, want snp (empty would disable RA-TLS)", arg)
		}
	}
}

// TestChartCallersDialAssamOverHTTPS proves the operator and the ratls-mesh
// daemonset dial Assam over https://, not http://. A regression here would
// silently turn off the H1 defence.
func TestChartCallersDialAssamOverHTTPS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	const wantAssamURL = "https://c8s-assam.c8s-system.svc:8080"

	operatorArgs := renderedOperatorArgs(t, out)
	assertContainerHasArg(t, "operator", operatorArgs, "--assam-url="+wantAssamURL)
	assertContainerNoArgPrefix(t, "operator", operatorArgs, "--assam-url=http://")

	meshArgs := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
	if i := slices.Index(meshArgs, "--assam-url"); i < 0 || i+1 >= len(meshArgs) {
		t.Fatalf("ratls-mesh container missing --assam-url <value>\nargs: %v", meshArgs)
	} else if got := meshArgs[i+1]; got != wantAssamURL {
		t.Fatalf("ratls-mesh --assam-url = %q, want %q", got, wantAssamURL)
	}
}

// TestChartRatlsMeshAssamMeasurementsFlagsThrough confirms a measurement set
// in `ratls-mesh.assam.measurements` reaches the daemonset's
// --assam-measurements flag — without this the RA-TLS handshake accepts any
// measurement and the H1 defence collapses to "trust the cluster network".
func TestChartRatlsMeshAssamMeasurementsFlagsThrough(t *testing.T) {
	const measurement = "abc1230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff"
	out, err := helmTemplate(t,
		"--set", "ratls-mesh.assam.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
	i := slices.Index(args, "--assam-measurements")
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("ratls-mesh container missing --assam-measurements <value>\nargs: %v", args)
	}
	if got := args[i+1]; got != measurement {
		t.Fatalf("--assam-measurements = %q, want %q", got, measurement)
	}
}

// TestChartCertIssuerHandoffEnabledWiresAssamFlags confirms that turning on
// certIssuer.handoff.enabled in values plumbs the bootstrap flags into the
// cert-issuer container — without them, the in-process handoff bootstrap
// silently doesn't run and /handoff stays disabled.
func TestChartCertIssuerHandoffEnabledWiresAssamFlags(t *testing.T) {
	const measurement = "0011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566ff"
	out, err := helmTemplate(t,
		"--set", "certIssuer.handoff.enabled=true",
		"--set", "assam.measurements[0]="+measurement,
		// certIssuer.measurements is what enables handoff now — the chart
		// auto-injects the cert-issuer/handoff resourceMap entry from it
		// (see TestChartHandoffMeasurementsAutoInjectResourceMap).
		"--set", "certIssuer.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cert-issuer", "cert-issuer").Args

	assertContainerHasArg(t, "cert-issuer", args, "--handoff-assam-url=https://c8s-assam.c8s-system.svc:8080")
	assertContainerHasArg(t, "cert-issuer", args, "--handoff-attestation-service-url=http://c8s-attestation-service.c8s-system.svc:8400")
	// The single --assam-measurements flag is shared between JWKS fetch and
	// handoff bootstrap (both pin Assam's identity).
	assertContainerHasArg(t, "cert-issuer", args, "--assam-measurements="+measurement)
}

// TestChartCertIssuerHandoffDisabledOmitsAssamFlags is the negative: when
// handoff is off (the default), the cert-issuer args MUST NOT include the
// bootstrap flags. A regression here would silently start dialling Assam on
// every restart even when handoff isn't supposed to be enabled.
func TestChartCertIssuerHandoffDisabledOmitsAssamFlags(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cert-issuer", "cert-issuer").Args
	for _, prefix := range []string{
		"--handoff-assam-url=",
		"--handoff-attestation-service-url=",
	} {
		assertContainerNoArgPrefix(t, "cert-issuer", args, prefix)
	}
}

// TestChartHandoffEnabledFailsWithoutCertIssuerMeasurements locks the
// chart-time validation after the resourceMap-from-measurements
// consolidation: enabling certIssuer.handoff.enabled without setting
// certIssuer.measurements would leave the auto-injected entry empty, the
// bootstrap would still run, /handoff would register, and every handoff
// request would 403 — only discovered when scaling up. Fail at helm template.
func TestChartHandoffEnabledFailsWithoutCertIssuerMeasurements(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "certIssuer.handoff.enabled=true",
	)
	if err == nil {
		t.Fatalf("helm template succeeded with handoff enabled but no certIssuer.measurements; output=%s", out)
	}
	if got := parseValidationErrorKind(out); got != "handoff_measurements" {
		t.Fatalf("validation kind = %q, want handoff_measurements; output=%s", got, out)
	}
}

// TestChartAssamWhitelistMaxBodyBytesPlumbsValue confirms that overriding
// assam.whitelistMaxBodyBytes flows into the assam container's
// --whitelist-max-body-bytes flag (typed-decoded from the rendered
// Deployment, no string matching).
func TestChartAssamWhitelistMaxBodyBytesPlumbsValue(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "assam.whitelistMaxBodyBytes=131072",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-assam", "assam").Args
	assertContainerHasArg(t, "assam", args, "--whitelist-max-body-bytes=131072")
}

// parseValidationErrorKind extracts kind=<id> from helm's stderr when the
// chart's `fail` message starts with `VALIDATION_ERROR kind=<id>:`. Returns
// empty string if the marker is absent.
func parseValidationErrorKind(helmOutput string) string {
	re := regexp.MustCompile(`VALIDATION_ERROR kind=([a-z0-9_]+)`)
	m := re.FindStringSubmatch(helmOutput)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

// TestChartHandoffMeasurementsAutoInjectResourceMap proves the consolidation:
// setting certIssuer.measurements is enough — the chart auto-injects the
// cert-issuer/handoff entry into the rendered resource-map.json so the
// active cert-issuer authorises the joining replica without the operator
// repeating the measurement value in two places.
func TestChartHandoffMeasurementsAutoInjectResourceMap(t *testing.T) {
	const measurement = "0011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566ff"
	out, err := helmTemplate(t,
		"--set", "certIssuer.handoff.enabled=true",
		"--set", "assam.measurements[0]="+measurement,
		"--set", "certIssuer.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	rm := decodeCertIssuerResourceMap(t, out)
	got, ok := rm[measurement]
	if !ok {
		t.Fatalf("resource-map.json missing entry for measurement %q; got %#v", measurement, rm)
	}
	if !slices.Contains(got, "cert-issuer/handoff") {
		t.Fatalf("auto-injected resource list = %v, want to contain cert-issuer/handoff", got)
	}
}

// TestChartHandoffOperatorSuppliedHandoffResourceWins proves that an
// operator-supplied resource list including cert-issuer/* (the glob form
// that covers handoff) is preserved as-is — the chart doesn't double-add
// the literal cert-issuer/handoff entry.
func TestChartHandoffOperatorSuppliedHandoffResourceWins(t *testing.T) {
	const measurement = "0011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566ff"
	out, err := helmTemplate(t,
		"--set", "certIssuer.handoff.enabled=true",
		"--set", "assam.measurements[0]="+measurement,
		"--set", "certIssuer.measurements[0]="+measurement,
		"--set-string", "certIssuer.resourceMap."+measurement+"[0]=cert-issuer/*",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	rm := decodeCertIssuerResourceMap(t, out)
	got := rm[measurement]
	if slices.Contains(got, "cert-issuer/handoff") {
		t.Fatalf("auto-injected duplicate cert-issuer/handoff alongside cert-issuer/*; got %v", got)
	}
	if !slices.Contains(got, "cert-issuer/*") {
		t.Fatalf("operator-supplied cert-issuer/* dropped; got %v", got)
	}
}

// decodeCertIssuerResourceMap decodes the resource-map.json embedded in
// the rendered cert-issuer ConfigMap into a typed map. Avoids substring
// matching on the rendered YAML.
func decodeCertIssuerResourceMap(t *testing.T, manifest string) map[string][]string {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "ConfigMap" {
			continue
		}
		var cm corev1.ConfigMap
		if err := sigsyaml.Unmarshal([]byte(doc), &cm); err != nil {
			t.Fatalf("decode ConfigMap: %v\n%s", err, doc)
		}
		raw, ok := cm.Data["resource-map.json"]
		if !ok {
			continue
		}
		var rm map[string][]string
		if err := json.Unmarshal([]byte(raw), &rm); err != nil {
			t.Fatalf("parse resource-map.json: %v\n%s", err, raw)
		}
		return rm
	}
	t.Fatalf("no ConfigMap with resource-map.json found")
	return nil
}

// TestChartCertIssuerJWKSURLIsHTTPSAndPinnedToAssamMeasurement proves cert-issuer's
// JWKS fetch from Assam is RA-TLS, not plaintext HTTP. A regression here
// would let an on-path attacker swap the EAR signing keys cert-issuer trusts,
// which in turn would let them forge EARs and get arbitrary CSRs signed.
func TestChartCertIssuerJWKSURLIsHTTPSAndPinnedToAssamMeasurement(t *testing.T) {
	const measurement = "9988776655443322110099887766554433221100998877665544332211009988776655443322110099887766554433ee"
	out, err := helmTemplate(t,
		"--set", "assam.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cert-issuer", "cert-issuer").Args
	assertContainerHasArg(t, "cert-issuer", args, "--jwks-url=https://c8s-assam.c8s-system.svc:8080/.well-known/jwks.json")
	assertContainerHasArg(t, "cert-issuer", args, "--assam-measurements="+measurement)
	assertContainerNoArgPrefix(t, "cert-issuer", args, "--jwks-url=http://")
}

func assertContainerHasArg(t *testing.T, container string, args []string, want string) {
	t.Helper()
	if !slices.Contains(args, want) {
		t.Fatalf("%s container missing arg %q\nargs: %v", container, want, args)
	}
}

func assertContainerNoArgPrefix(t *testing.T, container string, args []string, prefix string) {
	t.Helper()
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			t.Fatalf("%s container has unexpected arg with prefix %q: %q\nargs: %v", container, prefix, arg, args)
		}
	}
}

func TestChartWebhookRendersSecurityKnobs(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "webhook.certVolume.fsGroup=4242",
		"--set-string", "webhook.certVolume.keyMode=0440",
		"--set-string", "webhook.getCert.renewInterval=3h",
		"--set", "webhook.getCert.runAsUser=0",
		"--set", "webhook.getCert.runAsGroup=0",
		"--set", "webhook.getCert.runAsNonRoot=false",
		"--set", "ratls-mesh.enabled=false",
		"--set", "nri-image-policy.enabled=false",
		"--set", "tee-proxy.enabled=false",
		"--set", "tls-lb.enabled=false",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !renderedManifestHasKind(t, out, "MutatingWebhookConfiguration") {
		t.Fatalf("render missing MutatingWebhookConfiguration\n%s", out)
	}
	args := renderedOperatorArgs(t, out)
	for _, want := range []string{
		"--assam-url=https://c8s-assam.c8s-system.svc:8080",
		"--cert-fs-group=4242",
		"--cert-key-mode=0440",
		"--get-cert-renew-interval=3h",
		"--get-cert-run-as-user=0",
		"--get-cert-run-as-group=0",
		"--get-cert-run-as-non-root=false",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("operator args missing %q\n%v", want, args)
		}
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
		"name: tls-certs",
		"name: public-tls",
		"mountPath: /edge-tls",
		"secretName: tls-lb-public-tls",
		"key: public.crt",
		"path: public.key",
		"name: discovery",
		"name: mesh-ca",
		"name: c8s-cert-issuer-mesh-ca",
		"optional: true",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
	assertRenderedDeploymentPodAnnotations(t, out, "c8s-tls-lb", tlsLBAnnotations("c8s-tls-lb.c8s-system.svc", map[string]string{
		webhook.AnnotationReloadWatchVolume:      "public-tls",
		webhook.AnnotationReloadWatchMountPath:   "/edge-tls",
		webhook.AnnotationReloadWatchPaths:       "/edge-tls/public.crt,/edge-tls/public.key",
		webhook.AnnotationDiscoveryVolume:        "discovery",
		webhook.AnnotationDiscoveryMountPath:     "/discovery",
		webhook.AnnotationDiscoveryOut:           "/discovery/discovery.json",
		webhook.AnnotationDiscoveryCDSCertURL:    "/.well-known/cds-cert.pem",
		webhook.AnnotationDiscoveryPublicTLSMode: "webpki",
		webhook.AnnotationDiscoveryMeshCAURL:     "/.well-known/mesh-ca.pem",
	}))
	deployment := renderedDeployment(t, out, "c8s-tls-lb")
	if got := deployment.Spec.Template.Spec.ShareProcessNamespace; got == nil || !*got {
		t.Fatalf("tls-lb shareProcessNamespace = %v, want true", got)
	}
	if got := deployment.Spec.Template.Spec.InitContainers; len(got) != 0 {
		t.Fatalf("tls-lb should rely on webhook-injected get-cert containers, got %v", got)
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

func TestTLSLBCertProvisioningValuesDriveWebhookAnnotations(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "tls-lb.certProvisioning.renewInterval=30m",
		"--set", "tls-lb.certProvisioning.verbose=true",
		"--set", "tls-lb.nginx.runAsUser=201",
		"--set", "tls-lb.nginx.runAsGroup=202",
		"--set", "tls-lb.nginx.runAsNonRoot=false",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertRenderedDeploymentPodAnnotations(t, out, "c8s-tls-lb", tlsLBAnnotations("c8s-tls-lb.c8s-system.svc", map[string]string{
		webhook.AnnotationRenewInterval:       "30m",
		webhook.AnnotationGetCertRunAsUser:    "201",
		webhook.AnnotationGetCertRunAsGroup:   "202",
		webhook.AnnotationGetCertRunAsNonRoot: "false",
		webhook.AnnotationGetCertVerbose:      "true",
	}))
	deployment := renderedDeployment(t, out, "c8s-tls-lb")
	if got := deployment.Spec.Template.Spec.SecurityContext.FSGroup; got == nil || *got != 202 {
		t.Fatalf("tls-lb fsGroup = %v, want 202", got)
	}
	nginx := renderedDeploymentContainer(t, out, "c8s-tls-lb", "nginx")
	if got := nginx.SecurityContext.RunAsUser; got == nil || *got != 201 {
		t.Fatalf("nginx runAsUser = %v, want 201", got)
	}
	if got := nginx.SecurityContext.RunAsGroup; got == nil || *got != 202 {
		t.Fatalf("nginx runAsGroup = %v, want 202", got)
	}
	if got := nginx.SecurityContext.RunAsNonRoot; got == nil || *got {
		t.Fatalf("nginx runAsNonRoot = %v, want false", got)
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
	cm := renderedConfigMap(t, manifest, "tls-lb-nginx")
	conf, ok := cm.Data["nginx.conf"]
	if !ok || conf == "" {
		t.Fatalf("tls-lb nginx ConfigMap missing nginx.conf\n%s", manifest)
	}
	return conf
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
		"optional: true",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
}

func TestTLSLBMeshCAOptionalCanBeRequired(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "discovery.enabled=true",
		"--set", "meshCA.optional=false",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !strings.Contains(out, "optional: false") {
		t.Fatalf("render missing %q\n%s", "optional: false", out)
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
		"alias /mesh-ca/ca.pem;",
		"- name: mesh-ca",
		"name: tls-lb-cert-issuer-mesh-ca",
		"optional: true",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
	assertRenderedDeploymentPodAnnotations(t, out, "tls-lb", map[string]string{
		webhook.AnnotationDiscoveryMeshCAURL: "/.well-known/mesh-ca.pem",
	})
}

func TestTLSLBDiscoveryReportsCDSModeWithoutPublicTLSSecret(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "discovery.enabled=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertRenderedDeploymentPodAnnotations(t, out, "tls-lb", map[string]string{
		webhook.AnnotationDiscoveryPublicTLSMode: "cds",
	})
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
	out, err := helmTemplate(t)
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
		"resources: [mutatingwebhookconfigurations]",
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
	} {
		if strings.Contains(out, unexpected) {
			t.Fatalf("render contained broad RBAC rule %q\n%s", unexpected, out)
		}
	}
}

func TestChartWebhookAddsCABundleRBAC(t *testing.T) {
	out, err := helmTemplate(t)
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

func TestChartRollsAttestationServiceOnConfigChange(t *testing.T) {
	defaultOut, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template default config: %v\n%s", err, defaultOut)
	}
	defaultChecksum := renderedValue(t, defaultOut, "checksum/config")
	if defaultChecksum == "" {
		t.Fatalf("default checksum/config is empty\n%s", defaultOut)
	}

	changedOut, err := helmTemplate(t,
		"--set", "attestationService.platforms[0]=az-snp",
	)
	if err != nil {
		t.Fatalf("helm template changed config: %v\n%s", err, changedOut)
	}
	changedChecksum := renderedValue(t, changedOut, "checksum/config")
	if changedChecksum == defaultChecksum {
		t.Fatalf("checksum/config did not change after changing platforms: %s", defaultChecksum)
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

// docMeta is the minimum we decode from each YAML doc to dispatch by kind+name.
type docMeta struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

// splitManifestDocs returns each non-empty doc in a multi-doc YAML stream as
// its own raw YAML chunk. helm template emits empty `---\n` separators that
// we silently drop.
func splitManifestDocs(manifest string) []string {
	var out []string
	for _, doc := range strings.Split(manifest, "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		out = append(out, doc)
	}
	return out
}

// findDoc returns the first YAML doc matching kind (and name when non-empty),
// decoded into out via sigs.k8s.io/yaml. Returns false if no match.
func findDoc(t *testing.T, manifest, kind, name string, out any) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil {
			continue
		}
		if meta.Kind != kind {
			continue
		}
		if name != "" && meta.Metadata.Name != name {
			continue
		}
		if err := sigsyaml.Unmarshal([]byte(doc), out); err != nil {
			t.Fatalf("decode %s/%s: %v\n%s", kind, name, err, doc)
		}
		return true
	}
	return false
}

func renderedManifestHasKind(t *testing.T, manifest, kind string) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err == nil && meta.Kind == kind {
			return true
		}
	}
	return false
}

func renderedManifestHasNamedKind(t *testing.T, manifest, kind, name string) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err == nil && meta.Kind == kind && meta.Metadata.Name == name {
			return true
		}
	}
	return false
}

func renderedMutatingWebhook(t *testing.T, manifest, name string) admissionregv1.MutatingWebhook {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "MutatingWebhookConfiguration" {
			continue
		}
		var cfg admissionregv1.MutatingWebhookConfiguration
		if err := sigsyaml.Unmarshal([]byte(doc), &cfg); err != nil {
			t.Fatalf("decode MutatingWebhookConfiguration: %v\n%s", err, doc)
		}
		for _, hook := range cfg.Webhooks {
			if hook.Name == name {
				return hook
			}
		}
	}
	t.Fatalf("rendered manifest missing MutatingWebhookConfiguration webhook %q\n%s", name, manifest)
	return admissionregv1.MutatingWebhook{}
}

func selectorExpressionValues(selector *metav1.LabelSelector, key string, op metav1.LabelSelectorOperator) []string {
	if selector == nil {
		return nil
	}
	for _, expression := range selector.MatchExpressions {
		if expression.Key == key && expression.Operator == op {
			return expression.Values
		}
	}
	return nil
}

func renderedOperatorArgs(t *testing.T, manifest string) []string {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "Deployment" {
			continue
		}
		var dep appsv1.Deployment
		if err := sigsyaml.Unmarshal([]byte(doc), &dep); err != nil {
			t.Fatalf("decode Deployment %q: %v\n%s", meta.Metadata.Name, err, doc)
		}
		for _, container := range dep.Spec.Template.Spec.Containers {
			if container.Name == "operator" {
				return container.Args
			}
		}
	}
	t.Fatalf("rendered manifest missing operator container\n%s", manifest)
	return nil
}

func renderedDeployment(t *testing.T, manifest, name string) appsv1.Deployment {
	t.Helper()
	var dep appsv1.Deployment
	if !findDoc(t, manifest, "Deployment", name, &dep) {
		t.Fatalf("rendered manifest missing Deployment %q\n%s", name, manifest)
	}
	return dep
}

func renderedDaemonSet(t *testing.T, manifest, name string) appsv1.DaemonSet {
	t.Helper()
	var ds appsv1.DaemonSet
	if !findDoc(t, manifest, "DaemonSet", name, &ds) {
		t.Fatalf("rendered manifest missing DaemonSet %q\n%s", name, manifest)
	}
	return ds
}

func renderedConfigMap(t *testing.T, manifest, name string) corev1.ConfigMap {
	t.Helper()
	var cm corev1.ConfigMap
	if !findDoc(t, manifest, "ConfigMap", name, &cm) {
		t.Fatalf("rendered manifest missing ConfigMap %q\n%s", name, manifest)
	}
	return cm
}

func renderedDaemonSetContainer(t *testing.T, manifest, daemonSetName, containerName string) corev1.Container {
	t.Helper()
	for _, container := range renderedDaemonSet(t, manifest, daemonSetName).Spec.Template.Spec.Containers {
		if container.Name == containerName {
			return container
		}
	}
	t.Fatalf("rendered DaemonSet %q missing container %q\n%s", daemonSetName, containerName, manifest)
	return corev1.Container{}
}

func renderedDeploymentInitContainers(t *testing.T, manifest, name string) []corev1.Container {
	t.Helper()
	return renderedDeployment(t, manifest, name).Spec.Template.Spec.InitContainers
}

func renderedDeploymentContainer(t *testing.T, manifest, deploymentName, containerName string) corev1.Container {
	t.Helper()
	for _, container := range renderedDeployment(t, manifest, deploymentName).Spec.Template.Spec.Containers {
		if container.Name == containerName {
			return container
		}
	}
	t.Fatalf("rendered Deployment %q missing container %q\n%s", deploymentName, containerName, manifest)
	return corev1.Container{}
}

func assertRenderedDeploymentPodLabels(t *testing.T, manifest, name string, want map[string]string) {
	t.Helper()
	labels := renderedDeployment(t, manifest, name).Spec.Template.Labels
	for key, wantValue := range want {
		if got := labels[key]; got != wantValue {
			t.Fatalf("Deployment %s label %s = %q, want %q\nlabels: %v", name, key, got, wantValue, labels)
		}
	}
}

func assertRenderedDeploymentPodAnnotations(t *testing.T, manifest, name string, want map[string]string) {
	t.Helper()
	annotations := renderedDeployment(t, manifest, name).Spec.Template.Annotations
	for key, wantValue := range want {
		if got := annotations[key]; got != wantValue {
			t.Fatalf("Deployment %s annotation %s = %q, want %q\nannotations: %v", name, key, got, wantValue, annotations)
		}
	}
}

func tlsLBAnnotations(workload string, overrides map[string]string) map[string]string {
	annotations := map[string]string{
		webhook.AnnotationWorkload:            workload,
		webhook.AnnotationCertVolume:          "tls-certs",
		webhook.AnnotationCertDir:             "/tls",
		webhook.AnnotationCertFile:            "cert.pem",
		webhook.AnnotationKeyFile:             "key.pem",
		webhook.AnnotationRenewInterval:       "1h",
		webhook.AnnotationReloadNginx:         "true",
		webhook.AnnotationGetCertRunAsUser:    "101",
		webhook.AnnotationGetCertRunAsGroup:   "101",
		webhook.AnnotationGetCertRunAsNonRoot: "true",
	}
	for key, value := range overrides {
		annotations[key] = value
	}
	return annotations
}

func helmTemplateTLSLB(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	base := []string{
		"template", "tls-lb", "c8s/charts/tls-lb",
		"--namespace", "c8s-system",
		"--set", "nginx.image.tag=dev",
	}
	cmd := exec.Command("helm", append(base, args...)...)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	return string(out), err
}
