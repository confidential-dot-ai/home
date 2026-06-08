package helmchart

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	pkgwhitelist "github.com/lunal-dev/c8s/pkg/whitelist"
	"gopkg.in/yaml.v3"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

// helmFailMessage extracts the user-visible message from a `helm template`
// failure so tests can parse a typed value out of it instead of grepping
// the whole stderr blob.
var helmFailRE = regexp.MustCompile(`execution error at \([^)]+\): (.+?)\n`)

func helmFailMessage(t *testing.T, out string) string {
	t.Helper()
	m := helmFailRE.FindStringSubmatch(out)
	if len(m) < 2 {
		t.Fatalf("no helm fail message in output:\n%s", out)
	}
	return m[1]
}

func assertHelmFailMessage(t *testing.T, out, want string) {
	t.Helper()
	if got := helmFailMessage(t, out); got != want {
		t.Fatalf("helm fail message = %q, want %q\n%s", got, want, out)
	}
}

// preStopBoundFailure captures the structured shape of the daemonset
// preStop fail-checks so tests can assert on typed fields instead of
// substring-matching the rendered error.
type preStopBoundFailure struct {
	Cmp   string // "le" for "≤", "ge" for "≥"
	Bound int
	Got   int
}

var preStopBoundRE = regexp.MustCompile(`iptablesCleanup\.preStopSleepSeconds must be ([≤≥]) (-?\d+).*got (-?\d+)`)

func parsePreStopBoundFailure(t *testing.T, out string) preStopBoundFailure {
	t.Helper()
	msg := helmFailMessage(t, out)
	m := preStopBoundRE.FindStringSubmatch(msg)
	if len(m) != 4 {
		t.Fatalf("preStop bound regex did not match %q", msg)
	}
	cmp := "ge"
	if m[1] == "≤" {
		cmp = "le"
	}
	bound, err := strconv.Atoi(m[2])
	if err != nil {
		t.Fatalf("bound %q is not an int: %v", m[2], err)
	}
	got, err := strconv.Atoi(m[3])
	if err != nil {
		t.Fatalf("got %q is not an int: %v", m[3], err)
	}
	return preStopBoundFailure{Cmp: cmp, Bound: bound, Got: got}
}

// gracePeriodBudgetFailure: the durations the chart says don't leave a
// preStop window.
type gracePeriodBudgetFailure struct {
	GracePeriod string
	Drain       string
}

var gracePeriodBudgetRE = regexp.MustCompile(`terminationGracePeriod \(([^)]+)\) must exceed drainTimeout \(([^)]+)\)`)

func parseGracePeriodBudgetFailure(t *testing.T, out string) gracePeriodBudgetFailure {
	t.Helper()
	msg := helmFailMessage(t, out)
	m := gracePeriodBudgetRE.FindStringSubmatch(msg)
	if len(m) != 3 {
		t.Fatalf("grace-period budget regex did not match %q", msg)
	}
	return gracePeriodBudgetFailure{GracePeriod: m[1], Drain: m[2]}
}

// durationFormatFailure classifies the two distinct rejection paths in the
// duration helper so a future refactor that conflates them flags here.
type durationFormatFailure struct {
	Value  string
	Reason string // "no-unit" | "non-integer"
}

var (
	durationNoUnitRE     = regexp.MustCompile(`duration "([^"]+)" must end with h, m, or s`)
	durationNonIntegerRE = regexp.MustCompile(`duration "([^"]+)" must be a positive integer`)
)

func parseDurationFormatFailure(t *testing.T, out string) durationFormatFailure {
	t.Helper()
	msg := helmFailMessage(t, out)
	if m := durationNoUnitRE.FindStringSubmatch(msg); len(m) == 2 {
		return durationFormatFailure{Value: m[1], Reason: "no-unit"}
	}
	if m := durationNonIntegerRE.FindStringSubmatch(msg); len(m) == 2 {
		return durationFormatFailure{Value: m[1], Reason: "non-integer"}
	}
	t.Fatalf("duration-format regex did not match %q", msg)
	return durationFormatFailure{}
}

// containerArgs returns the args of the named container, searching main and
// init containers. Fails the test if no such container exists.
func containerArgs(t *testing.T, ds *appsv1.DaemonSet, name string) []string {
	t.Helper()
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == name {
			return c.Args
		}
	}
	for _, c := range ds.Spec.Template.Spec.InitContainers {
		if c.Name == name {
			return c.Args
		}
	}
	t.Fatalf("container %q not found in DaemonSet", name)
	return nil
}

// containerArgValue returns (value, true) for `--flag value`, or ("", false)
// if the flag isn't present.
func containerArgValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func TestChartDefaultRendersReplacementStack(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !renderedManifestHasKind(t, out, "MutatingWebhookConfiguration") {
		t.Fatalf("default chart missing MutatingWebhookConfiguration\n%s", out)
	}
	for _, want := range []string{
		"app.kubernetes.io/component: cds",
		"app.kubernetes.io/name: ratls-mesh",
		"app.kubernetes.io/name: nri-image-policy",
		"app.kubernetes.io/name: tee-proxy",
		"port: 443\n      targetPort: 443\n      protocol: TCP\n      name: https",
		"app.kubernetes.io/name: tls-lb",
		"server_name \"c8s-tls-lb.c8s-system.svc\";",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("default chart missing %q\n%s", want, out)
		}
	}
	initCert := tlsLBGetCertContainer(t, out, "c8s-init-cert")
	assertContainerArgs(t, initCert,
		"get-cert",
		"--cds-url=https://c8s-cds.c8s-system.svc:8443",
		"--attestation-api-url=http://c8s-attestation-api.c8s-system.svc:8400",
		"--san=c8s-tls-lb.c8s-system.svc",
		"--out=/tls/cert.pem",
		"--key-out=/tls/key.pem",
	)
	renewCert := tlsLBGetCertContainer(t, out, "c8s-renew-cert")
	assertContainerArgs(t, renewCert,
		"--key=/tls/key.pem",
		"--out=/tls/cert.pem",
		"--renew-interval=1h",
		"--reload-nginx=true",
		"--continue-on-initial-error",
	)
	if renewCert.RestartPolicy == nil || *renewCert.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("c8s-renew-cert restartPolicy = %v, want Always", renewCert.RestartPolicy)
	}
	if got := initCert.SecurityContext.RunAsUser; got == nil || *got != 101 {
		t.Fatalf("c8s-init-cert runAsUser = %v, want 101", got)
	}
	args := renderedOperatorArgs(t, out)
	for _, want := range []string{
		"--get-cert-image=ghcr.io/lunal-dev/c8s-operator:dev",
		"--cds-url=https://c8s-cds.c8s-system.svc:8443",
		"--get-cert-renew-interval=6h",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("operator args missing %q\n%v", want, args)
		}
	}
}

func TestChartRendersRATLSHostRoutingDefaults(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)

	sync, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "iptables-sync")
	if !ok {
		t.Fatalf("iptables-sync init container missing; have %v", containerNames(ds.Spec.Template.Spec.InitContainers))
	}
	for _, pair := range [][2]string{
		{"--node-ip", "$(NODE_IP)"},
		{"--resync-period", "30s"},
		{"--watchdog-period", "2s"},
		{"--ipset-maxelem", "262144"},
		{"--ready-file", "/tmp/ratls-iptables-ready"},
		{"--iptables-metrics-file", "/tmp/ratls-iptables-metrics.json"},
		{"--exclude-source-namespaces", "kube-system,c8s-system"},
	} {
		if !argvContainsFlagValue(sync.Command, pair[0], pair[1]) {
			t.Errorf("iptables-sync command missing %s %s; command=%q", pair[0], pair[1], sync.Command)
		}
	}
	if slices.Contains(sync.Command, "--pod-cidrs") {
		t.Errorf("iptables-sync must not require static --pod-cidrs; command=%q", sync.Command)
	}

	mesh, ok := findContainer(ds.Spec.Template.Spec.Containers, "ratls-mesh")
	if !ok {
		t.Fatalf("ratls-mesh container missing; have %v", containerNames(ds.Spec.Template.Spec.Containers))
	}
	if !argvContainsFlagValue(mesh.Args, "--iptables-metrics-file", "/tmp/ratls-iptables-metrics.json") {
		t.Errorf("ratls-mesh args missing the shared iptables metrics file flag; args=%q", mesh.Args)
	}
	// --platform is the RA-TLS TEE type; an empty value (the old missing
	// default) trips the binary's "--platform is required" check, so the mesh
	// pod never starts. Pin the non-empty default.
	if !argvContainsFlagValue(mesh.Args, "--platform", "sev-snp") {
		t.Errorf("ratls-mesh args must default --platform to sev-snp; args=%q", mesh.Args)
	}
	if hp, ok := containerHostPort(mesh, "inbound"); !ok || hp != 15006 {
		t.Errorf("ratls-mesh inbound port must publish hostPort 15006; got %d (found=%v)", hp, ok)
	}
	for _, banned := range []int32{15001, 15021} {
		if containers := containersExposingHostPort(ds, banned); len(containers) > 0 {
			t.Errorf("hostPort %d must not be exposed; exposed by %v", banned, containers)
		}
	}

	for _, c := range allContainers(ds) {
		for name := range c.Resources.Requests {
			if strings.Contains(string(name), "lunal.dev/tpm") {
				t.Errorf("container %q requests local TPM resource %q by default", c.Name, name)
			}
		}
		for name := range c.Resources.Limits {
			if strings.Contains(string(name), "lunal.dev/tpm") {
				t.Errorf("container %q limits local TPM resource %q by default", c.Name, name)
			}
		}
	}

	if kinds := renderedKinds(t, out); kinds["NetworkPolicy"] > 0 {
		t.Errorf("ratls host routing must not render NetworkPolicy for hostNetwork pods; got %d", kinds["NetworkPolicy"])
	}
}

// argvContainsFlagValue reports whether argv has `flag` immediately followed
// by `value`.
func argvContainsFlagValue(argv []string, flag, value string) bool {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) && argv[i+1] == value {
			return true
		}
	}
	return false
}

func containerHostPort(c corev1.Container, portName string) (int32, bool) {
	for _, p := range c.Ports {
		if p.Name == portName {
			return p.HostPort, true
		}
	}
	return 0, false
}

func containersExposingHostPort(ds *appsv1.DaemonSet, port int32) []string {
	var hits []string
	for _, c := range allContainers(ds) {
		for _, p := range c.Ports {
			if p.HostPort == port {
				hits = append(hits, c.Name)
				break
			}
		}
	}
	return hits
}

func allContainers(ds *appsv1.DaemonSet) []corev1.Container {
	out := make([]corev1.Container, 0, len(ds.Spec.Template.Spec.InitContainers)+len(ds.Spec.Template.Spec.Containers))
	out = append(out, ds.Spec.Template.Spec.InitContainers...)
	out = append(out, ds.Spec.Template.Spec.Containers...)
	return out
}

// iterateManifests calls fn for each non-nil YAML document in helmOut,
// using yaml.NewDecoder so a "---" inside a block scalar can't fool the
// split. The document is re-marshalled to YAML bytes so fn can pass it
// to sigsyaml.Unmarshal for typed decoding. fn returning true stops
// iteration.
func iterateManifests(t *testing.T, helmOut string, fn func(doc []byte) bool) {
	t.Helper()
	decoder := yaml.NewDecoder(strings.NewReader(helmOut))
	for {
		var raw any
		err := decoder.Decode(&raw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			t.Fatalf("decode helm output: %v", err)
		}
		if raw == nil {
			continue
		}
		b, err := yaml.Marshal(raw)
		if err != nil {
			t.Fatalf("re-marshal manifest: %v", err)
		}
		if fn(b) {
			return
		}
	}
}

// renderedKinds counts each manifest kind across a helm template output.
func renderedKinds(t *testing.T, helmOut string) map[string]int {
	t.Helper()
	out := map[string]int{}
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var head struct {
			Kind string `json:"kind"`
		}
		if err := sigsyaml.Unmarshal(doc, &head); err == nil && head.Kind != "" {
			out[head.Kind]++
		}
		return false
	})
	return out
}

// Two silent-break risks in a daemonset.yaml refactor:
//  1. iptables-{cleanup,sync} must stay native sidecars (restartPolicy:
//     Always); dropping that demotes them to one-shot init containers and
//     the cleanup preStop never fires, leaking rules across restarts.
//  2. iptables-cleanup must be the FIRST initContainer; native sidecars
//     terminate in reverse-init order, so a swap with iptables-sync stops
//     cleanup before sync loses its chains.
func TestChartRATLSNativeSidecarShape(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)

	// hostNetwork + dnsPolicy are part of the routing contract: iptables-sync
	// must run in the host netns to see pre-DNAT pod traffic, and the
	// matching dnsPolicy keeps in-cluster service DNS working from that
	// netns. A refactor that templated either to a value and accidentally
	// toggled it via overlay defaults would still match the substring check
	// in TestChartRendersRATLSHostRoutingDefaults; assert against the typed
	// PodSpec so the contract is unambiguous.
	if !ds.Spec.Template.Spec.HostNetwork {
		t.Errorf("ratls-mesh DaemonSet must set hostNetwork: true; got %v", ds.Spec.Template.Spec.HostNetwork)
	}
	if got := ds.Spec.Template.Spec.DNSPolicy; got != corev1.DNSClusterFirstWithHostNet {
		t.Errorf("ratls-mesh DaemonSet must set dnsPolicy: ClusterFirstWithHostNet (paired with hostNetwork); got %q", got)
	}

	init := ds.Spec.Template.Spec.InitContainers
	if len(init) < 2 {
		t.Fatalf("expected at least 2 initContainers (iptables-cleanup, iptables-sync); got %d", len(init))
	}
	if init[0].Name != "iptables-cleanup" {
		t.Fatalf("first init container must be iptables-cleanup so its preStop fires last on shutdown; got %q", init[0].Name)
	}

	for _, name := range []string{"iptables-cleanup", "iptables-sync"} {
		c, ok := findContainer(init, name)
		if !ok {
			t.Fatalf("init container %q not found in %v", name, containerNames(init))
		}
		if c.RestartPolicy == nil || *c.RestartPolicy != corev1.ContainerRestartPolicyAlways {
			t.Errorf("init container %q must declare restartPolicy: Always (native sidecar contract); got %v", name, c.RestartPolicy)
		}
		if !hasCapability(c, "NET_ADMIN") {
			t.Errorf("init container %q must hold NET_ADMIN to manage iptables/ipset; caps=%+v", name, c.SecurityContext)
		}
		// NET_RAW is required for the xt_set match's socket to ip_set on the
		// nf_tables-compat path; without it `iptables -m set` fails with
		// "Can't open socket to ipset" despite NET_ADMIN.
		if !hasCapability(c, "NET_RAW") {
			t.Errorf("init container %q must hold NET_RAW for the iptables xt_set match; caps=%+v", name, c.SecurityContext)
		}
		// The sidecars run as root for iptables/ipset but are bounded by
		// allowPrivilegeEscalation: false and the runtime-default seccomp
		// profile. Both are easy to omit silently in a refactor and turn the
		// containers into a full-root attack surface; pin them.
		sc := c.SecurityContext
		if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			t.Errorf("init container %q must set allowPrivilegeEscalation: false; got %+v", name, sc)
		}
		if sc == nil || sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			t.Errorf("init container %q must set seccompProfile.type: RuntimeDefault; got %+v", name, sc.SeccompProfile)
		}
	}

	sync, ok := findContainer(init, "iptables-sync")
	if !ok {
		t.Fatalf("iptables-sync init container missing; initContainers=%v", containerNames(init))
	}
	if sync.StartupProbe == nil || sync.StartupProbe.Exec == nil {
		t.Fatalf("iptables-sync must expose a startupProbe so the main proxy waits for the ready file; got %+v", sync.StartupProbe)
	}
	if got := strings.Join(sync.StartupProbe.Exec.Command, " "); !strings.Contains(got, "/tmp/ratls-iptables-ready") {
		t.Errorf("iptables-sync startupProbe should check /tmp/ratls-iptables-ready; got %q", got)
	}

	// The entire teardown contract hinges on the iptables-cleanup preStop
	// hook firing last in the reverse-init-order stop sequence. A future
	// refactor that drops the lifecycle stanza or renames the subcommand
	// would silently leak iptables rules and ipsets across pod restarts —
	// catch that here instead of in production.
	cleanup := init[0]
	if cleanup.Lifecycle == nil || cleanup.Lifecycle.PreStop == nil || cleanup.Lifecycle.PreStop.Exec == nil {
		t.Fatalf("iptables-cleanup must declare a preStop exec hook; got %+v", cleanup.Lifecycle)
	}
	preStop := strings.Join(cleanup.Lifecycle.PreStop.Exec.Command, " ")
	if !strings.Contains(preStop, "ratls-mesh iptables-cleanup") {
		t.Errorf("iptables-cleanup preStop must invoke 'ratls-mesh iptables-cleanup'; got %q", preStop)
	}
}

// TestChartRATLSKubeVersionPinned guards the lower bound that makes the
// native-sidecar contract safe by default: Kubernetes 1.28 exposed
// restartPolicy: Always on initContainers behind the SidecarContainers
// feature gate, while 1.29 enables that gate by default. If the gate is off,
// iptables-cleanup is invalid as a native sidecar, its preStop cannot run,
// and the host can leak managed chains/ipsets across pod restarts. Helm
// rejects older clusters via the kubeVersion constraint; after hoisting the
// ratls-mesh subchart this constraint lives on the parent c8s chart, so keep
// it pinned there against an accidental relaxation.
func TestChartRATLSKubeVersionPinned(t *testing.T) {
	const path = "c8s/Chart.yaml"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var chart struct {
		KubeVersion string `json:"kubeVersion"`
	}
	if err := sigsyaml.Unmarshal(raw, &chart); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	const want = ">=1.29.0-0"
	if chart.KubeVersion != want {
		t.Fatalf("c8s Chart.yaml kubeVersion = %q; want %q (native sidecars require SidecarContainers default-on behavior from k8s 1.29+; relaxing this leaks iptables/ipset state across pod restarts on older clusters)", chart.KubeVersion, want)
	}
}

func findRATLSMeshDaemonSet(t *testing.T, helmOut string) *appsv1.DaemonSet {
	t.Helper()
	var ds *appsv1.DaemonSet
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var head struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := sigsyaml.Unmarshal(doc, &head); err != nil ||
			head.Kind != "DaemonSet" ||
			!strings.Contains(head.Metadata.Name, "ratls-mesh") {
			return false
		}
		var decoded appsv1.DaemonSet
		if err := sigsyaml.Unmarshal(doc, &decoded); err != nil {
			t.Fatalf("decode ratls-mesh DaemonSet: %v\n%s", err, doc)
		}
		ds = &decoded
		return true
	})
	if ds == nil {
		t.Fatalf("ratls-mesh DaemonSet not found in helm template output\n%s", helmOut)
	}
	return ds
}

// findContainer mirrors findEnv in internal/webhook/pod_mutator_test.go:
// return (value, ok) so callers decide how to report the miss.
func findContainer(containers []corev1.Container, name string) (corev1.Container, bool) {
	for _, c := range containers {
		if c.Name == name {
			return c, true
		}
	}
	return corev1.Container{}, false
}

func containerNames(containers []corev1.Container) []string {
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		names = append(names, c.Name)
	}
	return names
}

// tlsLBGetCertContainer returns the named tls-lb get-cert init container
// (c8s-init-cert or c8s-renew-cert), failing if absent.
func tlsLBGetCertContainer(t *testing.T, manifest, name string) corev1.Container {
	t.Helper()
	init := renderedDeploymentInitContainers(t, manifest, "c8s-tls-lb")
	c, ok := findContainer(init, name)
	if !ok {
		t.Fatalf("tls-lb init container %q missing; have %v", name, containerNames(init))
	}
	return c
}

// assertContainerArgs fails unless every wanted arg is present on the container.
func assertContainerArgs(t *testing.T, c corev1.Container, want ...string) {
	t.Helper()
	for _, w := range want {
		assertContainerHasArg(t, c.Name, c.Args, w)
	}
}

// assertContainerArgsAbsent fails if any listed exact arg is present on the
// container (assertContainerNoArgPrefix covers the prefix case).
func assertContainerArgsAbsent(t *testing.T, c corev1.Container, absent ...string) {
	t.Helper()
	for _, a := range absent {
		if slices.Contains(c.Args, a) {
			t.Fatalf("%s container should not contain arg %q\nargs: %v", c.Name, a, c.Args)
		}
	}
}

func hasCapability(c corev1.Container, want corev1.Capability) bool {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return false
	}
	for _, got := range c.SecurityContext.Capabilities.Add {
		if got == want {
			return true
		}
	}
	return false
}

// PrometheusRule's types live in a separate go module (prometheus-operator)
// the chart does not otherwise depend on; decoding into a local typed shim
// is enough to assert the rule contract without pulling that dep in just
// for tests.
type prometheusRule struct {
	Spec struct {
		Groups []struct {
			Name  string `json:"name"`
			Rules []struct {
				Alert       string            `json:"alert"`
				Expr        string            `json:"expr"`
				For         string            `json:"for"`
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
			} `json:"rules"`
		} `json:"groups"`
	} `json:"spec"`
}

func findRATLSMeshPrometheusRule(t *testing.T, helmOut string) prometheusRule {
	t.Helper()
	var found prometheusRule
	var ok bool
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var head struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := sigsyaml.Unmarshal(doc, &head); err != nil ||
			head.Kind != "PrometheusRule" ||
			!strings.Contains(head.Metadata.Name, "ratls-mesh") {
			return false
		}
		var rule prometheusRule
		if err := sigsyaml.Unmarshal(doc, &rule); err != nil {
			t.Fatalf("decode ratls-mesh PrometheusRule: %v\n%s", err, doc)
		}
		found = rule
		ok = true
		return true
	})
	if !ok {
		t.Fatalf("ratls-mesh PrometheusRule not found in helm template output\n%s", helmOut)
	}
	return found
}

// TestChartRATLSRoutingAlerts pins routing-path alerts that fire on signals
// downstream consumers should not have to reconstruct by hand: a wedged
// iptables-sync sidecar (its in-process counters stop publishing), unavailable
// local CIDR route cross-checking, and direct dials to :15001 outside the
// REDIRECT path. Drop any alert and a refactor of
// prometheus-rules.yaml could silently lose the corresponding production
// signal.
func TestChartRATLSRoutingAlerts(t *testing.T) {
	out, err := helmTemplate(t, "--set", "ratlsMesh.prometheusRules.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	rule := findRATLSMeshPrometheusRule(t, out)

	want := map[string]string{
		"RATLSMeshIptablesSyncWedged":             "ratls_mesh_iptables_metrics_file_updated_at_seconds",
		"RATLSMeshLocalCIDRRouteCheckUnavailable": "ratls_mesh_resolver_local_cidrs == 0",
		"RATLSMeshOutboundDirectDial":             `reason="host_addr"`,
		"RATLSMeshIptablesIPSetOverflow":          "ratls_mesh_iptables_ipset_overflow_total",
		"RATLSMeshJumpPositionViolations":         "ratls_mesh_iptables_jump_position_violations_total",
	}
	got := make(map[string]string)
	for _, g := range rule.Spec.Groups {
		for _, r := range g.Rules {
			if _, ok := want[r.Alert]; ok {
				got[r.Alert] = r.Expr
			}
		}
	}
	for alert, exprSubstr := range want {
		expr, ok := got[alert]
		if !ok {
			t.Errorf("alert %q missing from rendered PrometheusRule", alert)
			continue
		}
		if !strings.Contains(expr, exprSubstr) {
			t.Errorf("alert %q expr does not reference %q: got %q", alert, exprSubstr, expr)
		}
	}
}

// terminationGracePeriod minus drainTimeout (both Go-style durations) is the
// budget left for the iptables-cleanup preStop sleep. A higher value is
// silently truncated at runtime by SIGKILL, leaking managed chains/ipsets
// across the pod restart. The chart fails the install instead of letting
// that misconfig ship. The bound is derived, not hardcoded, so changes to
// either underlying value reshape it automatically.
func TestChartRejectsExcessivePreStopSleep(t *testing.T) {
	out, err := helmTemplate(t, "--set", "ratlsMesh.iptablesCleanup.preStopSleepSeconds=30")
	if err == nil {
		t.Fatalf("helm template succeeded, want preStopSleepSeconds upper-bound failure\n%s", out)
	}
	failure := parsePreStopBoundFailure(t, out)
	if want := (preStopBoundFailure{Cmp: "le", Bound: 15, Got: 30}); failure != want {
		t.Fatalf("preStop upper-bound failure = %+v, want %+v", failure, want)
	}
}

func TestChartRejectsNegativePreStopSleep(t *testing.T) {
	out, err := helmTemplate(t, "--set", "ratlsMesh.iptablesCleanup.preStopSleepSeconds=-1")
	if err == nil {
		t.Fatalf("helm template succeeded, want preStopSleepSeconds lower-bound failure\n%s", out)
	}
	failure := parsePreStopBoundFailure(t, out)
	if want := (preStopBoundFailure{Cmp: "ge", Bound: 0, Got: -1}); failure != want {
		t.Fatalf("preStop lower-bound failure = %+v, want %+v", failure, want)
	}
}

func TestChartAcceptsPreStopSleepAtBoundary(t *testing.T) {
	out, err := helmTemplate(t, "--set", "ratlsMesh.iptablesCleanup.preStopSleepSeconds=15")
	if err != nil {
		t.Fatalf("helm template at boundary should succeed: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	cleanup, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "iptables-cleanup")
	if !ok {
		t.Fatalf("iptables-cleanup init container missing")
	}
	if cleanup.Lifecycle == nil || cleanup.Lifecycle.PreStop == nil || cleanup.Lifecycle.PreStop.Exec == nil {
		t.Fatalf("iptables-cleanup preStop exec hook missing: %+v", cleanup.Lifecycle)
	}
	// The preStop is `/bin/sh -c "<script>"` and the script is the last
	// element; assert the rendered sleep value matches the boundary.
	script := cleanup.Lifecycle.PreStop.Exec.Command[len(cleanup.Lifecycle.PreStop.Exec.Command)-1]
	if !regexp.MustCompile(`(?m)^sleep 15$`).MatchString(script) {
		t.Fatalf("preStop script did not render `sleep 15` at the boundary:\n%s", script)
	}
}

// Tuning terminationGracePeriod or drainTimeout must reshape the preStop
// bound automatically — otherwise the bound goes stale silently once an
// operator changes either knob. Exercising mixed unit forms (h, m, s) also
// pins that the durationSeconds helper handles each correctly.
func TestChartPreStopBoundFollowsGracePeriodAndDrain(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "ratlsMesh.terminationGracePeriod=2m",
		"--set-string", "ratlsMesh.drainTimeout=60s",
		"--set", "ratlsMesh.iptablesCleanup.preStopSleepSeconds=45",
	)
	if err != nil {
		t.Fatalf("helm template at (tgp=2m, drain=60s, sleep=45) should succeed: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	if ds.Spec.Template.Spec.TerminationGracePeriodSeconds == nil {
		t.Fatalf("DaemonSet.terminationGracePeriodSeconds is nil")
	}
	if got := *ds.Spec.Template.Spec.TerminationGracePeriodSeconds; got != 120 {
		t.Errorf("terminationGracePeriodSeconds = %d, want 120 (from 2m)", got)
	}
	args := containerArgs(t, ds, "ratls-mesh")
	if got, ok := containerArgValue(args, "--drain-timeout"); !ok || got != "60s" {
		t.Errorf("--drain-timeout = (%q, %v), want (\"60s\", true)", got, ok)
	}

	// Same knobs, sleep one above the derived bound — must fail.
	out, err = helmTemplate(t,
		"--set-string", "ratlsMesh.terminationGracePeriod=2m",
		"--set-string", "ratlsMesh.drainTimeout=60s",
		"--set", "ratlsMesh.iptablesCleanup.preStopSleepSeconds=61",
	)
	if err == nil {
		t.Fatalf("helm template succeeded above derived bound, want failure\n%s", out)
	}
	failure := parsePreStopBoundFailure(t, out)
	if want := (preStopBoundFailure{Cmp: "le", Bound: 60, Got: 61}); failure != want {
		t.Fatalf("derived-bound failure = %+v, want %+v", failure, want)
	}
}

// drainTimeout ≥ terminationGracePeriod leaves zero preStop budget — even a
// 0-second sleep can race shutdown. Fail rather than render a useless
// DaemonSet.
func TestChartRejectsZeroPreStopBudget(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "ratlsMesh.terminationGracePeriod=30s",
		"--set-string", "ratlsMesh.drainTimeout=30s",
	)
	if err == nil {
		t.Fatalf("helm template succeeded with zero preStop budget, want failure\n%s", out)
	}
	failure := parseGracePeriodBudgetFailure(t, out)
	if want := (gracePeriodBudgetFailure{GracePeriod: "30s", Drain: "30s"}); failure != want {
		t.Fatalf("zero-budget failure = %+v, want %+v", failure, want)
	}
}

// Reject duration formats the helper intentionally doesn't support so a
// typo doesn't silently degrade the bound arithmetic via sprig's lenient
// int parsing (which would otherwise read "1m30s" as 1 second).
func TestChartRejectsCompoundDurations(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "ratlsMesh.drainTimeout=1m30s",
	)
	if err == nil {
		t.Fatalf("helm template succeeded for compound duration, want failure\n%s", out)
	}
	failure := parseDurationFormatFailure(t, out)
	if want := (durationFormatFailure{Value: "1m30s", Reason: "non-integer"}); failure != want {
		t.Fatalf("compound-duration failure = %+v, want %+v", failure, want)
	}
}

// Pin the suffix-only rejection separately so a future refactor of the
// helper can't remove the unit check without flagging in tests.
func TestChartRejectsUnitlessDuration(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "ratlsMesh.drainTimeout=30",
	)
	if err == nil {
		t.Fatalf("helm template succeeded for unitless duration, want failure\n%s", out)
	}
	failure := parseDurationFormatFailure(t, out)
	if want := (durationFormatFailure{Value: "30", Reason: "no-unit"}); failure != want {
		t.Fatalf("unitless-duration failure = %+v, want %+v", failure, want)
	}
}

func TestChartRendersRATLSCustomOutboundPortConsistently(t *testing.T) {
	out, err := helmTemplate(t, "--set", "ratlsMesh.ports.outbound=16001")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := strings.Count(out, "- --outbound-port\n            - \"16001\""); got != 2 {
		t.Fatalf("expected iptables-sync and ratls-mesh to use outbound port 16001, got %d occurrences\n%s", got, out)
	}
	if strings.Contains(out, "- --outbound-port\n            - \"15001\"") {
		t.Fatalf("ratls-mesh rendered the default outbound port despite override\n%s", out)
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

func TestChartWebhookInjectsWorkloadsAndExcludesSystemNamespaces(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// tls-lb now self-renders get-cert, so the platform-pods rule that only
	// existed to inject it is gone: one workload webhook remains.
	names := renderedMutatingWebhookNames(t, out)
	if !slices.Equal(names, []string{"pods.c8s.confidential.ai"}) {
		t.Fatalf("webhook names = %v, want only the workload rule", names)
	}

	generalWebhook := renderedMutatingWebhook(t, out, "pods.c8s.confidential.ai")
	excludedNamespaces := selectorExpressionValues(generalWebhook.NamespaceSelector, "kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
	for _, want := range []string{"c8s-system", "kube-system", "kube-public", "kube-node-lease"} {
		if !slices.Contains(excludedNamespaces, want) {
			t.Fatalf("general webhook namespaceSelector missing excluded namespace %q: %v", want, excludedNamespaces)
		}
	}
}

func TestChartWebhookExtraExcludedFlowsToWebhookAndSweep(t *testing.T) {
	out, err := helmTemplate(t, "--set", "webhook.extraExcluded={tenant-a,tenant-b}")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// extraExcluded must reach both the webhook namespaceSelector (CREATE-time
	// exclusion) and the operator's reinject sweep (--exclude-namespaces), or
	// the two disagree on which namespaces are out of scope.
	generalWebhook := renderedMutatingWebhook(t, out, "pods.c8s.confidential.ai")
	excluded := selectorExpressionValues(generalWebhook.NamespaceSelector, "kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
	args := renderedOperatorArgs(t, out)
	for _, ns := range []string{"tenant-a", "tenant-b"} {
		if !slices.Contains(excluded, ns) {
			t.Fatalf("webhook namespaceSelector missing extraExcluded %q: %v", ns, excluded)
		}
		if !slices.Contains(args, "--exclude-namespaces="+ns) {
			t.Fatalf("operator args missing --exclude-namespaces=%s\n%v", ns, args)
		}
	}
}

func TestChartManagedRATLSServiceTargetPortsMatchContainerPorts(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	for _, tc := range []struct {
		service    string
		deployment string
		container  string
		want       string
	}{
		{service: "c8s-cds", deployment: "c8s-cds", container: "cds", want: "https"},
	} {
		svc := renderedService(t, out, tc.service)
		if len(svc.Spec.Ports) != 1 {
			t.Fatalf("Service %s ports = %d, want 1", tc.service, len(svc.Spec.Ports))
		}
		if got := svc.Spec.Ports[0].TargetPort.String(); got != tc.want {
			t.Fatalf("Service %s targetPort = %q, want %q", tc.service, got, tc.want)
		}

		container := renderedDeploymentContainer(t, out, tc.deployment, tc.container)
		if _, ok := containerHostPort(container, tc.want); !ok {
			t.Fatalf("Deployment %s container %s missing port named %q; ports=%v", tc.deployment, tc.container, tc.want, container.Ports)
		}
	}
}

// TestChartCDSPinnedToCDSNode proves the CDS Deployment is pinned to the
// cds.node.selector node and tolerates that node's dedicated taint. CDS is a
// singleton trust root reached over a node-local NodePort and (with
// persistence) an RWO volume, so it must land on a known node — independent of
// image policy. Pinning without tolerating the dedicated taint leaves CDS
// Pending, so both must hold.
func TestChartCDSPinnedToCDSNode(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"image policy on (default)", nil},
		{"image policy off", []string{"--set", "nriImagePolicy.enabled=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			spec := renderedDeployment(t, out, "c8s-cds").Spec.Template.Spec
			if got := spec.NodeSelector["role"]; got != "cds" {
				t.Errorf("CDS nodeSelector[role] = %q, want %q (CDS must pin to a known node)", got, "cds")
			}
			if !tolerates(spec.Tolerations, "dedicated", "cds") {
				t.Errorf("CDS does not tolerate the dedicated=cds taint; it would stay Pending on a dedicated node: %v", spec.Tolerations)
			}
		})
	}
}

func tolerates(tols []corev1.Toleration, key, value string) bool {
	for _, t := range tols {
		if t.Key == key && t.Value == value {
			return true
		}
	}
	return false
}

// TestChartOperatorDialsTrustRootOverHTTPS proves the operator injects get-cert
// with --cds-url over https://, not http://. A regression to http:// would
// silently turn off the bootstrap-channel MITM defence (H1).
func TestChartOperatorDialsTrustRootOverHTTPS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	const wantURL = "https://c8s-cds.c8s-system.svc:8443"

	operatorArgs := renderedOperatorArgs(t, out)
	assertContainerHasArg(t, "operator", operatorArgs, "--cds-url="+wantURL)
	assertContainerNoArgPrefix(t, "operator", operatorArgs, "--cds-url=http://")
}

// TestChartRatlsMeshCDSMeasurementsFlagsThrough confirms the single
// cds.measurements reaches the daemonset's --cds-measurements flag — without
// this the RA-TLS handshake accepts any measurement and the H1 defence
// collapses to "trust the cluster network". ratls-mesh reads the parent's
// cds.measurements directly, so there is no mirror to drift.
func TestChartRatlsMeshCDSMeasurementsFlagsThrough(t *testing.T) {
	const measurement = "abc1230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff"
	out, err := helmTemplate(t,
		"--set", "cds.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
	i := slices.Index(args, "--cds-measurements")
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("ratls-mesh container missing --cds-measurements <value>\nargs: %v", args)
	}
	if got := args[i+1]; got != measurement {
		t.Fatalf("--cds-measurements = %q, want %q", got, measurement)
	}
}

func TestChartNRIImagePolicyUsesCDSPushAndPullModes(t *testing.T) {
	const measurement = "abc1230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff"
	out, err := helmTemplate(t,
		"--set", "cds.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	workerCfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	if got, want := workerCfg.Whitelist.Pull.URL, "https://127.0.0.1:30808"; got != want {
		t.Fatalf("worker pull URL = %q, want %q", got, want)
	}
	if got, want := workerCfg.Whitelist.Pull.Interval, "30s"; got != want {
		t.Fatalf("worker pull interval = %q, want %q", got, want)
	}
	if got, want := workerCfg.Whitelist.Pull.AttestationApiURL, "http://localhost:30840"; got != want {
		t.Fatalf("runtime attestation-api URL = %q, want %q", got, want)
	}
	if want := []string{measurement}; !slices.Equal(workerCfg.Whitelist.Pull.CDSMeasurements, want) {
		t.Fatalf("worker CDS measurements = %v, want %v", workerCfg.Whitelist.Pull.CDSMeasurements, want)
	}
	if workerCfg.Whitelist.Push.PersistPath != "" {
		t.Fatalf("worker boot config has push persist path %q, want empty", workerCfg.Whitelist.Push.PersistPath)
	}

	cdsCfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-cds")
	if got, want := cdsCfg.Whitelist.Push.PersistPath, "/var/lib/nri-image-policy/pushed.json"; got != want {
		t.Fatalf("CDS-node push persist path = %q, want %q", got, want)
	}
	if cdsCfg.Whitelist.Pull.URL != "" {
		t.Fatalf("CDS-node boot config has pull URL %q, want empty", cdsCfg.Whitelist.Pull.URL)
	}
}

func TestChartAttestationApiNodePortEnabledWithNRI(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	svc := renderedService(t, out, "c8s-attestation-api")
	if svc.Spec.Type != corev1.ServiceTypeNodePort {
		t.Fatalf("attestation-api Service type = %q by default, want NodePort", svc.Spec.Type)
	}
	if svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyTypeLocal {
		t.Fatalf("attestation-api externalTrafficPolicy = %q, want Local", svc.Spec.ExternalTrafficPolicy)
	}
	if got := svc.Spec.Ports[0].NodePort; got != 30840 {
		t.Fatalf("attestation-api nodePort = %d by default, want 30840", got)
	}
}

func TestChartAttestationApiNodePortWiresNRI(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "attestationApi.service.nodePort=31040",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	svc := renderedService(t, out, "c8s-attestation-api")
	if svc.Spec.Type != corev1.ServiceTypeNodePort {
		t.Fatalf("attestation-api Service type = %q, want NodePort", svc.Spec.Type)
	}
	if svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyTypeLocal {
		t.Fatalf("attestation-api externalTrafficPolicy = %q, want Local", svc.Spec.ExternalTrafficPolicy)
	}
	if got := svc.Spec.Ports[0].NodePort; got != 31040 {
		t.Fatalf("attestation-api nodePort = %d, want 31040", got)
	}

	cfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	if got, want := cfg.Whitelist.Pull.AttestationApiURL, "http://localhost:31040"; got != want {
		t.Fatalf("runtime attestation-api URL = %q, want %q", got, want)
	}
}

func TestChartAttestationApiNodePortDisabledWithoutNRI(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.enabled=false",
		"--set", "attestationApi.service.nodePort=0",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	svc := renderedService(t, out, "c8s-attestation-api")
	if svc.Spec.Type == corev1.ServiceTypeNodePort {
		t.Fatalf("attestation-api Service type = NodePort with NRI disabled, want no NodePort")
	}
	if got := svc.Spec.Ports[0].NodePort; got != 0 {
		t.Fatalf("attestation-api nodePort = %d with NRI disabled, want 0", got)
	}
}

func TestChartRejectsPlaintextNRIWhitelist(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "nriImagePolicy.cds.url=http://c8s-cds.c8s-system.svc:8443",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want plaintext NRI whitelist failure\n%s", out)
	}
	assertHelmFailMessage(t, out, `nriImagePolicy.cds.url must start with https:// when nriImagePolicy.enabled=true (got "http://c8s-cds.c8s-system.svc:8443"): the host plugin must fetch the whitelist over RA-TLS`)
}

func TestChartRejectsInvalidAttestationApiNodePortWithNRI(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "attestationApi.service.nodePort=0",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want invalid attestation-api host nodePort failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "attestationApi.service.nodePort must be within the Kubernetes NodePort range 30000-32767 when nriImagePolicy.enabled=true (got 0)")
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
		"--set", "ratlsMesh.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "teeProxy.enabled=false",
		"--set", "tlsLb.enabled=false",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !renderedManifestHasKind(t, out, "MutatingWebhookConfiguration") {
		t.Fatalf("render missing MutatingWebhookConfiguration\n%s", out)
	}
	args := renderedOperatorArgs(t, out)
	for _, want := range []string{
		"--cds-url=https://c8s-cds.c8s-system.svc:8443",
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

// TestChartAttestationApiBaremetalLeastPrivilege proves the default
// (cvmMode=baremetal) renders the least-privilege securityContext — not
// privileged — so a plain install does not over-privilege a host-device
// DaemonSet. This is the over-privilege regression guard.
func TestChartAttestationApiBaremetalLeastPrivilege(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	c := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api")
	sc := c.SecurityContext
	if sc == nil {
		t.Fatal("attestation-api missing securityContext")
	}
	if sc.Privileged != nil && *sc.Privileged {
		t.Errorf("default (baremetal) must not be privileged; got privileged=true")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Errorf("baremetal must set allowPrivilegeEscalation=false; got %+v", sc.AllowPrivilegeEscalation)
	}
	if !hasCapability(c, "SYS_RAWIO") {
		t.Errorf("baremetal must add SYS_RAWIO; got %+v", sc.Capabilities)
	}
	if !slices.Contains(sc.Capabilities.Drop, "ALL") {
		t.Errorf("baremetal must drop ALL; got %+v", sc.Capabilities)
	}
}

// TestChartAttestationApiManagedPrivileged proves cvmMode=managed renders a
// privileged container (managed CVM gates vTPM access below the capability
// layer, so /dev/tpm0 needs full privilege) and drops the least-privilege
// capabilities map — the two modes are strictly either/or, not merged.
func TestChartAttestationApiManagedPrivileged(t *testing.T) {
	out, err := helmTemplate(t, "--set", "attestationApi.cvmMode=managed")
	if err != nil {
		t.Fatalf("helm template (cvmMode=managed): %v\n%s", err, out)
	}
	c := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api")
	sc := c.SecurityContext
	if sc == nil || sc.Privileged == nil || !*sc.Privileged {
		t.Errorf("managed must be privileged for vTPM access; got %+v", sc)
	}
	if sc != nil && sc.Capabilities != nil {
		t.Errorf("managed must not carry the least-privilege capabilities map; got %+v", sc.Capabilities)
	}
}

// TestChartAttestationApiInvalidCvmMode proves an unrecognized cvmMode fails
// the render loudly rather than silently falling through to least-privilege
// (which would fail closed at runtime on a managed CVM).
func TestChartAttestationApiInvalidCvmMode(t *testing.T) {
	out, err := helmTemplate(t, "--set", "attestationApi.cvmMode=bogus")
	if err == nil {
		t.Fatalf("expected render to fail on invalid cvmMode; got success\n%s", out)
	}
	assertHelmFailMessage(t, out, `attestationApi.cvmMode must be "baremetal" or "managed" (got "bogus")`)
}

func TestChartRendersManagedClusterKnobs(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "serviceAccount.imagePullSecrets[0].name=ghcr-secret",
		"--set", "attestationApi.cvmMode=managed",
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

// TestChartGlobalImagePullSecrets proves the chart-wide imagePullSecrets feeds
// every component, and a per-component value overrides it for that component.
func TestChartGlobalImagePullSecrets(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "imagePullSecrets[0].name=ghcr-pull",
		"--set", "teeProxy.imagePullSecrets[0].name=tee-special",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// The global reaches a non-overriding component (ratls-mesh).
	rm := renderedDaemonSet(t, out, "c8s-ratls-mesh")
	if !hasPullSecret(rm.Spec.Template.Spec.ImagePullSecrets, "ghcr-pull") {
		t.Errorf("ratls-mesh missing global pull secret: %v", rm.Spec.Template.Spec.ImagePullSecrets)
	}
	// teeProxy's own value overrides the global.
	tp := renderedDeployment(t, out, "c8s-tee-proxy")
	if hasPullSecret(tp.Spec.Template.Spec.ImagePullSecrets, "ghcr-pull") || !hasPullSecret(tp.Spec.Template.Spec.ImagePullSecrets, "tee-special") {
		t.Errorf("tee-proxy should use its override, not the global: %v", tp.Spec.Template.Spec.ImagePullSecrets)
	}
}

func hasPullSecret(refs []corev1.LocalObjectReference, name string) bool {
	for _, r := range refs {
		if r.Name == name {
			return true
		}
	}
	return false
}

func TestChartRendersTLSLBPublicTLSAndDiscovery(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "tlsLb.publicTLS.secretName=tls-lb-public-tls",
		"--set-string", "tlsLb.publicTLS.mountPath=/edge-tls",
		"--set-string", "tlsLb.publicTLS.certKey=public.crt",
		"--set-string", "tlsLb.publicTLS.keyKey=public.key",
		"--set", "tlsLb.discovery.enabled=true",
		"--set-string", "tlsLb.upstream.address=c8s-tee-proxy:443",
		"--set", "tlsLb.upstream.protocol=https",
		"--set", "tlsLb.upstream.tls.verify=true",
		"--set-string", "tlsLb.upstream.tls.serverName=tee-proxy.tee-attestation.svc.cluster.local",
		"--set", "teeProxy.tls.enabled=true",
		"--set-string", "teeProxy.tls.secretName=tee-proxy-internal-tls",
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
		"alias /tls/ca.pem;",
		"proxy_ssl_certificate /tls/cert.pem;",
		"proxy_ssl_certificate_key /tls/key.pem;",
		"proxy_ssl_name tee-proxy.tee-attestation.svc.cluster.local;",
		"proxy_ssl_verify on;",
		"proxy_ssl_trusted_certificate /tls/cert.pem;",
		"proxy_pass https://backend;",
		"name: tls-certs",
		"name: public-tls",
		"mountPath: /edge-tls",
		"secretName: tls-lb-public-tls",
		"key: public.crt",
		"path: public.key",
		"name: discovery",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q\n%s", want, out)
		}
	}
	initCert := tlsLBGetCertContainer(t, out, "c8s-init-cert")
	assertContainerArgs(t, initCert,
		"--discovery-out=/discovery/discovery.json",
		"--discovery-cds-cert-url=/.well-known/cds-cert.pem",
		"--discovery-public-tls-mode=webpki",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem",
	)
	assertContainerArgsAbsent(t, initCert, "--reload-watch=/edge-tls/public.crt")
	renewCert := tlsLBGetCertContainer(t, out, "c8s-renew-cert")
	assertContainerArgs(t, renewCert,
		"--reload-watch=/edge-tls/public.crt",
		"--reload-watch=/edge-tls/public.key",
		"--discovery-public-tls-mode=webpki",
	)
	deployment := renderedDeployment(t, out, "c8s-tls-lb")
	if got := deployment.Spec.Template.Spec.ShareProcessNamespace; got == nil || !*got {
		t.Fatalf("tls-lb shareProcessNamespace = %v, want true", got)
	}
}

// TestChartTLSLBServiceType pins that the Service type is exactly what the
// operator sets: default ClusterIP, explicit LoadBalancer/NodePort honored.
// Public exposure is an explicit type=LoadBalancer, not inferred.
func TestChartTLSLBServiceType(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want corev1.ServiceType
	}{
		{"default is ClusterIP", nil, corev1.ServiceTypeClusterIP},
		{"explicit LoadBalancer", []string{"--set", "tlsLb.service.type=LoadBalancer"}, corev1.ServiceTypeLoadBalancer},
		{"explicit NodePort", []string{"--set", "tlsLb.service.type=NodePort"}, corev1.ServiceTypeNodePort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			if got := renderedService(t, out, "c8s-tls-lb").Spec.Type; got != tc.want {
				t.Fatalf("service type = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestChartRendersTeeProxyStaticTLSSecret(t *testing.T) {
	out, err := helmTemplate(t,
		// The static-secret TLS mode is the non-default alternative to
		// certProvisioning (self-rendered CDS cert), so turn the latter off.
		"--set", "teeProxy.certProvisioning.enabled=false",
		"--set", "teeProxy.tls.enabled=true",
		"--set-string", "teeProxy.tls.secretName=tee-proxy-internal-tls",
		"--set-string", "tlsLb.upstream.address=c8s-tee-proxy:443",
		"--set", "tlsLb.upstream.protocol=https",
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

func TestTLSLBCertProvisioningValuesDriveGetCertContainers(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "tlsLb.certProvisioning.renewInterval=30m",
		"--set", "tlsLb.certProvisioning.verbose=true",
		"--set", "tlsLb.nginx.runAsUser=201",
		"--set", "tlsLb.nginx.runAsGroup=202",
		"--set", "tlsLb.nginx.runAsNonRoot=false",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	initCert := tlsLBGetCertContainer(t, out, "c8s-init-cert")
	assertContainerArgs(t, initCert, "--verbose")
	if got := initCert.SecurityContext.RunAsUser; got == nil || *got != 201 {
		t.Fatalf("c8s-init-cert runAsUser = %v, want 201", got)
	}
	if got := initCert.SecurityContext.RunAsGroup; got == nil || *got != 202 {
		t.Fatalf("c8s-init-cert runAsGroup = %v, want 202", got)
	}
	if got := initCert.SecurityContext.RunAsNonRoot; got == nil || *got {
		t.Fatalf("c8s-init-cert runAsNonRoot = %v, want false", got)
	}
	renewCert := tlsLBGetCertContainer(t, out, "c8s-renew-cert")
	assertContainerArgs(t, renewCert, "--renew-interval=30m", "--verbose")
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

func TestChartRejectsManagedTeeProxyHTTPSWithoutListener(t *testing.T) {
	// With every HTTPS-listener source off (certProvisioning, static tls,
	// domain), https to the chart tee-proxy has nothing to talk to.
	out, err := helmTemplate(t,
		"--set-string", "tlsLb.upstream.address=c8s-tee-proxy:443",
		"--set", "tlsLb.upstream.protocol=https",
		"--set", "teeProxy.certProvisioning.enabled=false",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want tee-proxy HTTPS-listener failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "tlsLb.upstream.protocol=https with the chart-managed tee-proxy requires teeProxy.certProvisioning.enabled (default), teeProxy.tls.enabled, or teeProxy.domain to enable the HTTPS listener")
}

func TestChartRejectsTLSLBHTTPSWithTeeProxyHTTPPort(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "tlsLb.upstream.address=c8s-tee-proxy:80",
		"--set", "tlsLb.upstream.protocol=https",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want tls-lb upstream address failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "tlsLb.upstream.protocol=https requires tlsLb.upstream.address to point at a TLS port; for the chart-managed tee-proxy use c8s-tee-proxy:443")
}

// TestChartDefaultTLSLBToTeeProxyIsMutualTLS pins the new default: tls-lb
// reaches the chart tee-proxy over mutual attested TLS (both CDS-issued certs).
func TestChartDefaultTLSLBToTeeProxyIsMutualTLS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConf(t, out)
	for _, want := range []string{
		"server c8s-tee-proxy:443;",
		"proxy_pass https://backend;",
		"proxy_ssl_verify on;",
		"proxy_ssl_name c8s-tee-proxy.c8s-system.svc;",
		"proxy_ssl_certificate /tls/cert.pem;",
		// trust = the get-cert output cert.pem, which CDS returns as leaf+CA
		// chain, so the CDS CA that signed tee-proxy is the anchor.
		"proxy_ssl_trusted_certificate /tls/cert.pem;",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("tls-lb nginx config missing %q\n%s", want, cfg)
		}
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
	cfg := renderedTLSLBNginxConfig(t, out)
	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "proxy_ssl_name", "tee-proxy.tee-attestation.svc.cluster.local")
}

func TestTLSLBAdditionalRoutesConfigureNginxLocations(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/whitelist",
		"--set-string", "routes[0].match=exact",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
		"--set-string", "routes[1].path=/tenant/",
		"--set-string", "routes[1].backend.address=tenant-router.c8s-system.svc:8080",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)

	for _, tt := range []struct {
		name     string
		match    string
		path     string
		proxyURL string
	}{
		{
			name:     "exact",
			match:    "exact",
			path:     "/whitelist",
			proxyURL: "http://route_0",
		},
		{
			name:     "default-prefix",
			match:    "prefix",
			path:     "/tenant/",
			proxyURL: "http://route_1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			route := cfg.location(t, tt.match, tt.path)
			route.assertDirective(t, "proxy_pass", tt.proxyURL)
		})
	}

	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "proxy_pass", "http://backend")
	cfg.upstream(t, "backend").assertServer(t, "vllm:8000")
	cfg.upstream(t, "route_0").assertServer(t, "cds.c8s-system.svc:8080")
	cfg.upstream(t, "route_1").assertServer(t, "tenant-router.c8s-system.svc:8080")
}

func TestTLSLBTypedHTTPRouteConfiguresNginxLocation(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/tenant/",
		"--set-string", "routes[0].backend.address=tenant-router.c8s-system.svc:8080",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	cfg.upstream(t, "route_0").assertServer(t, "tenant-router.c8s-system.svc:8080")
	route := cfg.location(t, "prefix", "/tenant/")
	route.assertDirective(t, "proxy_pass", "http://route_0")
	route.assertDirective(t, "proxy_set_header", "X-Forwarded-Proto", "$scheme")
	route.assertNoDirective(t, "proxy_ssl_certificate")
	route.assertNoDirective(t, "proxy_ssl_certificate_key")
	route.assertNoDirective(t, "proxy_ssl_name")
	route.assertNoDirective(t, "proxy_ssl_verify")
}

func TestTLSLBTypedHTTPSRouteConfiguresProxyTLS(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/whitelist",
		"--set-string", "routes[0].match=exact",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc.cluster.local:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
		"--set-string", "routes[0].backend.tls.serverName=cds.c8s-system.svc.cluster.local",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	cfg.upstream(t, "route_0").assertServer(t, "cds.c8s-system.svc.cluster.local:8080")
	route := cfg.location(t, "exact", "/whitelist")
	route.assertDirective(t, "proxy_ssl_server_name", "on")
	route.assertDirective(t, "proxy_ssl_name", "cds.c8s-system.svc.cluster.local")
	route.assertDirective(t, "proxy_ssl_verify", "on")
	route.assertDirective(t, "proxy_ssl_verify_depth", "2")
	route.assertDirective(t, "proxy_ssl_trusted_certificate", "/tls/ca.pem")
	route.assertDirective(t, "proxy_pass", "https://route_0")
	route.assertNoDirective(t, "proxy_ssl_certificate")
	route.assertNoDirective(t, "proxy_ssl_certificate_key")
}

func TestTLSLBTypedHTTPSRouteCanUseCDSClientCert(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/whitelist",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc.cluster.local:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.useCDSClientCert=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	route := cfg.location(t, "prefix", "/whitelist")
	route.assertDirective(t, "proxy_ssl_certificate", "/tls/cert.pem")
	route.assertDirective(t, "proxy_ssl_certificate_key", "/tls/key.pem")
	route.assertDirective(t, "proxy_ssl_name", "cds.c8s-system.svc.cluster.local")
	route.assertDirective(t, "proxy_pass", "https://route_0")
}

func TestTLSLBTypedHTTPSRouteCustomTrustedCAPathDoesNotMountMeshCA(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/whitelist",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc.cluster.local:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
		"--set-string", "routes[0].backend.tls.trustedCAPath=/etc/ssl/certs/ca-certificates.crt",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	route := cfg.location(t, "prefix", "/whitelist")
	route.assertDirective(t, "proxy_ssl_trusted_certificate", "/etc/ssl/certs/ca-certificates.crt")
	assertNoTLSLBMeshCAVolume(t, out)
}

func renderedTLSLBNginxConf(t *testing.T, manifest string) string {
	t.Helper()
	cm := renderedConfigMap(t, manifest, "c8s-tls-lb-nginx")
	conf, ok := cm.Data["nginx.conf"]
	if !ok || conf == "" {
		t.Fatalf("tls-lb nginx ConfigMap missing nginx.conf\n%s", manifest)
	}
	return conf
}

type nginxConfig struct {
	upstreams map[string]*nginxBlock
	locations map[nginxLocationKey]*nginxBlock
}

type nginxLocationKey struct {
	match string
	path  string
}

type nginxBlock struct {
	directives map[string][][]string
}

func renderedTLSLBNginxConfig(t *testing.T, manifest string) nginxConfig {
	t.Helper()
	return parseNginxConfig(t, renderedTLSLBNginxConf(t, manifest))
}

func parseNginxConfig(t *testing.T, conf string) nginxConfig {
	t.Helper()
	cfg := nginxConfig{
		upstreams: make(map[string]*nginxBlock),
		locations: make(map[nginxLocationKey]*nginxBlock),
	}

	var current *nginxBlock
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, "{") {
			fields := strings.Fields(strings.TrimSpace(strings.TrimSuffix(trimmed, "{")))
			if len(fields) == 2 && fields[0] == "upstream" {
				block := &nginxBlock{directives: make(map[string][][]string)}
				cfg.upstreams[fields[1]] = block
				current = block
				continue
			}
			if len(fields) >= 2 && fields[0] == "location" {
				key := nginxLocationKey{match: "prefix", path: fields[1]}
				if len(fields) == 3 && fields[1] == "=" {
					key = nginxLocationKey{match: "exact", path: fields[2]}
				}
				block := &nginxBlock{directives: make(map[string][][]string)}
				cfg.locations[key] = block
				current = block
				continue
			}
			current = nil
			continue
		}
		if trimmed == "}" {
			current = nil
			continue
		}
		if current == nil || !strings.HasSuffix(trimmed, ";") {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(trimmed, ";"))
		if len(fields) == 0 {
			continue
		}
		current.directives[fields[0]] = append(current.directives[fields[0]], fields[1:])
	}
	return cfg
}

func (cfg nginxConfig) upstream(t *testing.T, name string) *nginxBlock {
	t.Helper()
	upstream, ok := cfg.upstreams[name]
	if !ok {
		t.Fatalf("nginx config missing upstream %q; got %v", name, cfg.upstreams)
	}
	return upstream
}

func (cfg nginxConfig) location(t *testing.T, match, path string) *nginxBlock {
	t.Helper()
	key := nginxLocationKey{match: match, path: path}
	location, ok := cfg.locations[key]
	if !ok {
		t.Fatalf("nginx config missing location %#v; got %v", key, cfg.locations)
	}
	return location
}

func (block *nginxBlock) assertServer(t *testing.T, server string) {
	t.Helper()
	block.assertDirective(t, "server", server)
}

func (block *nginxBlock) assertDirective(t *testing.T, name string, args ...string) {
	t.Helper()
	for _, got := range block.directives[name] {
		if slices.Equal(got, args) {
			return
		}
	}
	t.Fatalf("nginx directive %q args %v not found; got %v", name, args, block.directives[name])
}

func (block *nginxBlock) assertNoDirective(t *testing.T, name string) {
	t.Helper()
	if got := block.directives[name]; len(got) > 0 {
		t.Fatalf("nginx directive %q = %v, want absent", name, got)
	}
}

func assertNoTLSLBMeshCAVolume(t *testing.T, manifest string) {
	t.Helper()
	dep := renderedDeployment(t, manifest, "c8s-tls-lb")
	for _, volume := range dep.Spec.Template.Spec.Volumes {
		if volume.Name == "mesh-ca" {
			t.Fatalf("Deployment/tls-lb has mesh-ca volume, want absent: %#v", volume)
		}
	}
}

func TestTLSLBRejectsUnsafeProxyTLS(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "route-verifyDepth-injection",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
				"--set-string", "routes[0].backend.protocol=https",
				"--set", "routes[0].backend.tls.verify=true",
				"--set-string", "routes[0].backend.tls.verifyDepth=9; return 444",
			},
			want: "tlsLb.routes[0].backend.tls.verifyDepth must be a non-negative integer, got: 9; return 444",
		},
		{
			name: "route-tls-on-http-backend",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
				"--set", "routes[0].backend.tls.verify=true",
			},
			want: "tlsLb.routes[0].backend.tls.verify and useCDSClientCert require backend.protocol: https",
		},
		{
			name: "route-verify-not-bool",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
				"--set-string", "routes[0].backend.protocol=https",
				"--set-string", "routes[0].backend.tls.verify=false",
			},
			want: "tlsLb.routes[0].backend.tls.verify must be a boolean; do not set it via --set-string, got: false",
		},
		{
			name: "route-address-with-hash",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080#x",
			},
			want: "tlsLb.routes[0].backend.address must be a host:port address without scheme, whitespace, semicolons, braces, slashes, or '#', got: svc:8080#x",
		},
		{
			name: "route-serverName-with-slash",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
				"--set-string", "routes[0].backend.protocol=https",
				"--set-string", "routes[0].backend.tls.serverName=a/b",
			},
			want: "tlsLb.routes[0].backend.tls.serverName must not contain whitespace, semicolons, braces, slashes, or '#', got: a/b",
		},
		{
			name: "upstream-serverName-injection",
			args: []string{
				"--set", "upstream.protocol=https",
				"--set", "upstream.tls.verify=true",
				"--set-string", "upstream.tls.serverName=evil; return 444",
			},
			want: "tlsLb.upstream.tls.serverName must not contain whitespace, semicolons, braces, slashes, or '#', got: evil; return 444",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplateTLSLB(t, tt.args...)
			if err == nil {
				t.Fatalf("helm template succeeded, want %q\n%s", tt.want, out)
			}
			assertHelmFailMessage(t, out, tt.want)
		})
	}
}

// TestTLSLBVerifyDepthZeroPreserved guards against the sprig `default` footgun
// where an int 0 is treated as empty: an explicit verifyDepth: 0 (verify leaf
// only) must reach nginx as 0, not be silently bumped to the default 2.
func TestTLSLBVerifyDepthZeroPreserved(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "upstream.protocol=https",
		"--set", "upstream.tls.verify=true",
		"--set", "upstream.tls.verifyDepth=0",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	cfg.location(t, "prefix", "/").assertDirective(t, "proxy_ssl_verify_depth", "0")
}

// TestTLSLBMultiRouteVerifiedRouteUsesMeshCABundle pins that a verified HTTPS
// route using the default (mesh) CA resolves its trusted cert to the mesh CA
// bundle the get-cert sidecar writes alongside the leaf, even when an earlier
// route does not need it.
func TestTLSLBMultiRouteVerifiedRouteUsesMeshCABundle(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/a",
		"--set-string", "routes[0].backend.address=svc-a:8080",
		"--set-string", "routes[1].path=/b",
		"--set-string", "routes[1].backend.address=svc-b:8080",
		"--set-string", "routes[1].backend.protocol=https",
		"--set", "routes[1].backend.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	route := cfg.location(t, "prefix", "/b")
	route.assertDirective(t, "proxy_ssl_verify", "on")
	route.assertDirective(t, "proxy_ssl_trusted_certificate", "/tls/ca.pem")
}

func TestTLSLBRejectsInvalidRouteMatch(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/whitelist",
		"--set-string", "routes[0].match=regex",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want invalid route match failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "tlsLb.routes[0].match must be 'exact' or 'prefix', got: regex")
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
				"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
			},
			want: "tlsLb.routes[0].path is required",
		},
		{
			name: "backend",
			args: []string{
				"--set-string", "routes[0].path=/whitelist",
			},
			want: "tlsLb.routes[0].backend is required",
		},
		{
			name: "backend-address",
			args: []string{
				"--set-string", "routes[0].path=/whitelist",
				"--set-string", "routes[0].backend.protocol=https",
			},
			want: "tlsLb.routes[0].backend.address is required",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplateTLSLB(t, tt.args...)
			if err == nil {
				t.Fatalf("helm template succeeded, want missing route field failure\n%s", out)
			}
			assertHelmFailMessage(t, out, tt.want)
		})
	}
}

func TestTLSLBRejectsRouteUpstream(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/whitelist",
		"--set-string", "routes[0].upstream=http://cds.c8s-system.svc:8080",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want unsupported route upstream failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "tlsLb.routes[0].upstream is not supported; set backend.address and backend.protocol instead")
}

func TestTLSLBRejectsInvalidTypedRouteProtocol(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/whitelist",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
		"--set-string", "routes[0].backend.protocol=grpc",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want invalid typed route protocol failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "tlsLb.routes[0].backend.protocol must be 'http' or 'https', got: grpc")
}

func TestTLSLBRejectsUnsafeRoutePath(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/bad;return",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want unsafe route path failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "tlsLb.routes[0].path must start with '/' and contain only URI path characters safe for nginx locations, got: /bad;return")
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
	cfg := renderedTLSLBNginxConfig(t, out)
	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "proxy_ssl_trusted_certificate", "/etc/ssl/certs/ca-certificates.crt")
	assertNoTLSLBMeshCAVolume(t, out)
}

// TestTLSLBExplicitTrustedCAPathRendersVerbatim pins that an operator-supplied
// trustedCAPath is emitted verbatim in proxy_ssl_trusted_certificate. The chart
// no longer mounts any volume for it: providing the file at that path is the
// operator's responsibility.
func TestTLSLBExplicitTrustedCAPathRendersVerbatim(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "upstream.protocol=https",
		"--set", "upstream.tls.verify=true",
		"--set-string", "upstream.tls.trustedCAPath=/mesh-ca/ca.pem",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "proxy_ssl_trusted_certificate", "/mesh-ca/ca.pem")
}

func TestTLSLBDiscoveryRequiresAdvertisedMeshCA(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "discovery.enabled=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	meshCA := cfg.location(t, "exact", "/.well-known/mesh-ca.pem")
	meshCA.assertDirective(t, "alias", "/tls/ca.pem")
	assertContainerArgs(t, tlsLBGetCertContainer(t, out, "c8s-init-cert"),
		"--ca-out=/tls/ca.pem")
	assertContainerArgs(t, tlsLBGetCertContainer(t, out, "c8s-init-cert"),
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem")
}

// TestTLSLBGetCertWritesMeshCABundle pins the mechanism that replaced the
// c8s-cds-mesh-ca ConfigMap mount: both get-cert sidecars write the mesh CA
// bundle to /tls/ca.pem (the tls-certs volume that already holds the leaf).
func TestTLSLBGetCertWritesMeshCABundle(t *testing.T) {
	out, err := helmTemplateTLSLB(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerArgs(t, tlsLBGetCertContainer(t, out, "c8s-init-cert"),
		"--ca-out=/tls/ca.pem")
	assertContainerArgs(t, tlsLBGetCertContainer(t, out, "c8s-renew-cert"),
		"--ca-out=/tls/ca.pem")
}

func TestTLSLBDiscoveryReportsCDSModeWithoutPublicTLSSecret(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "discovery.enabled=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerArgs(t, tlsLBGetCertContainer(t, out, "c8s-init-cert"),
		"--discovery-public-tls-mode=cds")
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
	// The event recorder needs events, but only create/patch (recorder
	// aggregation), never read or delete across the cluster. Decode the
	// ClusterRole and assert the verbs exactly so a broadened grant fails.
	var role rbacv1.ClusterRole
	if !findDoc(t, out, "ClusterRole", "c8s-operator", &role) {
		t.Fatalf("render missing ClusterRole c8s-operator\n%s", out)
	}
	if got := operatorVerbsFor(role, "", "events"); !slices.Equal(got, []string{"create", "patch"}) {
		t.Fatalf("operator events verbs = %v, want [create patch]", got)
	}
	for _, unexpected := range []string{
		"resources: [confidentialworkloads/finalizers]",
		"resources: [deployments, statefulsets, daemonsets, replicasets]",
		"resources: [secrets, configmaps]",
		"resources: [nodes]",
		"resources: [rolebindings]",
	} {
		if strings.Contains(out, unexpected) {
			t.Fatalf("render contained broad RBAC rule %q\n%s", unexpected, out)
		}
	}
}

// operatorVerbsFor returns the verbs the ClusterRole grants on (apiGroup,
// resource), nil if no rule covers it. It does not expand wildcards: a "*"
// resource or apiGroup matches only a literal "*" lookup, which is intentional
// for least-privilege assertions.
func operatorVerbsFor(role rbacv1.ClusterRole, apiGroup, resource string) []string {
	for _, rule := range role.Rules {
		if slices.Contains(rule.APIGroups, apiGroup) && slices.Contains(rule.Resources, resource) {
			return rule.Verbs
		}
	}
	return nil
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

func TestChartRollsAttestationApiOnConfigChange(t *testing.T) {
	defaultOut, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template default config: %v\n%s", err, defaultOut)
	}
	defaultChecksum := renderedValue(t, defaultOut, "checksum/config")
	if defaultChecksum == "" {
		t.Fatalf("default checksum/config is empty\n%s", defaultOut)
	}

	changedOut, err := helmTemplate(t,
		"--set", "attestationApi.platforms[0]=az-snp",
	)
	if err != nil {
		t.Fatalf("helm template changed config: %v\n%s", err, changedOut)
	}
	changedChecksum := renderedValue(t, changedOut, "checksum/config")
	if changedChecksum == defaultChecksum {
		t.Fatalf("checksum/config did not change after changing platforms: %s", defaultChecksum)
	}
}

// --- Kata runtime installation and enforcement -------------------------

// TestChartKataDisabledByDefault: the default render must carry no kata
// resources, so installs that don't ask for kata are unchanged.
func TestChartKataDisabledByDefault(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-kata-deploy") {
		t.Fatalf("kata-deploy DaemonSet rendered without kata.enabled\n%s", out)
	}
	if renderedManifestHasNamedKind(t, out, "RuntimeClass", "kata-qemu") {
		t.Fatalf("kata RuntimeClass rendered without kata.enabled\n%s", out)
	}
	if renderedManifestHasNamedKind(t, out, "ValidatingAdmissionPolicy", "c8s-kata-enforcement") {
		t.Fatalf("kata ValidatingAdmissionPolicy rendered without kata enforcement\n%s", out)
	}
}

// TestChartKataEnabledRendersDeployStack: kata.enabled renders the
// kata-deploy DaemonSet and the three RuntimeClasses, but no enforcement.
func TestChartKataEnabledRendersDeployStack(t *testing.T) {
	out, err := helmTemplate(t, "--set", "kata.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, rc := range []string{"kata-qemu", "kata-clh", "kata-qemu-snp"} {
		if !renderedManifestHasNamedKind(t, out, "RuntimeClass", rc) {
			t.Fatalf("kata.enabled missing RuntimeClass %q\n%s", rc, out)
		}
	}

	ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
	if !ds.Spec.Template.Spec.HostPID {
		t.Errorf("kata-deploy DaemonSet must set hostPID: true (kata-deploy nsenters PID 1)")
	}
	c, ok := findContainer(ds.Spec.Template.Spec.Containers, "kube-kata")
	if !ok {
		t.Fatalf("kata-deploy DaemonSet missing kube-kata container; have %v", containerNames(ds.Spec.Template.Spec.Containers))
	}
	if c.SecurityContext == nil || c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged {
		t.Errorf("kube-kata container must run privileged (it installs a runtime onto the host); got %+v", c.SecurityContext)
	}

	// kata.enabled on its own must not turn on enforcement.
	if renderedManifestHasNamedKind(t, out, "ValidatingAdmissionPolicy", "c8s-kata-enforcement") {
		t.Errorf("kata.enabled without kata.enforce.enabled should not render the enforcement policy")
	}
	if slices.Contains(renderedOperatorArgs(t, out), "--kata-enforce=true") {
		t.Errorf("operator should not get --kata-enforce when enforcement is off")
	}
}

// TestChartKataDistroSelectsContainerdConfigDir: the kata.distro value must
// pick the right host containerd config dir for kata-deploy to bind.
func TestChartKataDistroSelectsContainerdConfigDir(t *testing.T) {
	for _, tc := range []struct {
		distro string
		want   string
	}{
		{"k8s", "/etc/containerd"},
		{"rke2", "/var/lib/rancher/rke2/agent/etc/containerd"},
	} {
		t.Run(tc.distro, func(t *testing.T) {
			out, err := helmTemplate(t, "--set", "kata.enabled=true", "--set-string", "kata.distro="+tc.distro)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
			if got := hostPathVolume(t, ds, "containerd-conf"); got != tc.want {
				t.Fatalf("distro %q: containerd-conf hostPath = %q, want %q", tc.distro, got, tc.want)
			}
		})
	}
}

func TestChartKataRejectsUnknownDistro(t *testing.T) {
	out, err := helmTemplate(t, "--set", "kata.enabled=true", "--set-string", "kata.distro=openshift")
	if err == nil {
		t.Fatalf("helm template succeeded for an unknown kata.distro, want failure\n%s", out)
	}
}

// TestChartKataContainerdPrepInitContainer: on rke2 the kata-deploy DaemonSet
// must carry a containerd-prep initContainer that wires up the drop-in import
// before kube-kata runs; on k8s kata-deploy edits containerd directly, so the
// prep must be absent.
func TestChartKataContainerdPrepInitContainer(t *testing.T) {
	t.Run("rke2", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "kata.enabled=true", "--set-string", "kata.distro=rke2")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
		prep, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "containerd-prep")
		if !ok {
			t.Fatalf("rke2: kata-deploy DaemonSet missing containerd-prep initContainer; have %v",
				containerNames(ds.Spec.Template.Spec.InitContainers))
		}
		if prep.SecurityContext == nil || prep.SecurityContext.Privileged == nil || !*prep.SecurityContext.Privileged {
			t.Errorf("containerd-prep must run privileged (it edits the host containerd config)")
		}
		env := initContainerEnv(t, ds, "containerd-prep")
		if got := env["HOST_CONTAINERD_DIR"]; got != "/var/lib/rancher/rke2/agent/etc/containerd" {
			t.Errorf("HOST_CONTAINERD_DIR = %q, want the rke2 containerd dir", got)
		}
		if got := env["BASE_DIRECTIVE"]; got != `{{ template "base" . }}` {
			t.Errorf("BASE_DIRECTIVE = %q, want the literal RKE2 base include", got)
		}
	})

	t.Run("k8s", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "kata.enabled=true", "--set-string", "kata.distro=k8s")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
		if _, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "containerd-prep"); ok {
			t.Fatalf("k8s: kata-deploy must not carry a containerd-prep initContainer")
		}
	})
}

// TestChartKataEnforceRendersPolicyAndOperatorFlag: kata.enforce.enabled
// renders the ValidatingAdmissionPolicy + binding and flips the operator's
// --kata-enforce flag — the two halves of enforcement must move together.
func TestChartKataEnforceRendersPolicyAndOperatorFlag(t *testing.T) {
	out, err := helmTemplate(t, "--set", "kata.enabled=true", "--set", "kata.enforce.enabled=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !renderedManifestHasNamedKind(t, out, "ValidatingAdmissionPolicy", "c8s-kata-enforcement") {
		t.Fatalf("kata enforcement missing ValidatingAdmissionPolicy\n%s", out)
	}
	if !renderedManifestHasNamedKind(t, out, "ValidatingAdmissionPolicyBinding", "c8s-kata-enforcement") {
		t.Fatalf("kata enforcement missing ValidatingAdmissionPolicyBinding\n%s", out)
	}
	if !slices.Contains(renderedOperatorArgs(t, out), "--kata-enforce=true") {
		t.Fatalf("operator missing --kata-enforce=true with enforcement on\n%s", out)
	}
}

// TestChartKataEnforceRequiresEnabled: enforcement without the kata stack it
// injects and validates is a misconfiguration — the chart must reject it.
func TestChartKataEnforceRequiresEnabled(t *testing.T) {
	out, err := helmTemplate(t, "--set", "kata.enforce.enabled=true")
	if err == nil {
		t.Fatalf("helm template succeeded with kata.enforce.enabled but kata.enabled=false, want failure\n%s", out)
	}
}

// TestChartNriImagePolicyDistroSelectsContainerdLayout: nriImagePolicy.distro
// drives the host containerd directory the installer binds and the patch
// strategy. The drop-in file path itself is discovered at runtime (the config
// file name varies), so it is not asserted here — only the dir, mode, restart.
func TestChartNriImagePolicyDistroSelectsContainerdLayout(t *testing.T) {
	for _, tc := range []struct {
		distro      string
		wantDir     string
		wantMode    string
		wantRestart string
	}{
		{
			distro:      "k8s",
			wantDir:     "/etc/containerd",
			wantMode:    "patch",
			wantRestart: "systemctl restart containerd",
		},
		{
			distro:      "rke2",
			wantDir:     "/var/lib/rancher/rke2/agent/etc/containerd",
			wantMode:    "dropin",
			wantRestart: "if systemctl is-active --quiet rke2-server; then systemctl restart rke2-server; else systemctl restart rke2-agent; fi",
		},
	} {
		t.Run(tc.distro, func(t *testing.T) {
			out, err := helmTemplate(t, "--set-string", "nriImagePolicy.distro="+tc.distro)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			for _, name := range []string{"c8s-nri-image-policy-worker", "c8s-nri-image-policy-cds"} {
				ds := renderedDaemonSet(t, out, name)
				if got := hostPathVolume(t, ds, "host-containerd-config"); got != tc.wantDir {
					t.Fatalf("%s distro %q: host-containerd-config hostPath = %q, want %q", name, tc.distro, got, tc.wantDir)
				}
				script := strings.Join(containerArgs(t, &ds, "install"), "\n")
				for _, want := range []string{
					"CONTAINERD_DIR=/host" + tc.wantDir,
					`CONTAINERD_CONFIG_MODE="` + tc.wantMode + `"`,
					`RESTART_COMMAND="` + tc.wantRestart + `"`,
				} {
					if !strings.Contains(script, want) {
						t.Fatalf("%s distro %q: install script missing %q\n%s", name, tc.distro, want, script)
					}
				}
			}
		})
	}
}

// TestChartNriImagePolicyRejectsUnknownDistro: an unsupported distro must fail
// the render, not silently fall through to a wrong containerd layout.
func TestChartNriImagePolicyRejectsUnknownDistro(t *testing.T) {
	out, err := helmTemplate(t, "--set-string", "nriImagePolicy.distro=openshift")
	if err == nil {
		t.Fatalf("helm template succeeded for an unknown nriImagePolicy.distro, want failure\n%s", out)
	}
}

// TestChartNriImagePolicyContainerdPrepInitContainer: on rke2 the installer
// DaemonSet must run a containerd-prep initContainer before `install`, so the
// drop-in import exists by the time `install` writes its drop-in. On k8s the
// installer patches config.toml in place, so the prep must be absent.
func TestChartNriImagePolicyContainerdPrepInitContainer(t *testing.T) {
	t.Run("rke2", func(t *testing.T) {
		out, err := helmTemplate(t, "--set-string", "nriImagePolicy.distro=rke2")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		for _, name := range []string{"c8s-nri-image-policy-worker", "c8s-nri-image-policy-cds"} {
			ds := renderedDaemonSet(t, out, name)
			names := containerNames(ds.Spec.Template.Spec.InitContainers)
			prepIdx, installIdx := slices.Index(names, "containerd-prep"), slices.Index(names, "install")
			if prepIdx < 0 {
				t.Fatalf("rke2: %s missing containerd-prep initContainer; have %v", name, names)
			}
			// initContainers run in order: prep must precede install.
			if prepIdx > installIdx {
				t.Fatalf("%s: containerd-prep must run before install; initContainers=%v", name, names)
			}
			env := initContainerEnv(t, ds, "containerd-prep")
			if got := env["HOST_CONTAINERD_DIR"]; got != "/var/lib/rancher/rke2/agent/etc/containerd" {
				t.Errorf("%s HOST_CONTAINERD_DIR = %q, want the rke2 containerd dir", name, got)
			}
		}
	})

	t.Run("k8s", func(t *testing.T) {
		out, err := helmTemplate(t, "--set-string", "nriImagePolicy.distro=k8s")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		for _, name := range []string{"c8s-nri-image-policy-worker", "c8s-nri-image-policy-cds"} {
			ds := renderedDaemonSet(t, out, name)
			if _, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "containerd-prep"); ok {
				t.Fatalf("k8s: %s must not carry a containerd-prep initContainer", name)
			}
		}
	})
}

// initContainerEnv returns the env name->value map of a DaemonSet init container.
func initContainerEnv(t *testing.T, ds appsv1.DaemonSet, name string) map[string]string {
	t.Helper()
	for _, c := range ds.Spec.Template.Spec.InitContainers {
		if c.Name != name {
			continue
		}
		env := make(map[string]string, len(c.Env))
		for _, e := range c.Env {
			env[e.Name] = e.Value
		}
		return env
	}
	t.Fatalf("DaemonSet has no init container %q", name)
	return nil
}

// hostPathVolume returns the hostPath of the named volume on a DaemonSet.
func hostPathVolume(t *testing.T, ds appsv1.DaemonSet, name string) string {
	t.Helper()
	for _, v := range ds.Spec.Template.Spec.Volumes {
		if v.Name == name {
			if v.HostPath == nil {
				t.Fatalf("DaemonSet volume %q is not a hostPath volume", name)
			}
			return v.HostPath.Path
		}
	}
	t.Fatalf("DaemonSet has no volume %q", name)
	return ""
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
		"--set", "attestationApi.image.tag=dev",
		"--set", "cds.image.tag=dev",
		"--set", "ratlsMesh.image.tag=dev",
		"--set", "teeProxy.image.tag=dev",
		"--set", "nriImagePolicy.image.tag=dev",
		"--set", "nriImagePolicy.image.digest=sha256:aaaa000000000000000000000000000000000000000000000000000000000000",
		"--set", "cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000001",
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

func renderedMutatingWebhookNames(t *testing.T, manifest string) []string {
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
		names := make([]string, 0, len(cfg.Webhooks))
		for _, hook := range cfg.Webhooks {
			names = append(names, hook.Name)
		}
		return names
	}
	t.Fatalf("rendered manifest missing MutatingWebhookConfiguration\n%s", manifest)
	return nil
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

// TestChartCDSIsInMemorySingleton locks the two invariants the in-memory mesh
// CA depends on: the Deployment is a single replica (a second would mint a
// divergent trust root) and is annotated inMemory (the CA key never lands in a
// Secret/PVC). The cds component's presence is covered by
// TestChartDefaultRendersReplacementStack.
func TestChartCDSIsInMemorySingleton(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dep := renderedDeployment(t, out, "c8s-cds")
	if got := dep.Spec.Template.Annotations["confidential.ai/trust-root-mode"]; got != "inMemory" {
		t.Fatalf("cds Deployment trust-root-mode annotation = %q, want inMemory", got)
	}
	if got := *dep.Spec.Replicas; got != 1 {
		t.Fatalf("cds replicas = %d, want 1 (in-memory CA singleton)", got)
	}
}

// TestChartPointsClientsAtCDS proves the operator-injected get-cert and the
// ratls-mesh daemonset both resolve their single --cds-url to the cds Service,
// and the mesh runs in cds cert-mode — this locks that wiring.
func TestChartPointsClientsAtCDS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	const wantURL = "https://c8s-cds.c8s-system.svc:8443"

	operatorArgs := renderedOperatorArgs(t, out)
	assertContainerHasArg(t, "operator", operatorArgs, "--cds-url="+wantURL)

	meshArgs := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
	if got, ok := containerArgValue(meshArgs, "--cds-url"); !ok || got != wantURL {
		t.Fatalf("ratls-mesh --cds-url = (%q, %v), want %q\nargs: %v", got, ok, wantURL, meshArgs)
	}
	if got, ok := containerArgValue(meshArgs, "--cert-mode"); !ok || got != "cds" {
		t.Fatalf("ratls-mesh --cert-mode = (%q, %v), want cds\nargs: %v", got, ok, meshArgs)
	}
}

// TestChartCDSWiresInProcessTrustRoot confirms the flag set: the in-memory CA
// (no Secret/ca-cert flag), the whitelist DB, and the in-process JWKS (no
// --jwks-url, since signing happens in the same binary).
func TestChartCDSWiresInProcessTrustRoot(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	for _, want := range []string{
		"--attestation-api-url=http://c8s-attestation-api.c8s-system.svc:8400",
		"--whitelist-db=/data/whitelist.db",
		"--ca-common-name=c8s Mesh CA",
		"--ca-cert-validity=8760h",
	} {
		assertContainerHasArg(t, "cds", args, want)
	}
}

// TestChartCDSServesRATLS confirms the cds container renders with a non-empty
// --ratls-platform by default, i.e. RA-TLS serving is ON. An empty platform
// makes cds serve /attest, /sign-csr, and /attest-key over plaintext HTTP,
// collapsing the H1 bootstrap-channel MITM defence — a regression this guards.
func TestChartCDSServesRATLS(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	// Default cds.ratlsPlatform is snp; an empty value would render
	// "--ratls-platform=" and serve plaintext. Assert the exact default token.
	assertContainerHasArg(t, "cds", args, "--ratls-platform=snp")
}

// TestChartCDSDnsSanPatternAcceptsAnyNamespace pins the always-present
// in-cluster --dns-san-pattern and the identities it admits: CDS full-matches
// the regex (issuer.fullRegexMatch), so it must sign any
// <service>.<namespace>.svc (workloads live in their own namespaces, not just
// the release namespace) while still rejecting SANs that are not in-cluster
// Service DNS names. This pattern is emitted by the chart unconditionally, so a
// per-cluster public hostname (cds.dnsSanPatterns) only ever adds to it.
func TestChartCDSDnsSanPatternAcceptsAnyNamespace(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	const wantArg = "--dns-san-pattern=^[a-z0-9-]+[.][a-z0-9-]+[.]svc$"
	assertContainerHasArg(t, "cds", args, wantArg)

	re := regexp.MustCompile(strings.TrimPrefix(wantArg, "--dns-san-pattern="))
	fullMatch := func(s string) bool {
		loc := re.FindStringIndex(s)
		return loc != nil && loc[0] == 0 && loc[1] == len(s)
	}
	for _, san := range []string{
		"c8s-tls-lb.c8s-system.svc",
		"c8s-tee-proxy.c8s-system.svc",
		"ratls-mesh.c8s-system.svc",
		"acme-vllm-router-service.vllm.svc",
		"acme-vllm-acme-opt-125m-engine-service.vllm.svc",
	} {
		if !fullMatch(san) {
			t.Fatalf("default dns-san-pattern should accept in-cluster SAN %q", san)
		}
	}
	for _, san := range []string{
		"evil.example.com",                    // not a .svc name
		"svc.cluster.local",                   // wrong shape
		"a.b.c.svc",                           // more than <name>.<ns>
		"tls-lb.c8s-system.svc.cluster.local", // trailing labels
	} {
		if fullMatch(san) {
			t.Fatalf("default dns-san-pattern should reject non-Service SAN %q", san)
		}
	}
}

// TestChartCDSDnsSanPatternsAppendPublicHostname proves that adding a public
// hostname via cds.dnsSanPatterns (the per-cluster ingress override that broke
// the mesh before this fix) leaves the always-present in-cluster pattern
// intact, so CDS renders both --dns-san-pattern args and both the public
// hostname and the mesh Service SANs validate.
func TestChartCDSDnsSanPatternsAppendPublicHostname(t *testing.T) {
	// helm --set strips backslashes, so use a literal pattern that needs no
	// escaping to prove plumbing without the assertion fighting --set parsing.
	const public = "confidential-gke-lunal-dev"
	out, err := helmTemplate(t, "--set", "cds.dnsSanPatterns[0]="+public)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerHasArg(t, "cds", args, "--dns-san-pattern=^[a-z0-9-]+[.][a-z0-9-]+[.]svc$")
	assertContainerHasArg(t, "cds", args, "--dns-san-pattern="+public)
}

// TestChartCertDependentPodStrategies pins each cert-dependent pod's rollout
// strategy to its storage constraint: tls-lb has no PVC so it surges (new
// cert-holding pod Ready before the old one retires, no serving gap), while
// tee-proxy mounts a RWO autocert PVC and must stay Recreate — surge would
// deadlock two pods on Multi-Attach. get-cert's in-process retry covers
// tee-proxy's brief restart gap.
func TestChartCertDependentPodStrategies(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	// tls-lb: surge, no gap.
	tlsLB := renderedDeployment(t, out, "c8s-tls-lb")
	if tlsLB.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
		t.Errorf("c8s-tls-lb strategy = %q, want RollingUpdate", tlsLB.Spec.Strategy.Type)
	}
	if ru := tlsLB.Spec.Strategy.RollingUpdate; ru == nil ||
		ru.MaxUnavailable == nil || ru.MaxUnavailable.IntValue() != 0 ||
		ru.MaxSurge == nil || ru.MaxSurge.IntValue() != 1 {
		t.Errorf("c8s-tls-lb should surge (maxSurge=1, maxUnavailable=0), got %+v", ru)
	}

	// tee-proxy: Recreate, because of its RWO autocert PVC.
	teeProxy := renderedDeployment(t, out, "c8s-tee-proxy")
	if teeProxy.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Errorf("c8s-tee-proxy strategy = %q, want Recreate (RWO autocert PVC forbids two concurrent pods)", teeProxy.Spec.Strategy.Type)
	}
}

// TestChartGetCertInitRetriesInProcess proves the injected init get-cert
// container retries CDS in-process (--initial-retry-timeout) instead of exiting
// into kubelet CrashLoopBackOff on a transient CDS/mesh outage during a roll.
func TestChartGetCertInitRetriesInProcess(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	inits := renderedDeploymentInitContainers(t, out, "c8s-tee-proxy")
	var initCert *corev1.Container
	for i := range inits {
		if inits[i].Name == "c8s-init-cert" {
			initCert = &inits[i]
		}
	}
	if initCert == nil {
		t.Fatalf("tee-proxy has no c8s-init-cert init container\n%s", out)
	}
	assertContainerHasArg(t, "c8s-init-cert", initCert.Args, "--initial-retry-timeout=2m")
}

// TestChartCDSMeasurementsPlumbFlatAllowlist proves the flat cds.measurements
// list drives --measurements.
func TestChartCDSMeasurementsPlumbFlatAllowlist(t *testing.T) {
	const measurement = "0011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566ff"
	out, err := helmTemplate(t, "--set", "cds.measurements[0]="+measurement)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerHasArg(t, "cds", args, "--measurements="+measurement)
}

// TestChartCDSHandoffEnabledWiresMeasurements confirms handoff plumbs the flat
// allowlist into --handoff-measurements (cds is its own EAR issuer, so there is
// no external URL to wire).
func TestChartCDSHandoffEnabledWiresMeasurements(t *testing.T) {
	const measurement = "0011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566ff"
	out, err := helmTemplate(t,
		"--set", "cds.handoff.enabled=true",
		"--set", "cds.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerHasArg(t, "cds", args, "--handoff-measurements="+measurement)
}

// TestChartCDSHandoffDisabledOmitsFlag is the negative: with handoff off
// (default) the bootstrap flag MUST be absent, or cds would register /handoff
// when it shouldn't.
func TestChartCDSHandoffDisabledOmitsFlag(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerNoArgPrefix(t, "cds", args, "--handoff-measurements=")
}

// TestChartCDSHandoffEnabledFailsWithoutMeasurements locks the chart-time
// guard: handoff with an empty allowlist would register /handoff and 403 every
// caller — caught at template time, not at scale-up.
func TestChartCDSHandoffEnabledFailsWithoutMeasurements(t *testing.T) {
	out, err := helmTemplate(t, "--set", "cds.handoff.enabled=true")
	if err == nil {
		t.Fatalf("helm template succeeded with cds handoff enabled but no cds.measurements; output=%s", out)
	}
	if got := parseValidationErrorKind(out); got != "cds_handoff_measurements" {
		t.Fatalf("validation kind = %q, want cds_handoff_measurements; output=%s", got, out)
	}
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

type nriRuntimeConfig struct {
	Whitelist struct {
		Pull struct {
			URL               string   `yaml:"url"`
			Interval          string   `yaml:"interval"`
			Timeout           string   `yaml:"timeout"`
			AttestationApiURL string   `yaml:"attestation_api_url"`
			CDSMeasurements   []string `yaml:"cds_measurements"`
		} `yaml:"pull"`
		Push struct {
			PersistPath string `yaml:"persist_path"`
		} `yaml:"push"`
	} `yaml:"whitelist"`
}

func renderedNRIBootConfig(t *testing.T, manifest, daemonSetName string) nriRuntimeConfig {
	t.Helper()
	ds := renderedDaemonSet(t, manifest, daemonSetName)
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	raw := extractHeredoc(t, script, "IMAGE_POLICY_EOF")
	var cfg nriRuntimeConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("decode %s boot config: %v\n%s", daemonSetName, err, raw)
	}
	return cfg
}

func extractHeredoc(t *testing.T, script, marker string) string {
	t.Helper()
	startMarker := "<<'" + marker + "'\n"
	start := strings.Index(script, startMarker)
	if start < 0 {
		t.Fatalf("script missing heredoc start marker %q\n%s", marker, script)
	}
	bodyStart := start + len(startMarker)
	end := strings.Index(script[bodyStart:], "\n"+marker)
	if end < 0 {
		t.Fatalf("script missing heredoc end marker %q\n%s", marker, script)
	}
	return script[bodyStart : bodyStart+end]
}

func renderedConfigMap(t *testing.T, manifest, name string) corev1.ConfigMap {
	t.Helper()
	var cm corev1.ConfigMap
	if !findDoc(t, manifest, "ConfigMap", name, &cm) {
		t.Fatalf("rendered manifest missing ConfigMap %q\n%s", name, manifest)
	}
	return cm
}

func renderedService(t *testing.T, manifest, name string) corev1.Service {
	t.Helper()
	var svc corev1.Service
	if !findDoc(t, manifest, "Service", name, &svc) {
		t.Fatalf("rendered manifest missing Service %q\n%s", name, manifest)
	}
	return svc
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

// helmTemplateTLSLB renders the tls-lb component from the parent c8s chart in
// isolation: siblings are disabled and every caller-supplied --set/--set-string
// path is prefixed with tlsLb. so the existing subchart-relative test values
// (upstream.*, routes[*], nginx.*) keep working after the hoist. The release is
// named "c8s" so tls-lb.fullname resolves to c8s-tls-lb, matching the resource
// names the parent-chart tls-lb tests already assert. upstream.address is
// pinned to the standalone subchart's old default (vllm:8000) so the
// default-backend assertions remain a meaningful fixture rather than the
// parent's c8s-tee-proxy:80 wiring.
func helmTemplateTLSLB(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	base := []string{
		"template", "c8s", "c8s",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "attestationApi.image.tag=dev",
		"--set", "cds.image.tag=dev",
		"--set", "ratlsMesh.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "teeProxy.enabled=false",
		"--set-string", "tlsLb.upstream.address=vllm:8000",
		// Plain-HTTP upstream baseline for the tls-lb subchart tests; the
		// chart default targets the tee-proxy over https, but this harness
		// points at a bare vllm address. Tests that exercise https set it.
		"--set", "tlsLb.upstream.protocol=http",
		"--set", "tlsLb.nginx.image.tag=dev",
		"--show-only", "templates/tls-lb-configmap.yaml",
		"--show-only", "templates/tls-lb-deployment.yaml",
	}
	cmd := exec.Command("helm", append(base, prefixTLSLBSetArgs(args)...)...)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// prefixTLSLBSetArgs rewrites the value path of each --set/--set-string pair to
// live under the parent chart's tlsLb key, leaving the value (right of '=')
// untouched.
func prefixTLSLBSetArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i+1 < len(out); i++ {
		if out[i] != "--set" && out[i] != "--set-string" {
			continue
		}
		out[i+1] = "tlsLb." + out[i+1]
		i++
	}
	return out
}

// Example_tlsLBConfig renders the tls-lb ConfigMap for a representative route
// set — one plaintext HTTP backend (/whitelist) and one RA-TLS-verified HTTPS
// backend (/tenant/) — and prints the generated nginx.conf. It doubles as a
// golden test of templates/configmap.yaml: a template edit that changes the
// rendered config must be reflected in the Output block, so the full config
// diff surfaces in review. helm is required, as it is for every test in this
// package; without it the render errors and the example fails.
func Example_tlsLBConfig() {
	fmt.Print(renderExampleTLSLBNginxConf())
	// Output:
	// worker_processes auto;
	// error_log /var/log/nginx/error.log warn;
	// pid /tmp/nginx.pid;
	//
	// events {
	//     worker_connections 1024;
	// }
	//
	// http {
	//     include /etc/nginx/mime.types;
	//     default_type application/octet-stream;
	//
	//     log_format main '$remote_addr - $remote_user [$time_local] "$request" '
	//                     '$status $body_bytes_sent "$http_referer" '
	//                     '"$http_user_agent"';
	//     access_log /var/log/nginx/access.log main;
	//
	//     sendfile on;
	//     keepalive_timeout 65;
	//
	//     upstream backend {
	//         server vllm:8000;
	//     }
	//     upstream route_0 {
	//         server c8s-cds.c8s-system.svc:8443;
	//     }
	//     upstream route_1 {
	//         server tenant-router.c8s-system.svc:8080;
	//     }
	//     server {
	//         listen 8443 ssl;
	//         server_name "c8s-tls-lb.c8s-system.svc";
	//
	//         ssl_certificate     /tls/cert.pem;
	//         ssl_certificate_key /tls/key.pem;
	//
	//         ssl_protocols TLSv1.2 TLSv1.3;
	//         ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
	//         ssl_prefer_server_ciphers on;
	//         ssl_session_cache shared:SSL:10m;
	//         ssl_session_timeout 1d;
	//
	//         # Large buffers for upstream responses that include TEE attestation headers (~8KB).
	//         proxy_buffer_size 16k;
	//         proxy_buffers 4 16k;
	//         # Route: /whitelist -> http://c8s-cds.c8s-system.svc:8443
	//         location = /whitelist {
	//             proxy_pass http://route_0;
	//             proxy_set_header Host $host;
	//             proxy_set_header X-Real-IP $remote_addr;
	//             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	//             proxy_set_header X-Forwarded-Proto $scheme;
	//         }
	//         # Route: /tenant/ -> https://tenant-router.c8s-system.svc:8080
	//         location /tenant/ {
	//
	//             proxy_ssl_server_name on;
	//             proxy_ssl_name tenant-router.c8s-system.svc;
	//             proxy_ssl_verify on;
	//             proxy_ssl_verify_depth 2;
	//             proxy_ssl_trusted_certificate /tls/ca.pem;
	//             proxy_pass https://route_1;
	//             proxy_set_header Host $host;
	//             proxy_set_header X-Real-IP $remote_addr;
	//             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	//             proxy_set_header X-Forwarded-Proto $scheme;
	//         }
	//         location / {
	//             proxy_pass http://backend;
	//             proxy_set_header Host $host;
	//             proxy_set_header X-Real-IP $remote_addr;
	//             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	//             proxy_set_header X-Forwarded-Proto $scheme;
	//         }
	//
	//         location /healthz {
	//             access_log off;
	//             return 200 "ok\n";
	//             add_header Content-Type text/plain;
	//         }
	//     }
	// }
	//
}

// containerVolumeMount returns the named volume mount from a container
// (read-only state checked separately by the caller).
func containerVolumeMount(c corev1.Container, name string) (corev1.VolumeMount, bool) {
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			return m, true
		}
	}
	return corev1.VolumeMount{}, false
}

func podVolume(spec corev1.PodSpec, name string) (corev1.Volume, bool) {
	for _, v := range spec.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return corev1.Volume{}, false
}

// TestChartSeedsCDSWhitelistFromFloor proves the single authoritative floor
// (nriImagePolicy.bootstrapWhitelist.digests) plus the CDS image self-entry are
// rendered into CDS's --whitelist-seed ConfigMap, so CDS's served /whitelist is
// non-empty on the first worker pull. Decoded with the same typed Whitelist
// shape CDS parses, not substring-matched.
func TestChartSeedsCDSWhitelistFromFloor(t *testing.T) {
	const floorDigest = "sha256:abcdef0000000000000000000000000000000000000000000000000000000000"
	out, err := helmTemplate(t,
		"--set-string", "nriImagePolicy.bootstrapWhitelist.digests."+floorDigest+"=ghcr.io/x/coredns:v1",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cm := renderedConfigMap(t, out, "c8s-cds-whitelist-seed")
	raw, ok := cm.Data["whitelist-seed.json"]
	if !ok {
		t.Fatalf("seed ConfigMap missing whitelist-seed.json key: %v", cm.Data)
	}

	seed, err := pkgwhitelist.ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("seed JSON does not parse as a Whitelist (CDS would fail closed): %v\n%s", err, raw)
	}

	// The floor digest the operator supplied.
	if got := seed.Digests[floorDigest]; got != "ghcr.io/x/coredns:v1" {
		t.Errorf("seed floor digest = %q, want ghcr.io/x/coredns:v1\nseed: %v", got, seed.Digests)
	}
	// The CDS self-entry, derived from cds.image (set by the test harness to
	// digest ...0001); the reference is repository@digest.
	const cdsDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	const cdsRef = "ghcr.io/lunal-dev/cds@" + cdsDigest
	if got := seed.Digests[cdsDigest]; got != cdsRef {
		t.Errorf("seed CDS self-entry = %q, want %q\nseed: %v", got, cdsRef, seed.Digests)
	}
}

// TestChartDerivesComponentDigestsIntoWhitelist proves that when the c8s
// component images are digest-pinned, each is auto-derived into the NRI
// whitelist seed with a repo@digest reference matching the rendered pod image —
// so a digest-pinned install self-allows the c8s components it deploys (#51).
func TestChartDerivesComponentDigestsIntoWhitelist(t *testing.T) {
	const (
		opD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a1"
		asD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a2"
		cdsD = "sha256:00000000000000000000000000000000000000000000000000000000000000a3"
		rmD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a4"
		nriD = "sha256:00000000000000000000000000000000000000000000000000000000000000a5"
		tpD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a6"
	)
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.bootstrapWhitelist.deriveComponents=true",
		"--set-string", "image.digest="+opD,
		"--set-string", "attestationApi.image.digest="+asD,
		"--set-string", "cds.image.digest="+cdsD,
		"--set-string", "ratlsMesh.image.digest="+rmD,
		"--set-string", "nriImagePolicy.image.digest="+nriD,
		"--set-string", "teeProxy.image.digest="+tpD,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cm := renderedConfigMap(t, out, "c8s-cds-whitelist-seed")
	seed, err := pkgwhitelist.ParseJSON([]byte(cm.Data["whitelist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["whitelist-seed.json"])
	}

	// Each derived entry's reference must be repo@digest for the image the chart
	// actually deploys (#51: refs match the rendered pod images).
	want := map[string]string{
		opD:  "ghcr.io/lunal-dev/c8s-operator@" + opD,
		asD:  "ghcr.io/lunal-dev/attestation-api@" + asD,
		cdsD: "ghcr.io/lunal-dev/cds@" + cdsD,
		rmD:  "ghcr.io/lunal-dev/ratls-mesh@" + rmD,
		nriD: "ghcr.io/lunal-dev/nri-image-policy@" + nriD,
		tpD:  "ghcr.io/lunal-dev/tee-proxy@" + tpD,
	}
	for digest, ref := range want {
		if got := seed.Digests[digest]; got != ref {
			t.Errorf("derived entry %s = %q, want %q\nseed: %v", digest, got, ref, seed.Digests)
		}
	}

	// The same derived floor must reach the worker plugin's always_allow,
	// decoded as typed config (not substring-matched).
	worker := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	for digest, ref := range want {
		if got := worker.Whitelist.AlwaysAllow[digest]; got != ref {
			t.Errorf("worker always_allow[%s] = %q, want %q\nalways_allow: %v", digest, got, ref, worker.Whitelist.AlwaysAllow)
		}
	}
}

// installerBootConfig is a typed view of the image-policy.yaml the installer
// writes. It mirrors the fields of the plugin's own config
// (internal/cmds/nri-image-policy/config.go, which is unexported) needed by the
// chart tests, so assertions are against typed fields rather than substrings.
type installerBootConfig struct {
	Whitelist struct {
		AlwaysAllow map[string]string `yaml:"always_allow"`
		Pull        struct {
			URL string `yaml:"url"`
		} `yaml:"pull"`
		Push struct {
			PersistPath string `yaml:"persist_path"`
		} `yaml:"push"`
	} `yaml:"whitelist"`
	Policy struct {
		Mode string `yaml:"mode"`
	} `yaml:"policy"`
}

// bootConfigHeredocRE captures the image-policy.yaml body the installer writes
// via a `write_file ... <<'IMAGE_POLICY_EOF' ... IMAGE_POLICY_EOF` heredoc.
var bootConfigHeredocRE = regexp.MustCompile(`(?s)<<'IMAGE_POLICY_EOF'\n(.*?)\nIMAGE_POLICY_EOF`)

// bootConfigFromInstaller decodes the image-policy.yaml an installer DaemonSet
// writes into a typed installerBootConfig. It uses gopkg.in/yaml.v3 — the same
// library the plugin's loadConfig uses — which (unlike sigs.k8s.io/yaml's JSON
// path) rejects the duplicate mapping keys that would crash the plugin at
// startup. (KnownFields is intentionally NOT set: the goal is duplicate-key
// detection plus typed field access, not mirroring the plugin's full schema.)
func bootConfigFromInstaller(t *testing.T, manifest, dsName string) installerBootConfig {
	t.Helper()
	ds := renderedDaemonSet(t, manifest, dsName)
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	m := bootConfigHeredocRE.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("install script for %s has no IMAGE_POLICY_EOF heredoc\n%s", dsName, script)
	}
	var cfg installerBootConfig
	if err := yaml.Unmarshal([]byte(m[1]), &cfg); err != nil {
		t.Fatalf("plugin would reject its boot config for %s (yaml.v3): %v\n%s", dsName, err, m[1])
	}
	return cfg
}

// TestChartBootConfigParsesAsPluginYAML guards the regression where the
// installer self-image was emitted both explicitly and via the derived floor,
// producing a duplicate always_allow key. yaml.v3 (the plugin's loader) rejects
// duplicate keys, so the plugin would crash-loop. Decode each archetype's boot
// config exactly as the plugin does, and assert the archetype-specific mode.
func TestChartBootConfigParsesAsPluginYAML(t *testing.T) {
	out, err := helmTemplate(t,
		// deriveComponents on (and a second component digest) so the installer
		// image appears in always_allow both explicitly and via derivation —
		// the exact shape of the duplicate-key regression this guards.
		"--set", "nriImagePolicy.bootstrapWhitelist.deriveComponents=true",
		"--set-string", "cds.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000c5",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// Worker pulls from CDS; the CDS-node accepts pushes. Asserting the
	// mutually-exclusive field per archetype confirms the typed decode landed
	// on the right document, not just that some YAML parsed.
	if wl := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Whitelist; wl.Pull.URL == "" || wl.Push.PersistPath != "" {
		t.Errorf("worker boot config should configure pull, not push: pull.url=%q push.persist_path=%q", wl.Pull.URL, wl.Push.PersistPath)
	}
	if wl := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-cds").Whitelist; wl.Push.PersistPath == "" || wl.Pull.URL != "" {
		t.Errorf("cds boot config should configure push, not pull: pull.url=%q push.persist_path=%q", wl.Pull.URL, wl.Push.PersistPath)
	}
}

// A fleet-supplied bootstrapWhitelist.digests entry must override a derived
// entry for the same sha256 (fleet values win).
func TestChartFleetWhitelistOverridesDerived(t *testing.T) {
	const cdsD = "sha256:00000000000000000000000000000000000000000000000000000000000000a3"
	out, err := helmTemplate(t,
		// deriveComponents on so cds.image.digest produces a derived entry for
		// the fleet `digests` value to override.
		"--set", "nriImagePolicy.bootstrapWhitelist.deriveComponents=true",
		"--set-string", "cds.image.digest="+cdsD,
		"--set-string", "nriImagePolicy.bootstrapWhitelist.digests."+cdsD+"=mirror.local/cds@"+cdsD,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-cds-whitelist-seed")
	seed, err := pkgwhitelist.ParseJSON([]byte(cm.Data["whitelist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v", err)
	}
	if got := seed.Digests[cdsD]; got != "mirror.local/cds@"+cdsD {
		t.Errorf("fleet override lost: %s = %q, want mirror.local/cds@%s\nseed: %v", cdsD, got, cdsD, seed.Digests)
	}
}

// deriveComponents is OFF by default (a demo convenience, like
// --resolve-digests): the seed carries only the CDS push-hook self-entry and
// operator-supplied digests, not the auto-derived component images. Covers both
// the default (unset) and an explicit =false.
func TestChartDeriveComponentsDefaultsOff(t *testing.T) {
	const opD = "sha256:00000000000000000000000000000000000000000000000000000000000000a1"
	const cdsDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"default unset", []string{"--set-string", "image.digest=" + opD}},
		{"explicit false", []string{"--set-string", "image.digest=" + opD, "--set", "nriImagePolicy.bootstrapWhitelist.deriveComponents=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cm := renderedConfigMap(t, out, "c8s-cds-whitelist-seed")
			seed, err := pkgwhitelist.ParseJSON([]byte(cm.Data["whitelist-seed.json"]))
			if err != nil {
				t.Fatalf("seed JSON does not parse: %v", err)
			}
			if _, ok := seed.Digests[opD]; ok {
				t.Errorf("operator digest derived without deriveComponents: %v", seed.Digests)
			}
			// The CDS self-entry (push-hook) is always present, independent of derivation.
			if _, ok := seed.Digests[cdsDigest]; !ok {
				t.Errorf("CDS push-hook self-entry missing: %v", seed.Digests)
			}
		})
	}
}

// TestChartWiresCDSWhitelistSeedFlagAndVolume proves the CDS container receives
// --whitelist-seed pointing at a read-only mount of the seed ConfigMap. The CDS
// pod runs readOnlyRootFilesystem, so the seed must be a read-only volume, not a
// writable path.
func TestChartWiresCDSWhitelistSeedFlagAndVolume(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	assertContainerHasArg(t, "cds", cds.Args, "--whitelist-seed=/etc/cds/whitelist-seed.json")

	mount, ok := containerVolumeMount(cds, "whitelist-seed")
	if !ok {
		t.Fatalf("cds container missing whitelist-seed volume mount; mounts=%v", cds.VolumeMounts)
	}
	if mount.MountPath != "/etc/cds" {
		t.Errorf("whitelist-seed mountPath = %q, want /etc/cds", mount.MountPath)
	}
	if !mount.ReadOnly {
		t.Errorf("whitelist-seed mount must be readOnly (cds has readOnlyRootFilesystem)")
	}

	vol, ok := podVolume(renderedDeployment(t, out, "c8s-cds").Spec.Template.Spec, "whitelist-seed")
	if !ok {
		t.Fatalf("cds pod missing whitelist-seed volume")
	}
	if vol.ConfigMap == nil || vol.ConfigMap.Name != "c8s-cds-whitelist-seed" {
		t.Errorf("whitelist-seed volume should source ConfigMap c8s-cds-whitelist-seed; got %+v", vol.ConfigMap)
	}
}

// With nriImagePolicy disabled there is no floor to seed and no image-policy to
// admit CDS, so the seed wiring must drop out entirely.
func TestChartOmitsCDSSeedWhenImagePolicyDisabled(t *testing.T) {
	out, err := helmTemplate(t, "--set", "nriImagePolicy.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "ConfigMap", "c8s-cds-whitelist-seed") {
		t.Fatalf("seed ConfigMap should not render when nriImagePolicy is disabled")
	}
	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	assertContainerNoArgPrefix(t, "cds", cds.Args, "--whitelist-seed")
}

// The CDS image must be admittable by digest in the floor/seed; without
// cds.image.digest the image policy would deny CDS on its own node. The chart
// fails the render with a structured marker rather than shipping that deadlock.
func TestChartRejectsImagePolicyWithoutCDSDigest(t *testing.T) {
	out, err := helmTemplate(t, "--set-string", "cds.image.digest=")
	if err == nil {
		t.Fatalf("helm template succeeded without cds image digest, want guard failure\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "cds_image_digest" {
		t.Fatalf("validation error kind = %q, want cds_image_digest\n%s", kind, out)
	}
}

// In fail-closed mode with deriveComponents off, a digest-pinned component
// whose digest is absent from bootstrapWhitelist.digests would be denied on its
// own node, so the chart fails the render. cds.image is exempt (always seeded).
func TestChartRejectsUncoveredComponentInFailClosed(t *testing.T) {
	const nriD = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"

	// Uncovered: nriImagePolicy.image is digest-pinned (by the harness) but not
	// in digests, deriveComponents off, fail-closed -> guard fires.
	out, err := helmTemplate(t, "--set", "nriImagePolicy.policy.mode=fail-closed")
	if err == nil {
		t.Fatalf("helm template succeeded with an uncovered component in fail-closed, want guard failure\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "uncovered_component_digest" {
		t.Fatalf("validation error kind = %q, want uncovered_component_digest\n%s", kind, out)
	}

	// Covered three ways: each must render.
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"audit mode is non-blocking", []string{"--set", "nriImagePolicy.policy.mode=audit"}},
		{"deriveComponents covers it", []string{"--set", "nriImagePolicy.policy.mode=fail-closed", "--set", "nriImagePolicy.bootstrapWhitelist.deriveComponents=true"}},
		{"digest listed in floor", []string{"--set", "nriImagePolicy.policy.mode=fail-closed", "--set-string", "nriImagePolicy.bootstrapWhitelist.digests." + nriD + "=ghcr.io/lunal-dev/nri-image-policy@" + nriD}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := helmTemplate(t, tc.args...); err != nil {
				t.Fatalf("helm template should render: %v\n%s", err, out)
			}
		})
	}
}

// golden stays gofmt-clean. Render errors are returned verbatim so the example
// fails loudly rather than masking a broken template.
func renderExampleTLSLBNginxConf() string {
	cmd := exec.Command("helm",
		"template", "c8s", "c8s",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "attestationApi.image.tag=dev",
		"--set", "cds.image.tag=dev",
		"--set", "ratlsMesh.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "teeProxy.enabled=false",
		"--set-string", "tlsLb.upstream.address=vllm:8000",
		"--set", "tlsLb.upstream.protocol=http",
		"--set", "tlsLb.nginx.image.tag=dev",
		"--set-string", "tlsLb.routes[0].path=/whitelist",
		"--set-string", "tlsLb.routes[0].match=exact",
		"--set-string", "tlsLb.routes[0].backend.address=c8s-cds.c8s-system.svc:8443",
		"--set-string", "tlsLb.routes[1].path=/tenant/",
		"--set-string", "tlsLb.routes[1].backend.address=tenant-router.c8s-system.svc:8080",
		"--set-string", "tlsLb.routes[1].backend.protocol=https",
		"--set", "tlsLb.routes[1].backend.tls.verify=true",
		"--show-only", "templates/tls-lb-configmap.yaml",
	)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("helm template failed: %v\n%s", err, out)
	}
	var cm corev1.ConfigMap
	if err := sigsyaml.Unmarshal(out, &cm); err != nil {
		return fmt.Sprintf("decode tls-lb ConfigMap: %v\n%s", err, out)
	}
	lines := strings.Split(cm.Data["nginx.conf"], "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.Join(lines, "\n")
}
