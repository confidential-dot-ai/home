package helmchart

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"gopkg.in/yaml.v3"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
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
		"app.kubernetes.io/name: tls-lb",
		"server_name c8s-tls-lb.c8s-system.svc;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("default chart missing %q\n%s", want, out)
		}
	}
	cert := tlsLBGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert,
		"get-cert",
		"--cds-url=https://c8s-cds.c8s-system.svc:8443",
		"--attestation-api-url=http://c8s-attestation-api.c8s-system.svc:8400",
		"--san=c8s-tls-lb.c8s-system.svc",
		"--out=/tls/cert.pem",
		"--key-out=/tls/key.pem",
		"--renew-interval=1h",
		"--reload-nginx=true",
		"--continue-on-initial-error",
	)
	if cert.RestartPolicy == nil || *cert.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("c8s-cert restartPolicy = %v, want Always (single long-lived sidecar so its pidns anchors shareProcessNamespace under kata)", cert.RestartPolicy)
	}
	if cert.StartupProbe == nil || cert.StartupProbe.Exec == nil {
		t.Fatalf("c8s-cert must expose a startupProbe so nginx waits for the initial cert; got %+v", cert.StartupProbe)
	}
	if got := strings.Join(cert.StartupProbe.Exec.Command, " "); !strings.Contains(got, "probe-file") || !strings.Contains(got, "/tls/cert.pem") {
		t.Fatalf("c8s-cert startupProbe command = %q, want `/c8s probe-file /tls/cert.pem` (distroless: no /bin/test available)", got)
	}
	if got := cert.SecurityContext.RunAsUser; got == nil || *got != 101 {
		t.Fatalf("c8s-cert runAsUser = %v, want 101", got)
	}
	args := renderedOperatorArgs(t, out)
	for _, want := range []string{
		"--get-cert-image=ghcr.io/confidential-dot-ai/c8s-operator:dev",
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
		// The release namespace must NOT be excluded: tls-lb egress to
		// workload pod IPs (headless-Service dials) needs mesh interception.
		{"--exclude-source-namespaces", "kube-system"},
	} {
		if !argvContainsFlagValue(sync.Command, pair[0], pair[1]) {
			t.Errorf("iptables-sync command missing %s %s; command=%q", pair[0], pair[1], sync.Command)
		}
	}
	if slices.Contains(sync.Command, "--pod-cidrs") {
		t.Errorf("iptables-sync must not require static --pod-cidrs; command=%q", sync.Command)
	}
	// The cw inbound guard is always on; its posture is the passthrough
	// allowlist, defaulting to DNS replies so get-cert can resolve.
	if !slices.Contains(sync.Command, "--cw-inbound-passthrough=udp:53,tcp:53") {
		t.Errorf("iptables-sync command missing --cw-inbound-passthrough=udp:53,tcp:53; command=%q", sync.Command)
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
			if strings.Contains(string(name), "confidential.ai/tpm") {
				t.Errorf("container %q requests local TPM resource %q by default", c.Name, name)
			}
		}
		for name := range c.Resources.Limits {
			if strings.Contains(string(name), "confidential.ai/tpm") {
				t.Errorf("container %q limits local TPM resource %q by default", c.Name, name)
			}
		}
	}

	if kinds := renderedKinds(t, out); kinds["NetworkPolicy"] > 0 {
		t.Errorf("ratls host routing must not render NetworkPolicy for hostNetwork pods; got %d", kinds["NetworkPolicy"])
	}
}

func TestChartCWInboundPassthrough(t *testing.T) {
	// An empty passthrough renders the strict fail-closed posture (no
	// exemptions), and the flag is present-but-empty so the manifest still
	// self-documents that the guard is on.
	out, err := helmTemplate(t, "--set", "ratlsMesh.cwInboundEnforcement.passthrough=[]")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	sync, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "iptables-sync")
	if !ok {
		t.Fatalf("iptables-sync init container missing; have %v", containerNames(ds.Spec.Template.Spec.InitContainers))
	}
	if !slices.Contains(sync.Command, "--cw-inbound-passthrough=") {
		t.Errorf("iptables-sync command missing empty --cw-inbound-passthrough=; command=%q", sync.Command)
	}

	// A custom passthrough list renders in order as proto:port,proto:port.
	out, err = helmTemplate(t,
		"--set", "ratlsMesh.cwInboundEnforcement.passthrough[0].protocol=udp",
		"--set", "ratlsMesh.cwInboundEnforcement.passthrough[0].sourcePort=53",
		"--set", "ratlsMesh.cwInboundEnforcement.passthrough[1].protocol=tcp",
		"--set", "ratlsMesh.cwInboundEnforcement.passthrough[1].sourcePort=8443",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds = findRATLSMeshDaemonSet(t, out)
	sync, _ = findContainer(ds.Spec.Template.Spec.InitContainers, "iptables-sync")
	if !slices.Contains(sync.Command, "--cw-inbound-passthrough=udp:53,tcp:8443") {
		t.Errorf("iptables-sync command missing --cw-inbound-passthrough=udp:53,tcp:8443; command=%q", sync.Command)
	}

	// A wrong-typed value (e.g. --set-string) fails loudly instead of silently
	// rendering strict drop-all, which would reproduce the DNS-resolution
	// outage this guard exists to prevent.
	out, err = helmTemplate(t, "--set-string", "ratlsMesh.cwInboundEnforcement.passthrough=udp:53")
	if err == nil {
		t.Fatalf("helm template succeeded on a string passthrough, want a fail\n%s", out)
	}
	if !strings.Contains(out, "must be a list") {
		t.Errorf("passthrough type error should name the fix; got %s", out)
	}

	// A malformed entry fails at render, not at daemon startup — a rendered
	// "udp:<nil>" would crash-loop the init container. The key prefix is elided
	// to pt for readability.
	const pt = "ratlsMesh.cwInboundEnforcement.passthrough"
	for _, bad := range [][]string{
		{"--set", pt + "[0].protocol=udp"},                                       // missing sourcePort
		{"--set", pt + "[0].protocol=sctp", "--set", pt + "[0].sourcePort=53"},   // bad protocol
		{"--set", pt + "[0].protocol=udp", "--set", pt + "[0].sourcePort=70000"}, // out-of-range port
	} {
		if out, err := helmTemplate(t, bad...); err == nil {
			t.Errorf("helm template succeeded on malformed passthrough entry %v, want a fail\n%s", bad, out)
		}
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

func namedContainerPort(c corev1.Container, portName string) (corev1.ContainerPort, bool) {
	for _, p := range c.Ports {
		if p.Name == portName {
			return p, true
		}
	}
	return corev1.ContainerPort{}, false
}

func containerHostPort(c corev1.Container, portName string) (int32, bool) {
	p, ok := namedContainerPort(c, portName)
	return p.HostPort, ok
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

// TestChartRATLSKubeVersionPinned guards the chart's Kubernetes floor
// against accidental relaxation. Two contracts pin it:
//   - native sidecars (SidecarContainers default-on from 1.29): with the
//     gate off, iptables-cleanup is invalid as a native sidecar, its preStop
//     cannot run, and the host leaks managed chains/ipsets across restarts;
//   - ValidatingAdmissionPolicy v1 (GA from 1.30): the chart ships two
//     default-on policies (deny-ratls-mesh-uid, cw-label-integrity), so a
//     pre-1.30 apply fails mid-install on unknown kinds anyway — the
//     kubeVersion constraint makes helm fail early and clearly instead.
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
	const want = ">=1.30.0-0"
	if chart.KubeVersion != want {
		t.Fatalf("c8s Chart.yaml kubeVersion = %q; want %q (native sidecars need k8s 1.29+, and the default-on ValidatingAdmissionPolicies need v1/GA from 1.30)", chart.KubeVersion, want)
	}
}

// nodeAffinityHasKey reports whether any required nodeAffinity matchExpression
// keys on the given label.
func nodeAffinityHasKey(ds appsv1.DaemonSet, key string) bool {
	aff := ds.Spec.Template.Spec.Affinity
	if aff == nil || aff.NodeAffinity == nil ||
		aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return false
	}
	for _, term := range aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if expr.Key == key {
				return true
			}
		}
	}
	return false
}

// The chart renders exactly one pull-mode installer DaemonSet, `-worker`, that
// targets every node — there is no CDS/worker partition. The old push archetype
// (a role=cds-pinned `-cds` installer) is gone; this guards against it coming
// back.
func TestChartNriInstallerRendersSinglePullDaemonSet(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-nri-image-policy-cds") {
		t.Error("no cds/push installer must render; only the pull-mode -worker DaemonSet exists")
	}
	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	if nodeAffinityHasKey(worker, "role") {
		t.Error("worker installer must not key on role; it targets every node")
	}
	if got, want := worker.Spec.Template.Labels["app.kubernetes.io/component"], "nri-installer-worker"; got != want {
		t.Errorf("worker installer pod component label = %q, want %q", got, want)
	}
}

// Single-node (empty cds.node.selector) renders the installer identically to
// the default (covered by TestChartNriInstallerRendersSinglePullDaemonSet);
// what's unique here is the CDS Deployment carrying no nodeSelector so it lands
// on the lone node.
func TestChartCDSDeploymentHasNoNodeSelectorUnderEmptySelector(t *testing.T) {
	out, err := helmTemplate(t, "--set", "cds.node.selector=null")
	if err != nil {
		t.Fatalf("helm template --set cds.node.selector=null: %v\n%s", err, out)
	}
	cdsDep := renderedDeployment(t, out, "c8s-cds")
	if len(cdsDep.Spec.Template.Spec.NodeSelector) != 0 {
		t.Errorf("cds Deployment must have no nodeSelector under single-node; got %v", cdsDep.Spec.Template.Spec.NodeSelector)
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

// envValue returns the value of the named env var on a container, or "" if it
// is absent (or set via valueFrom rather than a literal value).
func envValue(env []corev1.EnvVar, name string) string {
	for _, e := range env {
		if e.Name == name {
			return e.Value
		}
	}
	return ""
}

func containerNames(containers []corev1.Container) []string {
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		names = append(names, c.Name)
	}
	return names
}

// tlsLBGetCertContainer returns the named tls-lb get-cert init container
// (c8s-cert), failing if absent.
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

// TestChartRejectsOperatorKeysPath pins the path-vs-content guard: a
// cds.operatorKeys value that is a filesystem path (or any non-PEM string)
// must fail the render with an instructive message, not ship a ConfigMap CDS
// will refuse at startup.
func TestChartRejectsOperatorKeysPath(t *testing.T) {
	out, err := helmTemplate(t, "--set", "cds.operatorKeys=/home/user/public.pem")
	if err == nil {
		t.Fatalf("helm template succeeded, want operatorKeys content-guard failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "cds.operatorKeys must be the PEM content of the operator public-key bundle, not a file path — use `c8s install --operator-keys <file>`, `c8s render-values --operator-keys <file>`, or helm --set-file cds.operatorKeys=<file>")
}

func TestChartRendersOperatorKeysPEM(t *testing.T) {
	pemText := "-----BEGIN PUBLIC KEY-----\nMFkwfakefakefake\n-----END PUBLIC KEY-----\n"
	path := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(path, []byte(pemText), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	out, err := helmTemplate(t, "--set-file", "cds.operatorKeys="+path)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !strings.Contains(out, "operator-keys") || !strings.Contains(out, "BEGIN PUBLIC KEY") {
		t.Fatalf("rendered output missing the operator-keys ConfigMap with PEM content")
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

// TestChartWebhookOptsOutOfAKSAdmissionsEnforcer proves the AKS workaround:
// with attestationApi.cvmMode=aks (what `c8s install --cvm-mode aks` sets) the
// pod-injector MutatingWebhookConfiguration carries
// admissions.enforcer/disabled=true, so AKS's admissionsenforcer controller
// stops rewriting the webhook namespaceSelector and conflicting with helm
// re-applies. The default (baremetal) must NOT carry it — the annotation is
// pure AKS plumbing and shouldn't appear on other platforms. A user-set
// webhook.annotations value flows through alongside it.
func TestChartWebhookOptsOutOfAKSAdmissionsEnforcer(t *testing.T) {
	const annotation = "admissions.enforcer/disabled"

	// Default (baremetal): no AKS opt-out annotation.
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var def admissionregv1.MutatingWebhookConfiguration
	if !findDoc(t, out, "MutatingWebhookConfiguration", "c8s-pod-injector", &def) {
		t.Fatalf("default chart missing MutatingWebhookConfiguration c8s-pod-injector\n%s", out)
	}
	if _, ok := def.Annotations[annotation]; ok {
		t.Errorf("default (baremetal) webhook must not carry %s; got %v", annotation, def.Annotations)
	}

	// aks: opt-out annotation present and "true".
	out, err = helmTemplate(t, "--set-string", "attestationApi.cvmMode=aks")
	if err != nil {
		t.Fatalf("helm template --set attestationApi.cvmMode=aks: %v\n%s", err, out)
	}
	var aks admissionregv1.MutatingWebhookConfiguration
	if !findDoc(t, out, "MutatingWebhookConfiguration", "c8s-pod-injector", &aks) {
		t.Fatalf("aks chart missing MutatingWebhookConfiguration c8s-pod-injector\n%s", out)
	}
	if got := aks.Annotations[annotation]; got != "true" {
		t.Errorf("aks webhook %s = %q, want \"true\"; annotations=%v", annotation, got, aks.Annotations)
	}

	// A user-supplied annotation coexists with the automatic AKS opt-out.
	out, err = helmTemplate(t,
		"--set-string", "attestationApi.cvmMode=aks",
		"--set-string", "webhook.annotations.team=platform",
	)
	if err != nil {
		t.Fatalf("helm template with extra webhook annotation: %v\n%s", err, out)
	}
	var both admissionregv1.MutatingWebhookConfiguration
	if !findDoc(t, out, "MutatingWebhookConfiguration", "c8s-pod-injector", &both) {
		t.Fatalf("override chart missing MutatingWebhookConfiguration c8s-pod-injector\n%s", out)
	}
	if got := both.Annotations["team"]; got != "platform" {
		t.Errorf("user webhook.annotations.team = %q, want \"platform\"; annotations=%v", got, both.Annotations)
	}
	if got := both.Annotations[annotation]; got != "true" {
		t.Errorf("AKS opt-out must still apply alongside user annotations: %s = %q, want \"true\"", annotation, got)
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

func TestChartNRIImagePolicyUsesPullMode(t *testing.T) {
	const measurement = "abc1230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff"
	out, err := helmTemplate(t,
		"--set", "cds.measurements[0]="+measurement,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	workerCfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	if got, want := workerCfg.Allowlist.Pull.URL, "https://127.0.0.1:30808"; got != want {
		t.Fatalf("worker pull URL = %q, want %q", got, want)
	}
	if got, want := workerCfg.Allowlist.Pull.Interval, "30s"; got != want {
		t.Fatalf("worker pull interval = %q, want %q", got, want)
	}
	if got, want := workerCfg.Allowlist.Pull.AttestationApiURL, "http://localhost:30840"; got != want {
		t.Fatalf("runtime attestation-api URL = %q, want %q", got, want)
	}
	if want := []string{measurement}; !slices.Equal(workerCfg.Allowlist.Pull.CDSMeasurements, want) {
		t.Fatalf("worker CDS measurements = %v, want %v", workerCfg.Allowlist.Pull.CDSMeasurements, want)
	}
	// Pull-only: the boot config never carries a push block.
	if workerCfg.Allowlist.Push.PersistPath != "" {
		t.Fatalf("worker boot config has push persist path %q, want empty", workerCfg.Allowlist.Push.PersistPath)
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
	if got, want := cfg.Allowlist.Pull.AttestationApiURL, "http://localhost:31040"; got != want {
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

func TestChartRejectsPlaintextNRIAllowlist(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "nriImagePolicy.cds.url=http://c8s-cds.c8s-system.svc:8443",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want plaintext NRI allowlist failure\n%s", out)
	}
	assertHelmFailMessage(t, out, `nriImagePolicy.cds.url must start with https:// when nriImagePolicy.enabled=true (got "http://c8s-cds.c8s-system.svc:8443"): the host plugin must fetch the allowlist over RA-TLS`)
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

// A -f values file decodes ints as float64; helm renders float64 >= 1e6 as
// scientific notation (7000000 -> 7e+06), which is invalid in a numeric
// securityContext field and a type error in CEL. c8s.int must keep these plain
// integers. This drives the bug's actual path (a -f file, value >= 1e6), which
// --set does not reproduce.
func TestChartIntValuesFromValuesFileRenderPlain(t *testing.T) {
	dir := t.TempDir()
	vals := filepath.Join(dir, "vals.yaml")
	if err := os.WriteFile(vals, []byte(
		"ratlsMesh:\n  uid: 7000000\n"+
			"tlsLb:\n  nginx:\n    runAsUser: 7000000\n    runAsGroup: 7000000\n"+
			"webhook:\n  certVolume:\n    fsGroup: 1500000\n  getCert:\n    runAsUser: 2000000000\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplate(t, "-f", vals)
	if err != nil {
		t.Fatalf("helm template -f: %v\n%s", err, out)
	}
	// No value anywhere may render in scientific notation.
	if strings.Contains(out, "e+0") {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "e+0") {
				t.Errorf("scientific-notation int leaked: %q", strings.TrimSpace(line))
			}
		}
	}
	// Spot-check the plain-integer renders, including the CEL admission policy
	// (where int != double would be an uninstallable compile error).
	for _, want := range []string{
		"--cert-fs-group=1500000",
		"--get-cert-run-as-user=2000000000",
		"runAsUser: 7000000",
		"runAsUser != 7000000",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q", want)
		}
	}
}

// c8s.int must fail the render on a non-integer rather than silently coercing to
// 0 (sprig int64's fail-open behavior — 0 is root). Guards against a malformed
// hand-written -f.
func TestChartIntValueRejectsNonInteger(t *testing.T) {
	dir := t.TempDir()
	vals := filepath.Join(dir, "vals.yaml")
	if err := os.WriteFile(vals, []byte("webhook:\n  getCert:\n    runAsUser: notanumber\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplate(t, "-f", vals)
	if err == nil {
		t.Fatalf("expected render to fail on a non-integer runAsUser, got success:\n%s", out)
	}
	if !strings.Contains(out, "expected an integer") {
		t.Errorf("want 'expected an integer' error, got: %s", out)
	}
}

// TestChartAttestationApiPrivileged proves every cvmMode renders privileged:
// true. A hostPath device mount does not add a device-cgroup rule, so open() on
// the TEE device (/dev/sev-guest, /dev/tpm0) is EPERM from an unprivileged
// container regardless of SYS_RAWIO (cgroup v2 eBPF device controller); aks
// additionally gates the vTPM below the capability layer. TODO: revert to
// least-privilege once SNP attest goes through the TSM configfs report
// interface.
func TestChartAttestationApiPrivileged(t *testing.T) {
	for _, tc := range []struct {
		mode string
		// baremetal is the chart default, so render it via the no-arg path to
		// also guard that a plain install is privileged.
		useDefault bool
		// aks renders the privilege axis only — it must NOT also carry the
		// least-privilege capabilities map (the modes are either/or, not merged).
		noCapabilities bool
	}{
		{mode: "baremetal", useDefault: true},
		{mode: "node"},
		{mode: "gke"},
		{mode: "aks", noCapabilities: true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			var args []string
			if !tc.useDefault {
				args = []string{"--set", "attestationApi.cvmMode=" + tc.mode}
			}
			out, err := helmTemplate(t, args...)
			if err != nil {
				t.Fatalf("helm template (cvmMode=%s): %v\n%s", tc.mode, err, out)
			}
			c := renderedDaemonSetContainer(t, out, "c8s-attestation-api", "attestation-api")
			sc := c.SecurityContext
			if sc == nil || sc.Privileged == nil || !*sc.Privileged {
				t.Errorf("%s must be privileged for device access; got %+v", tc.mode, sc)
			}
			if tc.noCapabilities && sc != nil && sc.Capabilities != nil {
				t.Errorf("%s must not carry the least-privilege capabilities map; got %+v", tc.mode, sc.Capabilities)
			}
		})
	}
}

// TestChartAttestationApiInvalidCvmMode proves an unrecognized cvmMode fails
// the render loudly rather than silently falling through to least-privilege
// (which would fail closed at runtime on an AKS CVM).
func TestChartAttestationApiInvalidCvmMode(t *testing.T) {
	out, err := helmTemplate(t, "--set", "attestationApi.cvmMode=bogus")
	if err == nil {
		t.Fatalf("expected render to fail on invalid cvmMode; got success\n%s", out)
	}
	assertHelmFailMessage(t, out, `attestationApi.cvmMode must be one of baremetal, node, gke, aks (got "bogus")`)
}

func TestChartRendersManagedClusterKnobs(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "serviceAccount.imagePullSecrets[0].name=ghcr-secret",
		"--set", "attestationApi.cvmMode=aks",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !strings.Contains(out, "imagePullSecrets:\n- name: ghcr-secret") {
		t.Fatalf("render missing chart-wide imagePullSecrets\n%s", out)
	}
	// aks → privileged attestation-api (assert the two fields without pinning
	// the exact line spacing, which carries explanatory comments).
	for _, want := range []string{"privileged: true", "readOnlyRootFilesystem: true"} {
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
		"--set", "tlsLb.imagePullSecrets[0].name=lb-special",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// The global reaches a non-overriding component (ratls-mesh).
	rm := renderedDaemonSet(t, out, "c8s-ratls-mesh")
	if !hasPullSecret(rm.Spec.Template.Spec.ImagePullSecrets, "ghcr-pull") {
		t.Errorf("ratls-mesh missing global pull secret: %v", rm.Spec.Template.Spec.ImagePullSecrets)
	}
	// tlsLb's own value overrides the global.
	lb := renderedDeployment(t, out, "c8s-tls-lb")
	if hasPullSecret(lb.Spec.Template.Spec.ImagePullSecrets, "ghcr-pull") || !hasPullSecret(lb.Spec.Template.Spec.ImagePullSecrets, "lb-special") {
		t.Errorf("tls-lb should use its override, not the global: %v", lb.Spec.Template.Spec.ImagePullSecrets)
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
	out, err := helmTemplate(t, noUpstreamArgs(
		"--set-string", "tlsLb.publicTLS.secretName=tls-lb-public-tls",
		"--set-string", "tlsLb.publicTLS.mountPath=/edge-tls",
		"--set-string", "tlsLb.publicTLS.certKey=public.crt",
		"--set-string", "tlsLb.publicTLS.keyKey=public.key",
		"--set", "tlsLb.discovery.enabled=true",
		"--set-string", "tlsLb.upstream.address=my-backend.other-ns.svc:8443",
		"--set", "tlsLb.upstream.protocol=https",
		"--set", "tlsLb.upstream.tls.verify=true",
		"--set-string", "tlsLb.upstream.tls.serverName=my-backend.other-ns.svc.cluster.local",
	)...)
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
		"proxy_ssl_name my-backend.other-ns.svc.cluster.local;",
		"proxy_ssl_verify on;",
		"proxy_ssl_trusted_certificate /tls/cert.pem;",
		"proxy_pass https://$backend_addr;",
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
	cert := tlsLBGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert,
		"--discovery-out=/discovery/discovery.json",
		"--discovery-cds-cert-url=/.well-known/cds-cert.pem",
		"--discovery-public-tls-mode=webpki",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem",
		"--reload-watch=/edge-tls/public.crt",
		"--reload-watch=/edge-tls/public.key",
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

func TestChartRendersTLSLBAttestSidecar(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "tlsLb.attest.enabled=true",
		"--set", "tlsLb.attest.port=8800",
		"--set-string", "tlsLb.attest.generation=milan",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	// The cds-attest sidecar runs the operator multi-mode image with the
	// cds-attest subcommand, bound to loopback for nginx to proxy to.
	deployment := renderedDeployment(t, out, "c8s-tls-lb")
	sidecar := renderedDeploymentContainer(t, out, "c8s-tls-lb", "cds-attest")
	if len(sidecar.Args) == 0 || sidecar.Args[0] != "cds-attest" {
		t.Fatalf("cds-attest args = %v, want first arg 'cds-attest'", sidecar.Args)
	}
	joined := strings.Join(sidecar.Args, " ")
	for _, want := range []string{
		"--host=127.0.0.1",
		"--port=8800",
		"--generation=milan",
		"--attestation-api-url=http://",
		"--mesh-identity-cert-file=/tls/cert.pem",
		"--mesh-identity-key-file=/tls/key.pem",
		"--mesh-identity-ca-file=/tls/ca.pem",
		// The baseline mesh-wrapped upstream is a plain-HTTP workload upstream;
		// the mTLS args render only for an https upstream.
		"--upstream=http://c8s-infer.c8s-system.svc.cluster.local:8000",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("cds-attest args missing %q: %v", want, sidecar.Args)
		}
	}
	for _, banned := range []string{"--upstream-ca", "--upstream-cert", "--upstream-key", "--upstream-server-name"} {
		if strings.Contains(joined, banned) {
			t.Fatalf("cds-attest must not set %s for the default http upstream: %v", banned, sidecar.Args)
		}
	}
	// --cds-cert-file must NOT be set: nginx serves /.well-known/c8s/cds-cert.pem
	// statically (hot-reloaded), while the sidecar would embed a stale copy.
	if strings.Contains(joined, "--cds-cert-file") {
		t.Fatalf("cds-attest must not set --cds-cert-file (nginx serves it statically): %v", sidecar.Args)
	}
	// The sidecar must not mount the mesh-CA for the default cert.pem trust path.
	if _, ok := containerVolumeMount(sidecar, "mesh-ca"); ok {
		t.Fatalf("cds-attest should not mount mesh-ca with the default /tls/cert.pem trust; mounts=%v", sidecar.VolumeMounts)
	}
	if got := len(deployment.Spec.Template.Spec.Containers); got != 2 {
		t.Fatalf("tls-lb should have nginx + cds-attest, got %d containers", got)
	}

	// nginx reverse-proxies the dynamic well-known prefix to the sidecar.
	for _, want := range []string{
		"location /.well-known/c8s/ {",
		"proxy_pass http://127.0.0.1:8800;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("nginx config missing %q\n%s", want, out)
		}
	}

	// An https upstream: the sidecar presents the CDS client cert and
	// verifies the upstream against the CA chain get-cert writes to
	// /tls/cert.pem, mirroring the nginx proxy_ssl_* config.
	httpsOut, err := helmTemplate(t, noUpstreamArgs(
		"--set", "tlsLb.attest.enabled=true",
		"--set-string", "tlsLb.upstream.address=my-backend.other-ns.svc:8443",
		"--set", "tlsLb.upstream.protocol=https",
	)...)
	if err != nil {
		t.Fatalf("helm template (https upstream): %v\n%s", err, httpsOut)
	}
	httpsSidecar := renderedDeploymentContainer(t, httpsOut, "c8s-tls-lb", "cds-attest")
	httpsJoined := strings.Join(httpsSidecar.Args, " ")
	for _, want := range []string{
		"--upstream=https://my-backend.other-ns.svc:8443",
		"--upstream-ca=/tls/cert.pem",
		"--upstream-cert=/tls/cert.pem",
		"--upstream-key=/tls/key.pem",
		"--upstream-server-name=my-backend.other-ns.svc",
	} {
		if !strings.Contains(httpsJoined, want) {
			t.Fatalf("cds-attest args missing %q: %v", want, httpsSidecar.Args)
		}
	}

	// Default off: no sidecar, no well-known proxy.
	offOut, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template (defaults): %v\n%s", err, offOut)
	}
	if strings.Contains(offOut, "name: cds-attest") || strings.Contains(offOut, "location /.well-known/c8s/ {") {
		t.Fatal("cds-attest sidecar should not render when tlsLb.attest.enabled is false")
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
	cert := tlsLBGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert, "--verbose", "--renew-interval=30m")
	if got := cert.SecurityContext.RunAsUser; got == nil || *got != 201 {
		t.Fatalf("c8s-cert runAsUser = %v, want 201", got)
	}
	if got := cert.SecurityContext.RunAsGroup; got == nil || *got != 202 {
		t.Fatalf("c8s-cert runAsGroup = %v, want 202", got)
	}
	if got := cert.SecurityContext.RunAsNonRoot; got == nil || *got {
		t.Fatalf("c8s-cert runAsNonRoot = %v, want false", got)
	}
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

// TestTLSLBProbesAvoidMTLSHandshakeUnderKata: under kata the RA-TLS mesh moves
// into the guest, so the pod's serving port is fronted by the in-guest inbound
// proxy that expects mutual attested TLS. The kubelet prober presents no
// attested client cert, so an httpGet probe is rejected at the handshake ("tls:
// certificate required") and the container CrashLoopBackOffs on failed probes.
// The chart must fall back to a tcpSocket probe under kata (same pattern and
// rationale as cds.yaml); the base shape — where the host-side mesh excludes
// kubelet's UID and it reaches nginx directly — keeps the richer httpGet
// /healthz check.
func TestTLSLBProbesAvoidMTLSHandshakeUnderKata(t *testing.T) {
	type namedProbe struct {
		name  string
		probe *corev1.Probe
	}

	base, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, base)
	}
	nginx := renderedDeploymentContainer(t, base, "c8s-tls-lb", "nginx")
	for _, p := range []namedProbe{
		{"readiness", nginx.ReadinessProbe},
		{"liveness", nginx.LivenessProbe},
	} {
		if p.probe == nil || p.probe.HTTPGet == nil {
			t.Fatalf("base shape: tls-lb %s probe should be httpGet; got %+v", p.name, p.probe)
		}
		if got := p.probe.HTTPGet.Scheme; got != corev1.URISchemeHTTPS {
			t.Errorf("base shape: tls-lb %s probe scheme = %q, want HTTPS", p.name, got)
		}
		if got := p.probe.HTTPGet.Path; got != "/healthz" {
			t.Errorf("base shape: tls-lb %s probe path = %q, want /healthz", p.name, got)
		}
	}

	kata, err := helmTemplateKata(t)
	if err != nil {
		t.Fatalf("helm template --kata: %v\n%s", err, kata)
	}
	nginx = renderedDeploymentContainer(t, kata, "c8s-tls-lb", "nginx")
	for _, p := range []namedProbe{
		{"readiness", nginx.ReadinessProbe},
		{"liveness", nginx.LivenessProbe},
	} {
		if p.probe == nil || p.probe.TCPSocket == nil {
			t.Fatalf("kata shape: tls-lb %s probe should be tcpSocket (an httpGet hits the in-guest mTLS handshake); got %+v", p.name, p.probe)
		}
		if got := p.probe.TCPSocket.Port.String(); got != "https" {
			t.Errorf("kata shape: tls-lb %s probe tcpSocket port = %q, want https", p.name, got)
		}
		if p.probe.HTTPGet != nil {
			t.Errorf("kata shape: tls-lb %s probe must not be httpGet under kata", p.name)
		}
	}
}

// TestChartDefaultTLSLBUpstreamIsWorkloadDirect pins the default front-door
// path: tls-lb proxies straight to the workload over plain HTTP at the app
// layer (the node mesh wraps pod-IP hops in attested mTLS), with no
// proxy_ssl_* directives on the default route. The upstream is dialed via a
// variable with a resolver so nginx re-resolves per DNS TTL: a headless
// Service (an adopted workload) returns pod IPs that change on pod churn, and
// a static upstream block would pin the startup-time IPs and 502 until the
// next config reload.
func TestChartTLSLBMeshWrappedUpstreamIsWorkloadDirect(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConf(t, out)
	for _, want := range []string{
		"resolver kube-dns.kube-system.svc.cluster.local;",
		// The baseline mesh-wrapped upstream is the operator-managed headless
		// Service, so the pod-IP hop is mesh-wrapped.
		"set $backend_addr c8s-infer.c8s-system.svc.cluster.local:8000;",
		"proxy_pass http://$backend_addr;",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("tls-lb nginx config missing %q\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "upstream backend {") {
		t.Fatalf("catch-all upstream must be a variable dial, not a static upstream block (it would pin headless pod IPs at startup)\n%s", cfg)
	}
	if strings.Contains(cfg, "proxy_ssl_") {
		t.Fatalf("default http upstream must not render proxy_ssl_ directives\n%s", cfg)
	}
}

// nginx exits at startup on a resolver name that does not resolve, and RKE2
// names its CoreDNS Service rke2-coredns-rke2-coredns — the kube-dns default
// crash-loops tls-lb on every RKE2 cluster. The resolver therefore derives
// from the distro values (which every RKE2 install already sets for the
// containerd layout); an explicit tlsLb.nginx.resolver still wins.
func TestChartTLSLBResolverDerivesFromDistro(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "rke2 via kata.distro",
			args: []string{"--set-string", "kata.distro=rke2"},
			want: "resolver rke2-coredns-rke2-coredns.kube-system.svc.cluster.local;",
		},
		{
			name: "rke2 via nriImagePolicy.distro",
			args: []string{"--set-string", "nriImagePolicy.distro=rke2"},
			want: "resolver rke2-coredns-rke2-coredns.kube-system.svc.cluster.local;",
		},
		{
			name: "explicit resolver wins over distro",
			args: []string{
				"--set-string", "kata.distro=rke2",
				"--set-string", "tlsLb.nginx.resolver=my-dns.dns-ns.svc.cluster.local",
			},
			want: "resolver my-dns.dns-ns.svc.cluster.local;",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cfg := renderedTLSLBNginxConf(t, out)
			if !strings.Contains(cfg, tc.want) {
				t.Fatalf("tls-lb nginx config missing %q\n%s", tc.want, cfg)
			}
		})
	}
}

func TestTLSLBVerifyDerivesProxySSLNameFromUpstream(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "upstream.address=my-backend.other-ns.svc.cluster.local:443",
		"--set", "upstream.protocol=https",
		"--set", "upstream.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "proxy_ssl_name", "my-backend.other-ns.svc.cluster.local")
}

func TestTLSLBAdditionalRoutesConfigureNginxLocations(t *testing.T) {
	// Route backends must be secured (https + verify); the location/upstream
	// wiring under test is protocol-independent.
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].match=exact",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
		"--set-string", "routes[1].path=/tenant/",
		"--set-string", "routes[1].backend.address=tenant-router.c8s-system.svc:8080",
		"--set-string", "routes[1].backend.protocol=https",
		"--set", "routes[1].backend.tls.verify=true",
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
			path:     "/allowlist",
			proxyURL: "https://route_0",
		},
		{
			name:     "default-prefix",
			match:    "prefix",
			path:     "/tenant/",
			proxyURL: "https://route_1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			route := cfg.location(t, tt.match, tt.path)
			route.assertDirective(t, "proxy_pass", tt.proxyURL)
		})
	}

	defaultRoute := cfg.location(t, "prefix", "/")
	defaultRoute.assertDirective(t, "set", "$backend_addr", "vllm:8000")
	defaultRoute.assertDirective(t, "proxy_pass", "https://$backend_addr")
	cfg.upstream(t, "route_0").assertServer(t, "cds.c8s-system.svc:8080")
	cfg.upstream(t, "route_1").assertServer(t, "tenant-router.c8s-system.svc:8080")
}

// A route backend forwards X-Forwarded-Proto to the origin regardless of the
// backend protocol; the backend must be secured (https + verify), so a client
// cert is presented but no proxy_ssl client cert is required for that header.
func TestTLSLBRouteForwardsProto(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/tenant/",
		"--set-string", "routes[0].backend.address=tenant-router.c8s-system.svc:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	cfg.upstream(t, "route_0").assertServer(t, "tenant-router.c8s-system.svc:8080")
	route := cfg.location(t, "prefix", "/tenant/")
	route.assertDirective(t, "proxy_pass", "https://route_0")
	route.assertDirective(t, "proxy_set_header", "X-Forwarded-Proto", "$scheme")
}

func TestTLSLBTypedHTTPSRouteConfiguresProxyTLS(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/allowlist",
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
	route := cfg.location(t, "exact", "/allowlist")
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
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc.cluster.local:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.useCDSClientCert=true",
		"--set", "routes[0].backend.tls.verify=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	route := cfg.location(t, "prefix", "/allowlist")
	route.assertDirective(t, "proxy_ssl_certificate", "/tls/cert.pem")
	route.assertDirective(t, "proxy_ssl_certificate_key", "/tls/key.pem")
	route.assertDirective(t, "proxy_ssl_name", "cds.c8s-system.svc.cluster.local")
	route.assertDirective(t, "proxy_pass", "https://route_0")
}

func TestTLSLBTypedHTTPSRouteCustomTrustedCAPathDoesNotMountMeshCA(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].backend.address=cds.c8s-system.svc.cluster.local:8080",
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
		"--set-string", "routes[0].backend.tls.trustedCAPath=/etc/ssl/certs/ca-certificates.crt",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedTLSLBNginxConfig(t, out)
	route := cfg.location(t, "prefix", "/allowlist")
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
		"--set-string", "routes[0].backend.protocol=https",
		"--set", "routes[0].backend.tls.verify=true",
		"--set-string", "routes[0].backend.tls.trustedCAPath=/tls/other.pem",
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

// TestTLSLBRejectsUnsecuredRoute pins the per-route secured-backend guard,
// mirroring the catch-all upstream: a route backend must be https with
// tls.verify=true (app-TLS). A plaintext http backend, or https without verify,
// fails the render; there is no plaintext-to-unattested acknowledgment.
func TestTLSLBRejectsUnsecuredRoute(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		kind string
	}{
		{
			name: "http-route",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
			},
			kind: "tlslb_unsecured_route",
		},
		{
			name: "unverified-https-route",
			args: []string{
				"--set-string", "routes[0].path=/x",
				"--set-string", "routes[0].backend.address=svc:8080",
				"--set-string", "routes[0].backend.protocol=https",
			},
			kind: "tlslb_unsecured_route",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplateTLSLB(t, tt.args...)
			if err == nil {
				t.Fatalf("helm template succeeded, want %s failure\n%s", tt.kind, out)
			}
			if got := parseValidationErrorKind(out); got != tt.kind {
				t.Fatalf("validation kind = %q, want %q\n%s", got, tt.kind, out)
			}
		})
	}
}

func TestTLSLBRejectsInvalidRouteMatch(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/allowlist",
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
				"--set-string", "routes[0].path=/allowlist",
			},
			want: "tlsLb.routes[0].backend is required",
		},
		{
			name: "backend-address",
			args: []string{
				"--set-string", "routes[0].path=/allowlist",
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
		"--set-string", "routes[0].path=/allowlist",
		"--set-string", "routes[0].upstream=http://cds.c8s-system.svc:8080",
	)
	if err == nil {
		t.Fatalf("helm template succeeded, want unsupported route upstream failure\n%s", out)
	}
	assertHelmFailMessage(t, out, "tlsLb.routes[0].upstream is not supported; set backend.address and backend.protocol instead")
}

func TestTLSLBRejectsInvalidTypedRouteProtocol(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set-string", "routes[0].path=/allowlist",
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
	assertContainerArgs(t, tlsLBGetCertContainer(t, out, "c8s-cert"),
		"--ca-out=/tls/ca.pem",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem")
}

// TestTLSLBGetCertWritesMeshCABundle pins the mechanism that replaced the
// c8s-cds-mesh-ca ConfigMap mount: the c8s-cert sidecar writes the mesh CA
// bundle to /tls/ca.pem (the tls-certs volume that already holds the leaf).
func TestTLSLBGetCertWritesMeshCABundle(t *testing.T) {
	out, err := helmTemplateTLSLB(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerArgs(t, tlsLBGetCertContainer(t, out, "c8s-cert"),
		"--ca-out=/tls/ca.pem")
}

func TestTLSLBDiscoveryReportsCDSModeWithoutPublicTLSSecret(t *testing.T) {
	out, err := helmTemplateTLSLB(t,
		"--set", "discovery.enabled=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	assertContainerArgs(t, tlsLBGetCertContainer(t, out, "c8s-cert"),
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
	// The workload-service reconciler reads workloads (never mutates them)
	// and owns the headless Services it provisions in workload namespaces.
	for _, resource := range []string{"deployments", "statefulsets", "daemonsets"} {
		if got := operatorVerbsFor(role, "apps", resource); !slices.Equal(got, []string{"get", "list", "watch"}) {
			t.Fatalf("operator %s verbs = %v, want read-only [get list watch]", resource, got)
		}
	}
	if got := operatorVerbsFor(role, "", "services"); !slices.Equal(got, []string{"get", "list", "watch", "create", "update", "delete"}) {
		t.Fatalf("operator services verbs = %v", got)
	}
	for _, unexpected := range []string{
		"resources: [confidentialworkloads/finalizers]",
		"resources: [replicasets]",
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
// kata-deploy DaemonSet and the platform's RuntimeClasses — on the default
// (SNP) platform the two non-confidential classes plus the SNP pair; the TDX
// classes must NOT render (one CPU TEE per cluster).
func TestChartKataEnabledRendersDeployStack(t *testing.T) {
	out, err := helmTemplateKata(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, rc := range []string{"kata-qemu", "kata-clh", "kata-qemu-snp", "kata-qemu-snp-nvidia"} {
		if !renderedManifestHasNamedKind(t, out, "RuntimeClass", rc) {
			t.Fatalf("kata.enabled missing RuntimeClass %q\n%s", rc, out)
		}
	}
	for _, rc := range []string{"kata-qemu-tdx", "kata-qemu-tdx-nvidia"} {
		if renderedManifestHasNamedKind(t, out, "RuntimeClass", rc) {
			t.Fatalf("TDX RuntimeClass %q rendered on an SNP install — only the declared platform's classes ship\n%s", rc, out)
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

	// kata is enforcing: there is no kata-without-enforcement shape, so the
	// stack and the enforcement policy must arrive together.
	if !renderedManifestHasNamedKind(t, out, "ValidatingAdmissionPolicy", "c8s-kata-enforcement") {
		t.Errorf("kata.enabled must render the enforcement policy — kata is enforcing")
	}
	if !slices.Contains(renderedOperatorArgs(t, out), "--kata-enforce=true") {
		t.Errorf("operator must get --kata-enforce under kata.enabled — kata is enforcing")
	}
	// The webhook injects the platform's confidential classes; the operator
	// must be told which platform the chart rendered for.
	if !slices.Contains(renderedOperatorArgs(t, out), "--hardware-platform=sev-snp") {
		t.Errorf("operator must get --hardware-platform=sev-snp on a default kata install; args: %v", renderedOperatorArgs(t, out))
	}
	// The enforcement allowlist is platform-scoped too: a TDX class name must
	// not be admissible on an SNP install.
	if strings.Contains(out, "'kata-qemu-tdx'") || strings.Contains(out, "'kata-qemu-tdx-nvidia'") {
		t.Errorf("kata-enforcement allowlist must not accept TDX classes on an SNP install\n%s", out)
	}
}

// rcScheduling captures the scheduling block of a rendered RuntimeClass.
type rcScheduling struct {
	Scheduling struct {
		NodeSelector map[string]string `json:"nodeSelector"`
	} `json:"scheduling"`
}

// TestChartKataSnpRuntimeClassesCarryNodeSelector: the confidential classes
// must select SNP-labelled nodes (kata.snpNodeSelector). Without the selector
// a confidential pod scheduled onto a non-SNP TEE host (e.g. Intel TDX) does
// not fail cleanly — kata's confidential_guest auto-detects the host TEE and
// QEMU aborts in an unbounded crash-loop; with it the pod stays Pending with a
// clear scheduling message. kata-qemu / kata-clh work on any kata node and
// must stay unrestricted.
func TestChartKataSnpRuntimeClassesCarryNodeSelector(t *testing.T) {
	out, err := helmTemplateKata(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, name := range []string{"kata-qemu-snp", "kata-qemu-snp-nvidia"} {
		var rc rcScheduling
		if !findDoc(t, out, "RuntimeClass", name, &rc) {
			t.Fatalf("RuntimeClass %q not rendered\n%s", name, out)
		}
		if got := rc.Scheduling.NodeSelector["confidential.ai/sev-snp"]; got != "true" {
			t.Errorf("%s scheduling.nodeSelector[confidential.ai/sev-snp] = %q, want \"true\"", name, got)
		}
	}
	for _, name := range []string{"kata-qemu", "kata-clh"} {
		var rc rcScheduling
		if !findDoc(t, out, "RuntimeClass", name, &rc) {
			t.Fatalf("RuntimeClass %q not rendered\n%s", name, out)
		}
		if len(rc.Scheduling.NodeSelector) != 0 {
			t.Errorf("%s must carry no scheduling.nodeSelector (it runs on any kata node), got %v", name, rc.Scheduling.NodeSelector)
		}
	}
}

// kata.snpNodeSelector={} is the documented opt-out: the confidential classes
// render with no scheduling block (unrestricted scheduling, e.g. a uniformly
// SNP cluster that wants no capability label).
func TestChartKataSnpNodeSelectorClearable(t *testing.T) {
	out, err := helmTemplateKata(t, "--set", "kata.snpNodeSelector=null")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, name := range []string{"kata-qemu-snp", "kata-qemu-snp-nvidia"} {
		var rc rcScheduling
		if !findDoc(t, out, "RuntimeClass", name, &rc) {
			t.Fatalf("RuntimeClass %q not rendered\n%s", name, out)
		}
		if len(rc.Scheduling.NodeSelector) != 0 {
			t.Errorf("%s scheduling.nodeSelector = %v, want none with kata.snpNodeSelector cleared", name, rc.Scheduling.NodeSelector)
		}
	}
}

// TestChartGpuAbsentWithoutKata: with kata disabled (the chart default) none of
// the confidential-GPU stack renders — the whole GPU stack is part of the kata
// stack, gated on kata.enabled.
func TestChartGpuAbsentWithoutKata(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "RuntimeClass", "kata-qemu-snp-nvidia") {
		t.Errorf("GPU RuntimeClass rendered without kata.enabled\n%s", out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-kata-deploy-image-puller-nvidia") {
		t.Errorf("GPU image puller rendered without kata.enabled")
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-kata-deploy-sandbox-device-plugin") {
		t.Errorf("sandbox device plugin rendered without kata.enabled")
	}
}

// TestChartKataRendersGpuStack: a plain --kata install (no GPU flag) ships the
// confidential-GPU stack — the GPU RuntimeClass (handler kata-qemu-nvidia-gpu-snp),
// the GPU shim in SHIMS_X86_64, the enforcement allowlist entry, the GPU image
// puller, and the privileged digest-pinned sandbox device plugin. GPU is part of
// every kata install; there is no separate toggle.
func TestChartKataRendersGpuStack(t *testing.T) {
	out, err := helmTemplateKata(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	// RuntimeClass name follows the c8s convention; handler is the kata shim.
	var rc struct {
		Handler string `yaml:"handler"`
	}
	if !findDoc(t, out, "RuntimeClass", "kata-qemu-snp-nvidia", &rc) {
		t.Fatalf("a kata install must render RuntimeClass kata-qemu-snp-nvidia\n%s", out)
	}
	if rc.Handler != "kata-qemu-nvidia-gpu-snp" {
		t.Errorf("kata-qemu-snp-nvidia handler = %q, want kata-qemu-nvidia-gpu-snp", rc.Handler)
	}

	// GPU shim registered with kata-deploy.
	ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
	kube, _ := findContainer(ds.Spec.Template.Spec.Containers, "kube-kata")
	if v := envValue(kube.Env, "SHIMS_X86_64"); !strings.Contains(v, "qemu-nvidia-gpu-snp") {
		t.Errorf("SHIMS_X86_64 = %q must register qemu-nvidia-gpu-snp", v)
	}

	// Enforcement allowlist accepts the class.
	if !strings.Contains(out, "'kata-qemu-snp-nvidia'") {
		t.Errorf("kata-enforcement allowlist must accept kata-qemu-snp-nvidia\n%s", out)
	}

	// GPU image puller: pulls the -nvidia tag and patches the GPU config.
	puller := renderedDaemonSet(t, out, "c8s-kata-deploy-image-puller-nvidia")
	pc, ok := findContainer(puller.Spec.Template.Spec.Containers, "reconcile")
	if !ok {
		t.Fatalf("GPU puller missing reconcile container")
	}
	if got := envValue(pc.Env, "TAG"); got != "main-nvidia" {
		t.Errorf("GPU puller TAG = %q, want main-nvidia", got)
	}
	if got := envValue(pc.Env, "SHIM_NAME"); got != "qemu-nvidia-gpu-snp" {
		t.Errorf("GPU puller SHIM_NAME = %q, want qemu-nvidia-gpu-snp", got)
	}
	if got := envValue(pc.Env, "GPU_PCIE_ROOT_PORT"); got != "8" {
		t.Errorf("GPU puller GPU_PCIE_ROOT_PORT = %q, want 8", got)
	}

	// Sandbox device plugin: privileged, digest-pinned, advertises GPUs.
	plugin := renderedDaemonSet(t, out, "c8s-kata-deploy-sandbox-device-plugin")
	dp, ok := findContainer(plugin.Spec.Template.Spec.Containers, "nvidia-sandbox-device-plugin")
	if !ok {
		t.Fatalf("sandbox device plugin missing its container")
	}
	if dp.SecurityContext == nil || dp.SecurityContext.Privileged == nil || !*dp.SecurityContext.Privileged {
		t.Errorf("sandbox device plugin must run privileged (it mounts host /dev/vfio)")
	}
	if !strings.Contains(dp.Image, "@sha256:") {
		t.Errorf("sandbox device plugin image %q must be digest-pinned", dp.Image)
	}
}

// TestChartKataRendersGpuStackTdx: under attestationApi.teeDevices.tdxGuest
// the TDX classes render (and the SNP ones do NOT — one CPU TEE per cluster),
// the TDX shims register with kata-deploy, the enforcement allowlist accepts
// the TDX pair only, the GPU puller targets the qemu-nvidia-gpu-tdx shim
// (mirroring the non-GPU puller's qemu-tdx switch), and the operator is told
// the platform so webhook injection matches.
func TestChartKataRendersGpuStackTdx(t *testing.T) {
	out, err := helmTemplateKata(t,
		"--set", "attestationApi.teeDevices.tdxGuest=true",
		"--set", "attestationApi.teeDevices.sevGuest=false",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	var rc struct {
		Handler    string `yaml:"handler"`
		Scheduling struct {
			NodeSelector map[string]string `yaml:"nodeSelector"`
		} `yaml:"scheduling"`
	}
	if !findDoc(t, out, "RuntimeClass", "kata-qemu-tdx-nvidia", &rc) {
		t.Fatalf("a kata install must render RuntimeClass kata-qemu-tdx-nvidia\n%s", out)
	}
	if rc.Handler != "kata-qemu-nvidia-gpu-tdx" {
		t.Errorf("kata-qemu-tdx-nvidia handler = %q, want kata-qemu-nvidia-gpu-tdx", rc.Handler)
	}
	if got := rc.Scheduling.NodeSelector["confidential.ai/tdx"]; got != "true" {
		t.Errorf("kata-qemu-tdx-nvidia nodeSelector[confidential.ai/tdx] = %q, want \"true\" (same guard as kata-qemu-tdx)", got)
	}

	ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
	kube, _ := findContainer(ds.Spec.Template.Spec.Containers, "kube-kata")
	if v := envValue(kube.Env, "SHIMS_X86_64"); !strings.Contains(v, "qemu-nvidia-gpu-tdx") {
		t.Errorf("SHIMS_X86_64 = %q must register qemu-nvidia-gpu-tdx", v)
	}
	if v := envValue(kube.Env, "SNAPSHOTTER_HANDLER_MAPPING_X86_64"); !strings.Contains(v, "qemu-nvidia-gpu-tdx:nydus") {
		t.Errorf("SNAPSHOTTER_HANDLER_MAPPING_X86_64 = %q must route qemu-nvidia-gpu-tdx through nydus", v)
	}

	if !strings.Contains(out, "'kata-qemu-tdx-nvidia'") {
		t.Errorf("kata-enforcement allowlist must accept kata-qemu-tdx-nvidia\n%s", out)
	}

	puller := renderedDaemonSet(t, out, "c8s-kata-deploy-image-puller-nvidia")
	pc, ok := findContainer(puller.Spec.Template.Spec.Containers, "reconcile")
	if !ok {
		t.Fatalf("GPU puller missing reconcile container")
	}
	if got := envValue(pc.Env, "SHIM_NAME"); got != "qemu-nvidia-gpu-tdx" {
		t.Errorf("GPU puller SHIM_NAME = %q, want qemu-nvidia-gpu-tdx on a TDX cluster", got)
	}

	// One CPU TEE per cluster: the SNP classes must not render on TDX, the
	// SNP shims must not register, and the allowlist must not accept them.
	for _, rc := range []string{"kata-qemu-snp", "kata-qemu-snp-nvidia"} {
		if renderedManifestHasNamedKind(t, out, "RuntimeClass", rc) {
			t.Errorf("SNP RuntimeClass %q rendered on a TDX install — only the declared platform's classes ship", rc)
		}
	}
	if v := envValue(kube.Env, "SHIMS_X86_64"); strings.Contains(v, "-snp") {
		t.Errorf("SHIMS_X86_64 = %q must not register SNP shims on a TDX install", v)
	}
	if strings.Contains(out, "'kata-qemu-snp'") || strings.Contains(out, "'kata-qemu-snp-nvidia'") {
		t.Errorf("kata-enforcement allowlist must not accept SNP classes on a TDX install\n%s", out)
	}
	if !strings.Contains(out, "'kata-qemu-tdx'") {
		t.Errorf("kata-enforcement allowlist must accept kata-qemu-tdx on a TDX install\n%s", out)
	}

	// Webhook injection follows the platform.
	if !slices.Contains(renderedOperatorArgs(t, out), "--hardware-platform=tdx") {
		t.Errorf("operator must get --hardware-platform=tdx on a TDX kata install; args: %v", renderedOperatorArgs(t, out))
	}
}

// TestChartKataSandboxDevicePluginOptOut: the privileged sandbox device plugin
// (the only nvcr.io-pulled, host-/dev/vfio-mounting GPU component) can be opted
// out via kata.gpu.sandboxDevicePlugin.enabled while the rest of the GPU stack
// (runtime class, shim, puller) still ships.
func TestChartKataSandboxDevicePluginOptOut(t *testing.T) {
	out, err := helmTemplateKata(t, "--set", "kata.gpu.sandboxDevicePlugin.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-kata-deploy-sandbox-device-plugin") {
		t.Errorf("sandbox device plugin rendered with sandboxDevicePlugin.enabled=false")
	}
	if !renderedManifestHasNamedKind(t, out, "RuntimeClass", "kata-qemu-snp-nvidia") {
		t.Errorf("the rest of the GPU stack must still render with the device plugin opted out")
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
			out, err := helmTemplateKata(t, "--set-string", "kata.distro="+tc.distro)
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
	out, err := helmTemplateKata(t, "--set-string", "kata.distro=openshift")
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
		out, err := helmTemplateKata(t, "--set-string", "kata.distro=rke2")
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
		out, err := helmTemplateKata(t, "--set-string", "kata.distro=k8s")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		ds := renderedDaemonSet(t, out, "c8s-kata-deploy")
		if _, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "containerd-prep"); ok {
			t.Fatalf("k8s: kata-deploy must not carry a containerd-prep initContainer")
		}
	})
}

// TestChartCwLabelIntegrityPolicyRendersByDefault: the cw-label
// ValidatingAdmissionPolicy guards Service-membership identity and must ship
// on by default, with the immutability (oldObject) check present and the
// webhook's namespace exclusions mirrored.
func TestChartCwLabelIntegrityPolicyRendersByDefault(t *testing.T) {
	out, err := helmTemplate(t, "--set", "webhook.extraExcluded[0]=skip-me")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var policy admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, out, "ValidatingAdmissionPolicy", "c8s-cw-label-integrity", &policy) {
		t.Fatalf("missing cw-label-integrity ValidatingAdmissionPolicy\n%s", out)
	}
	ops := policy.Spec.MatchConstraints.ResourceRules[0].Operations
	if !slices.Contains(ops, admissionregv1.Update) {
		t.Fatalf("policy operations = %v, must include UPDATE (post-create label mutation is the attack)", ops)
	}
	if !slices.ContainsFunc(policy.Spec.Validations, func(v admissionregv1.Validation) bool {
		return strings.Contains(v.Expression, "oldObject")
	}) {
		t.Fatalf("policy has no oldObject immutability validation: %+v", policy.Spec.Validations)
	}
	var binding admissionregv1.ValidatingAdmissionPolicyBinding
	if !findDoc(t, out, "ValidatingAdmissionPolicyBinding", "c8s-cw-label-integrity", &binding) {
		t.Fatalf("missing cw-label-integrity ValidatingAdmissionPolicyBinding\n%s", out)
	}
	excluded := selectorExpressionValues(binding.Spec.MatchResources.NamespaceSelector,
		"kubernetes.io/metadata.name", metav1.LabelSelectorOpNotIn)
	for _, ns := range []string{"c8s-system", "kube-system", "kube-public", "kube-node-lease", "skip-me"} {
		if !slices.Contains(excluded, ns) {
			t.Fatalf("binding namespace exclusions %v missing %s (must mirror the webhook)", excluded, ns)
		}
	}
}

func TestChartCwLabelIntegrityPolicyDisabled(t *testing.T) {
	out, err := helmTemplate(t, "--set", "webhook.cwLabelPolicy.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "ValidatingAdmissionPolicy", "c8s-cw-label-integrity") {
		t.Fatalf("cw-label-integrity policy rendered while disabled\n%s", out)
	}
}

// helmTemplateKata renders the chart in the shape `c8s install --kata`
// produces. kata is enforcing, so the host-side components whose function
// moves into the kata-guest-base image are switched off (the chart validates
// they are off — see TestChartKataRejectsHostSideComponents).
func helmTemplateKata(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return helmTemplate(t, append([]string{
		"--set", "kata.enabled=true",
		"--set", "ratlsMesh.enabled=false",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
	}, args...)...)
}

// TestChartKataRendersPolicyAndOperatorFlag: kata.enabled renders the
// ValidatingAdmissionPolicy + binding and flips the operator's --kata-enforce
// flag — the two halves of enforcement must move together, and kata is
// enforcing by definition.
func TestChartKataRendersPolicyAndOperatorFlag(t *testing.T) {
	out, err := helmTemplateKata(t)
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

// pcie_root_port=0 disables VFIO cold-plug: a GPU pod would boot as a
// confidential VM with no device and the only symptom is a missing
// /dev/nvidia* in-guest. The chart must refuse the render instead of
// shipping that silently (the puller script double-checks at run time).
func TestChartKataRejectsZeroPcieRootPort(t *testing.T) {
	out, err := helmTemplateKata(t, "--set", "kata.gpu.guestImage.pcieRootPort=0")
	if err == nil {
		t.Fatalf("helm template succeeded with kata.gpu.guestImage.pcieRootPort=0, want failure\n%s", out)
	}
	if msg := helmFailMessage(t, out); !strings.Contains(msg, "kind=gpu_pcie_root_port") {
		t.Errorf("fail message %q missing the gpu_pcie_root_port marker", msg)
	}
}

// kata is enforcing: every workload is a kata CVM, where ratls routing,
// attestation, and image admission run inside the kata-guest-base image. The
// chart must refuse to deploy the host-side versions alongside — they would be
// dead weight at best and a second, unattested enforcement path at worst.
func TestChartKataRejectsHostSideComponents(t *testing.T) {
	out, err := helmTemplate(t, "--set", "kata.enabled=true")
	if err == nil {
		t.Fatalf("helm template succeeded with kata and host-side components enabled, want failure\n%s", out)
	}
	msg := helmFailMessage(t, out)
	if !strings.Contains(msg, "kind=enforce_host_components") {
		t.Errorf("fail message %q missing the enforce_host_components marker", msg)
	}
	for _, want := range []string{"ratlsMesh.enabled", "attestationApi.enabled", "nriImagePolicy.enabled"} {
		if !strings.Contains(msg, want) {
			t.Errorf("fail message %q should name %s", msg, want)
		}
	}
}

// The kata shape (what `c8s install --kata` renders) must drop the host-side
// DaemonSets entirely — their in-guest counterparts ship in kata-guest-base.
func TestChartKataShapeDropsHostSideComponents(t *testing.T) {
	out, err := helmTemplateKata(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-attestation-api") {
		t.Errorf("kata shape still renders the host attestation-api DaemonSet")
	}
	for _, component := range []string{"ratls-mesh", "nri-image-policy"} {
		if strings.Contains(out, "app.kubernetes.io/name: "+component) {
			t.Errorf("kata shape still renders %s manifests", component)
		}
	}
}

// tls-lb lives in the release namespace, which the kata-enforcement webhook
// deliberately excludes — so the chart itself must pin the confidential
// RuntimeClass on it under kata, exactly like cds.yaml. kata-qemu-snp
// specifically: its get-cert containers dial the in-guest attestation-api on
// loopback (c8s.attestationApiURL), which only exists inside an SNP guest.
func TestChartKataPinsRuntimeClassOnTLSLB(t *testing.T) {
	out, err := helmTemplateKata(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dep := renderedDeployment(t, out, "c8s-tls-lb")
	rc := dep.Spec.Template.Spec.RuntimeClassName
	if rc == nil || *rc != "kata-qemu-snp" {
		t.Errorf("c8s-tls-lb runtimeClassName = %v, want kata-qemu-snp", rc)
	}
}

// Without kata the same Deployment must carry no RuntimeClass — runc is the
// only runtime on a plain cluster.
func TestChartNoRuntimeClassOnTLSLBWithoutKata(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dep := renderedDeployment(t, out, "c8s-tls-lb")
	if rc := dep.Spec.Template.Spec.RuntimeClassName; rc != nil {
		t.Errorf("c8s-tls-lb runtimeClassName = %q, want unset without kata", *rc)
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
			for _, name := range []string{"c8s-nri-image-policy-worker"} {
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

// TestChartNriImagePolicyDetachesContainerdRestart: the installer must hand the
// host containerd restart to systemd-run (host PID 1), not run it in this pod's
// process tree. A restart via `nsenter ... sh -c "$RESTART_COMMAND"` is killed
// with the pod when containerd bounces, which on a sole control-plane node
// interrupts the rke2 bootstrap and wedges it.
func TestChartNriImagePolicyDetachesContainerdRestart(t *testing.T) {
	out, err := helmTemplate(t, "--set-string", "nriImagePolicy.distro=rke2")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	if !strings.Contains(script, "systemd-run") {
		t.Fatalf("install script must detach the containerd restart via systemd-run\n%s", script)
	}
	// The bare in-pod form (nsenter ... -- sh -c "$RESTART_COMMAND") must be
	// gone; the restart now goes nsenter ... -- systemd-run ... sh -c "...".
	if strings.Contains(script, `-p -- sh -c "$RESTART_COMMAND"`) {
		t.Fatalf("install script still runs RESTART_COMMAND in-pod (not detached)\n%s", script)
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
		for _, name := range []string{"c8s-nri-image-policy-worker"} {
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
		for _, name := range []string{"c8s-nri-image-policy-worker"} {
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

// baseNRIDigest is the nri-image-policy image digest the shared harness pins
// and covers in the allowlist floor, so the default fail-closed render is valid.
const baseNRIDigest = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"

func helmTemplate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	base := []string{
		"template", "c8s", "c8s",
		// Pin the simulated cluster version at the chart's kubeVersion floor
		// so the tests do not depend on the helm client's compiled default
		// (helm 3.14 simulates 1.29, below the floor).
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "attestationApi.image.tag=dev",
		"--set", "cds.image.tag=dev",
		"--set", "ratlsMesh.image.tag=dev",
		"--set", "nriImagePolicy.image.tag=dev",
		// tls-lb has no default upstream (a silently-plaintext VIP was
		// removed); a c8s-<id> headless-Service address (what `c8s install
		// --upstream` derives) is the representative mesh-wrapped baseline, and
		// the chart recognizes that shape as mesh-wrapped. Tests for the
		// manual-upstream paths clear it via noUpstreamArgs.
		"--set-string", "tlsLb.upstream.address=c8s-infer.c8s-system.svc.cluster.local:8000",
		"--set", "nriImagePolicy.image.digest=" + baseNRIDigest,
		// The fail-closed default (this PR) activates the
		// uncovered_component_digest guard: every digest-pinned component must be
		// covered in the allowlist floor or the plugin would deny it on its own
		// node. The nri installer also self-allows by digest, so the image must
		// stay digest-pinned. Cover the base nri digest in the floor so the
		// default render is a valid fail-closed config. Tests that exercise the
		// guard pin a different, deliberately-uncovered digest.
		"--set-string", "nriImagePolicy.bootstrapAllowlist.digests." + baseNRIDigest + "=ghcr.io/confidential-dot-ai/nri-image-policy@" + baseNRIDigest,
		"--set", "cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000001",
	}
	cmd := exec.Command("helm", append(base, args...)...)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// noUpstreamArgs clears the mesh-wrapped upstream that helmTemplate pins by
// default, for tests exercising the manual tlsLb.upstream paths.
func noUpstreamArgs(args ...string) []string {
	return append([]string{"--set-string", "tlsLb.upstream.address="}, args...)
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
// (no Secret/ca-cert flag), the allowlist DB, and the in-process JWKS (no
// --jwks-url, since signing happens in the same binary).
func TestChartCDSWiresInProcessTrustRoot(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	for _, want := range []string{
		"--attestation-api-url=http://c8s-attestation-api.c8s-system.svc:8400",
		"--allowlist-db=/data/allowlist.db",
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
	const public = "confidential-gke-confidential-dot-ai"
	out, err := helmTemplate(t, "--set", "cds.dnsSanPatterns[0]="+public)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	args := renderedDeploymentContainer(t, out, "c8s-cds", "cds").Args
	assertContainerHasArg(t, "cds", args, "--dns-san-pattern=^[a-z0-9-]+[.][a-z0-9-]+[.]svc$")
	assertContainerHasArg(t, "cds", args, "--dns-san-pattern="+public)
}

// TestChartCertDependentPodStrategies pins tls-lb's rollout strategy to its
// constraint: with the default hostPort binding it must Recreate (two pods on
// a node would collide on the host port, and a surge pod could never schedule
// on a single-node cluster, deadlocking the roll); without hostPort it surges
// so the new cert-holding pod is Ready before the old one retires. An
// explicit tlsLb.strategy renders verbatim.
func TestChartCertDependentPodStrategies(t *testing.T) {
	t.Run("default hostPort binds, so Recreate", func(t *testing.T) {
		out, err := helmTemplate(t)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		tlsLB := renderedDeployment(t, out, "c8s-tls-lb")
		if tlsLB.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
			t.Errorf("c8s-tls-lb strategy = %q, want Recreate (host-port binding forbids two concurrent pods on a node)", tlsLB.Spec.Strategy.Type)
		}
	})

	t.Run("no hostPort surges with no gap", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "tlsLb.hostPort.enabled=false")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		tlsLB := renderedDeployment(t, out, "c8s-tls-lb")
		if tlsLB.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
			t.Errorf("c8s-tls-lb strategy = %q, want RollingUpdate", tlsLB.Spec.Strategy.Type)
		}
		if ru := tlsLB.Spec.Strategy.RollingUpdate; ru == nil ||
			ru.MaxUnavailable == nil || ru.MaxUnavailable.IntValue() != 0 ||
			ru.MaxSurge == nil || ru.MaxSurge.IntValue() != 1 {
			t.Errorf("c8s-tls-lb should surge (maxSurge=1, maxUnavailable=0), got %+v", ru)
		}
	})

	t.Run("explicit strategy renders verbatim", func(t *testing.T) {
		out, err := helmTemplate(t, "--set-string", "tlsLb.strategy.type=RollingUpdate")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		tlsLB := renderedDeployment(t, out, "c8s-tls-lb")
		if tlsLB.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
			t.Errorf("c8s-tls-lb strategy = %q, want the explicit RollingUpdate override", tlsLB.Spec.Strategy.Type)
		}
	})
}

// TestChartTLSLBHostPort covers the tlsLb.hostPort edge toggle. The default
// publishes nginx's TLS listener on the node's host port 443 (the in-pod
// listener stays on the unprivileged nginx.httpsPort). hostPort.enabled=false
// omits it so the pod schedules where another controller already owns 443
// (e.g. RKE2's bundled ingress-nginx). A custom host port binds independently
// of the listener port.
func TestChartTLSLBHostPort(t *testing.T) {
	nginxHTTPSPort := func(t *testing.T, out string) (containerPort, hostPort int32) {
		t.Helper()
		nginx := renderedDeploymentContainer(t, out, "c8s-tls-lb", "nginx")
		p, ok := namedContainerPort(nginx, "https")
		if !ok {
			t.Fatal("nginx container has no https port")
		}
		return p.ContainerPort, p.HostPort
	}

	t.Run("default binds host 443", func(t *testing.T) {
		out, err := helmTemplate(t)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cp, hp := nginxHTTPSPort(t, out)
		if cp != 8443 || hp != 443 {
			t.Fatalf("https = containerPort %d / hostPort %d, want 8443 / 443", cp, hp)
		}
	})

	t.Run("disabled omits the host port", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "tlsLb.hostPort.enabled=false")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cp, hp := nginxHTTPSPort(t, out)
		if hp != 0 {
			t.Fatalf("https hostPort = %d, want 0 (unbound)", hp)
		}
		if cp != 8443 {
			t.Fatalf("https containerPort = %d, must stay 8443 with hostPort disabled", cp)
		}
	})

	t.Run("custom host port decouples from the listener port", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "tlsLb.hostPort.https=8443")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cp, hp := nginxHTTPSPort(t, out)
		if cp != 8443 || hp != 8443 {
			t.Fatalf("https = containerPort %d / hostPort %d, want 8443 / 8443", cp, hp)
		}
	})

	t.Run("string bool is rejected", func(t *testing.T) {
		// A string "false" is truthy in templates and would silently keep the
		// port bound (and the strategy on Recreate) despite the opt-out.
		out, err := helmTemplate(t, "--set-string", "tlsLb.hostPort.enabled=false")
		if err == nil {
			t.Fatalf("helm template succeeded, want string-bool rejection\n%s", out)
		}
		assertHelmFailMessage(t, out, "tlsLb.hostPort.enabled must be a boolean; do not set it via --set-string, got: false")
	})
}

// TestChartNoTeeProxyRemnants sweeps the default and kata renders for any
// leftover tee-proxy wiring after the component's removal.
func TestChartNoTeeProxyRemnants(t *testing.T) {
	for _, tc := range []struct {
		name   string
		render func(t *testing.T, args ...string) (string, error)
	}{
		{"default", helmTemplate},
		{"kata", helmTemplateKata},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.render(t)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			if strings.Contains(strings.ToLower(out), "tee-proxy") {
				t.Fatalf("render still references tee-proxy\n%s", out)
			}
		})
	}
}

// TestChartRejectsMalformedUpstreamAddress pins the catch-all upstream to the
// same charset guard every routes[].backend.address gets: an address with
// nginx metacharacters must fail the render, not corrupt the config.
func TestChartRejectsMalformedUpstreamAddress(t *testing.T) {
	// Clear the workload baseline and secure the manual upstream (https + verify)
	// so the render reaches the address-format check rather than tripping the
	// workload-conflict / unsecured-upstream guards first.
	out, err := helmTemplate(t, noUpstreamArgs(
		"--set-string", "tlsLb.upstream.address=bad addr;{}",
		"--set-string", "tlsLb.upstream.protocol=https",
		"--set", "tlsLb.upstream.tls.verify=true")...)
	if err == nil {
		t.Fatalf("helm template succeeded, want upstream address rejection\n%s", out)
	}
	assertHelmFailMessage(t, out, "tlsLb.upstream.address must be a host:port address without scheme, whitespace, semicolons, braces, slashes, or '#', got: bad addr;{}")
}

// TestChartRejectsLeftoverTeeProxyValues: helm silently ignores values keys
// the chart no longer reads, so a values file carried over from a release
// that still had tee-proxy would drop its settings (e.g. the hostPort
// opt-out) without a trace. The render must fail loud instead.
func TestChartRejectsLeftoverTeeProxyValues(t *testing.T) {
	out, err := helmTemplate(t, "--set", "teeProxy.hostPort.enabled=false")
	if err == nil {
		t.Fatalf("helm template succeeded, want removed_component failure\n%s", out)
	}
	if got := parseValidationErrorKind(out); got != "removed_component" {
		t.Fatalf("validation kind = %q, want removed_component\n%s", got, out)
	}
}

// TestChartGetCertRetriesInProcess proves the injected c8s-cert sidecar retries
// CDS in-process (--initial-retry-timeout) on the bootstrap fetch instead of
// exiting into kubelet CrashLoopBackOff on a transient CDS/mesh outage during
// a roll.
func TestChartGetCertRetriesInProcess(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	inits := renderedDeploymentInitContainers(t, out, "c8s-tls-lb")
	var cert *corev1.Container
	for i := range inits {
		if inits[i].Name == "c8s-cert" {
			cert = &inits[i]
		}
	}
	if cert == nil {
		t.Fatalf("tls-lb has no c8s-cert init container\n%s", out)
	}
	assertContainerHasArg(t, "c8s-cert", cert.Args, "--initial-retry-timeout=2m")
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
	Allowlist struct {
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
	} `yaml:"allowlist"`
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
// parent's default upstream wiring.
func helmTemplateTLSLB(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	base := []string{
		"template", "c8s", "c8s",
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "attestationApi.image.tag=dev",
		"--set", "cds.image.tag=dev",
		"--set", "ratlsMesh.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		"--set-string", "tlsLb.upstream.address=vllm:8000",
		// Secured (https + verify) upstream baseline for the tls-lb subchart
		// tests, on a bare vllm address. A manual address must be app-TLS now
		// that no default ships and there is no unmeshed acknowledgment; tests
		// that exercise a specific upstream protocol override it.
		"--set", "tlsLb.upstream.protocol=https",
		"--set", "tlsLb.upstream.tls.verify=true",
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
// set — one plaintext HTTP backend (/allowlist) and one RA-TLS-verified HTTPS
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
	//     # The catch-all upstream is dialed via a variable (see location /), so
	//     # nginx re-resolves it here at request time per record TTL. A static
	//     # upstream block would pin the pod IPs a headless-Service name (an
	//     # adopted workload) resolved to at startup and 502 after pod churn.
	//     resolver kube-dns.kube-system.svc.cluster.local;
	//     upstream route_0 {
	//         server c8s-cds.c8s-system.svc:8443;
	//     }
	//     upstream route_1 {
	//         server tenant-router.c8s-system.svc:8080;
	//     }
	//     server {
	//         listen 8443 ssl;
	//         server_name c8s-tls-lb.c8s-system.svc;
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
	//         # Headroom for upstream responses with large headers.
	//         proxy_buffer_size 16k;
	//         proxy_buffers 4 16k;
	//         # Route: /allowlist -> https://c8s-cds.c8s-system.svc:8443
	//         location = /allowlist {
	//
	//             proxy_ssl_server_name on;
	//             proxy_ssl_name c8s-cds.c8s-system.svc;
	//             proxy_ssl_verify on;
	//             proxy_ssl_verify_depth 2;
	//             proxy_ssl_trusted_certificate /tls/ca.pem;
	//             proxy_pass https://route_0;
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
	//
	//             proxy_ssl_certificate /tls/cert.pem;
	//             proxy_ssl_certificate_key /tls/key.pem;
	//             proxy_ssl_server_name on;
	//             proxy_ssl_name vllm;
	//             proxy_ssl_verify on;
	//             proxy_ssl_verify_depth 2;
	//             proxy_ssl_trusted_certificate /tls/cert.pem;
	//             set $backend_addr vllm:8000;
	//             proxy_pass https://$backend_addr;
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

// TestChartSeedsCDSAllowlistFromFloor proves the single authoritative floor
// (nriImagePolicy.bootstrapAllowlist.digests) plus the CDS image self-entry are
// rendered into CDS's --allowlist-seed ConfigMap, so CDS's served /allowlist is
// non-empty on the first worker pull. Decoded with the same typed Allowlist
// shape CDS parses, not substring-matched.
func TestChartSeedsCDSAllowlistFromFloor(t *testing.T) {
	const floorDigest = "sha256:abcdef0000000000000000000000000000000000000000000000000000000000"
	out, err := helmTemplate(t,
		"--set-string", "nriImagePolicy.bootstrapAllowlist.digests."+floorDigest+"=ghcr.io/x/coredns:v1",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	raw, ok := cm.Data["allowlist-seed.json"]
	if !ok {
		t.Fatalf("seed ConfigMap missing allowlist-seed.json key: %v", cm.Data)
	}

	seed, err := pkgallowlist.ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("seed JSON does not parse as a Allowlist (CDS would fail closed): %v\n%s", err, raw)
	}

	// The floor digest the operator supplied.
	if got := seed.Digests[floorDigest]; got != "ghcr.io/x/coredns:v1" {
		t.Errorf("seed floor digest = %q, want ghcr.io/x/coredns:v1\nseed: %v", got, seed.Digests)
	}
	// The CDS self-entry, derived from cds.image (set by the test harness to
	// digest ...0001); the reference is repository@digest.
	const cdsDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	const cdsRef = "ghcr.io/confidential-dot-ai/cds@" + cdsDigest
	if got := seed.Digests[cdsDigest]; got != cdsRef {
		t.Errorf("seed CDS self-entry = %q, want %q\nseed: %v", got, cdsRef, seed.Digests)
	}
}

// TestChartDerivesComponentDigestsIntoAllowlist proves that when the c8s
// component images are digest-pinned, each is auto-derived into the NRI
// allowlist seed with a repo@digest reference matching the rendered pod image —
// so a digest-pinned install self-allows the c8s components it deploys (#51).
func TestChartDerivesComponentDigestsIntoAllowlist(t *testing.T) {
	const (
		opD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a1"
		asD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a2"
		cdsD = "sha256:00000000000000000000000000000000000000000000000000000000000000a3"
		rmD  = "sha256:00000000000000000000000000000000000000000000000000000000000000a4"
		nriD = "sha256:00000000000000000000000000000000000000000000000000000000000000a5"
	)
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set-string", "image.digest="+opD,
		"--set-string", "attestationApi.image.digest="+asD,
		"--set-string", "cds.image.digest="+cdsD,
		"--set-string", "ratlsMesh.image.digest="+rmD,
		"--set-string", "nriImagePolicy.image.digest="+nriD,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}

	// Each derived entry's reference must be repo@digest for the image the chart
	// actually deploys (#51: refs match the rendered pod images).
	want := map[string]string{
		opD:  "ghcr.io/confidential-dot-ai/c8s-operator@" + opD,
		asD:  "ghcr.io/confidential-dot-ai/attestation-api@" + asD,
		cdsD: "ghcr.io/confidential-dot-ai/cds@" + cdsD,
		rmD:  "ghcr.io/confidential-dot-ai/ratls-mesh@" + rmD,
		nriD: "ghcr.io/confidential-dot-ai/nri-image-policy@" + nriD,
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
		if got := worker.Allowlist.AlwaysAllow[digest]; got != ref {
			t.Errorf("worker always_allow[%s] = %q, want %q\nalways_allow: %v", digest, got, ref, worker.Allowlist.AlwaysAllow)
		}
	}
}

// The tls-lb nginx image is a chart-deployed non-c8s system image: it is not in
// the tag-locked c8sComponents derive set, so a default install would otherwise
// leave it out of the allowlist and the NRI plugin would reject the tls-lb
// nginx container (#250). It must be self-seeded from its pinned digest whenever
// tls-lb is enabled — independent of deriveComponents (off here) — and dropped
// when tls-lb is disabled.
func TestChartAllowlistsTlsLbNginxSelfEntry(t *testing.T) {
	const (
		nxDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000b1"
		nxRepo   = "example.test/nginx-unprivileged"
	)
	t.Run("enabled: self-entry present without deriveComponents", func(t *testing.T) {
		out, err := helmTemplate(t,
			"--set-string", "tlsLb.nginx.image.repository="+nxRepo,
			"--set-string", "tlsLb.nginx.image.digest="+nxDigest,
		)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
		seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
		if err != nil {
			t.Fatalf("seed JSON does not parse: %v", err)
		}
		if got, want := seed.Digests[nxDigest], nxRepo+"@"+nxDigest; got != want {
			t.Errorf("tls-lb nginx self-entry = %q, want %q\nseed: %v", got, want, seed.Digests)
		}
	})

	t.Run("disabled: no self-entry", func(t *testing.T) {
		out, err := helmTemplate(t,
			"--set", "tlsLb.enabled=false",
			"--set-string", "tlsLb.nginx.image.repository="+nxRepo,
			"--set-string", "tlsLb.nginx.image.digest="+nxDigest,
		)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
		seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
		if err != nil {
			t.Fatalf("seed JSON does not parse: %v", err)
		}
		if _, ok := seed.Digests[nxDigest]; ok {
			t.Errorf("tls-lb nginx self-entry present with tls-lb disabled: %v", seed.Digests)
		}
	})
}

// installerBootConfig is a typed view of the image-policy.yaml the installer
// writes. It mirrors the fields of the plugin's own config
// (internal/cmds/nri-image-policy/config.go, which is unexported) needed by the
// chart tests, so assertions are against typed fields rather than substrings.
type installerBootConfig struct {
	Allowlist struct {
		AlwaysAllow map[string]string `yaml:"always_allow"`
		Pull        struct {
			URL string `yaml:"url"`
		} `yaml:"pull"`
		Push struct {
			PersistPath string `yaml:"persist_path"`
		} `yaml:"push"`
	} `yaml:"allowlist"`
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
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set-string", "cds.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000c5",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	// The single installer is pull-mode: it configures a pull URL and never a
	// push block. Asserting both confirms the typed decode landed on the boot
	// config document, not just that some YAML parsed.
	if wl := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist; wl.Pull.URL == "" || wl.Push.PersistPath != "" {
		t.Errorf("worker boot config should configure pull, not push: pull.url=%q push.persist_path=%q", wl.Pull.URL, wl.Push.PersistPath)
	}
}

// A fleet-supplied bootstrapAllowlist.digests entry must override a derived
// entry for the same sha256 (fleet values win).
func TestChartFleetAllowlistOverridesDerived(t *testing.T) {
	const cdsD = "sha256:00000000000000000000000000000000000000000000000000000000000000a3"
	out, err := helmTemplate(t,
		// deriveComponents on so cds.image.digest produces a derived entry for
		// the fleet `digests` value to override.
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set-string", "cds.image.digest="+cdsD,
		"--set-string", "nriImagePolicy.bootstrapAllowlist.digests."+cdsD+"=mirror.local/cds@"+cdsD,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v", err)
	}
	if got := seed.Digests[cdsD]; got != "mirror.local/cds@"+cdsD {
		t.Errorf("fleet override lost: %s = %q, want mirror.local/cds@%s\nseed: %v", cdsD, got, cdsD, seed.Digests)
	}
}

// deriveComponents is OFF by default (a demo convenience, like
// --resolve-digests): the seed carries only the CDS floor self-entry and
// operator-supplied digests, not the auto-derived component images. Covers both
// the default (unset) and an explicit =false. Rendered in audit mode so the
// deliberately-uncovered operator digest exercises derivation, not the
// fail-closed uncovered_component_digest guard.
func TestChartDeriveComponentsDefaultsOff(t *testing.T) {
	const opD = "sha256:00000000000000000000000000000000000000000000000000000000000000a1"
	const cdsDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"default unset", []string{"--set", "nriImagePolicy.policy.mode=audit", "--set-string", "image.digest=" + opD}},
		{"explicit false", []string{"--set", "nriImagePolicy.policy.mode=audit", "--set-string", "image.digest=" + opD, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
			seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
			if err != nil {
				t.Fatalf("seed JSON does not parse: %v", err)
			}
			if _, ok := seed.Digests[opD]; ok {
				t.Errorf("operator digest derived without deriveComponents: %v", seed.Digests)
			}
			// The CDS floor self-entry is always present, independent of derivation.
			if _, ok := seed.Digests[cdsDigest]; !ok {
				t.Errorf("CDS floor self-entry missing: %v", seed.Digests)
			}
		})
	}
}

// TestChartWiresCDSAllowlistSeedFlagAndVolume proves the CDS container receives
// --allowlist-seed pointing at a read-only mount of the seed ConfigMap. The CDS
// pod runs readOnlyRootFilesystem, so the seed must be a read-only volume, not a
// writable path.
func TestChartWiresCDSAllowlistSeedFlagAndVolume(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	assertContainerHasArg(t, "cds", cds.Args, "--allowlist-seed=/etc/cds/allowlist-seed.json")

	mount, ok := containerVolumeMount(cds, "allowlist-seed")
	if !ok {
		t.Fatalf("cds container missing allowlist-seed volume mount; mounts=%v", cds.VolumeMounts)
	}
	if mount.MountPath != "/etc/cds" {
		t.Errorf("allowlist-seed mountPath = %q, want /etc/cds", mount.MountPath)
	}
	if !mount.ReadOnly {
		t.Errorf("allowlist-seed mount must be readOnly (cds has readOnlyRootFilesystem)")
	}

	vol, ok := podVolume(renderedDeployment(t, out, "c8s-cds").Spec.Template.Spec, "allowlist-seed")
	if !ok {
		t.Fatalf("cds pod missing allowlist-seed volume")
	}
	if vol.ConfigMap == nil || vol.ConfigMap.Name != "c8s-cds-allowlist-seed" {
		t.Errorf("allowlist-seed volume should source ConfigMap c8s-cds-allowlist-seed; got %+v", vol.ConfigMap)
	}
}

// With host NRI disabled and no kata, nothing consumes CDS's served allowlist,
// so the seed wiring must drop out entirely.
func TestChartOmitsCDSSeedWhenImagePolicyDisabled(t *testing.T) {
	out, err := helmTemplate(t, "--set", "nriImagePolicy.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "ConfigMap", "c8s-cds-allowlist-seed") {
		t.Fatalf("seed ConfigMap should not render when nriImagePolicy is disabled")
	}
	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	assertContainerNoArgPrefix(t, "cds", cds.Args, "--allowlist-seed")
}

// Under kata the host NRI plugin is off, but admission is the in-guest
// policy-monitor fed from CDS's served allowlist, so the seed must still render.
// Otherwise adopted --workload-ref digests (in bootstrapAllowlist.digests) never
// reach CDS and the in-guest monitor denies those images.
func TestChartRendersCDSSeedUnderKata(t *testing.T) {
	const (
		wlDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000a1"
		wlRepo   = "example.test/vllm-router"
	)
	out, err := helmTemplateKata(t,
		"--set-string", "nriImagePolicy.bootstrapAllowlist.digests."+wlDigest+"="+wlRepo+"@"+wlDigest,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	if got, want := seed.Digests[wlDigest], wlRepo+"@"+wlDigest; got != want {
		t.Errorf("adopted workload digest not in kata seed = %q, want %q\nseed: %v", got, want, seed.Digests)
	}
	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	if !slices.Contains(cds.Args, "--allowlist-seed=/etc/cds/allowlist-seed.json") {
		t.Errorf("cds missing --allowlist-seed flag under kata\nargs: %v", cds.Args)
	}
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
// whose digest is absent from bootstrapAllowlist.digests would be denied on its
// own node, so the chart fails the render. cds.image is exempt (always seeded).
func TestChartRejectsUncoveredComponentInFailClosed(t *testing.T) {
	// A digest distinct from the harness floor (baseNRIDigest), so it is
	// genuinely uncovered unless a case below covers it.
	const nriD = "sha256:bbbb000000000000000000000000000000000000000000000000000000000000"

	// Uncovered: nriImagePolicy.image is digest-pinned but not in digests,
	// deriveComponents off, fail-closed -> guard fires.
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.policy.mode=fail-closed",
		"--set-string", "nriImagePolicy.image.digest="+nriD,
	)
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
		{"audit mode is non-blocking", []string{"--set-string", "nriImagePolicy.image.digest=" + nriD, "--set", "nriImagePolicy.policy.mode=audit"}},
		{"deriveComponents covers it", []string{"--set-string", "nriImagePolicy.image.digest=" + nriD, "--set", "nriImagePolicy.policy.mode=fail-closed", "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"}},
		{"digest listed in floor", []string{"--set-string", "nriImagePolicy.image.digest=" + nriD, "--set", "nriImagePolicy.policy.mode=fail-closed", "--set-string", "nriImagePolicy.bootstrapAllowlist.digests." + nriD + "=ghcr.io/confidential-dot-ai/nri-image-policy@" + nriD}},
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
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "attestationApi.image.tag=dev",
		"--set", "cds.image.tag=dev",
		"--set", "ratlsMesh.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		// discovery defaults to enabled; scope this example to route rendering
		// (discovery's own locations are covered by a dedicated test above).
		"--set", "tlsLb.discovery.enabled=false",
		"--set-string", "tlsLb.upstream.address=vllm:8000",
		"--set", "tlsLb.upstream.protocol=https",
		"--set", "tlsLb.upstream.tls.verify=true",
		"--set", "tlsLb.nginx.image.tag=dev",
		"--set-string", "tlsLb.routes[0].path=/allowlist",
		"--set-string", "tlsLb.routes[0].match=exact",
		"--set-string", "tlsLb.routes[0].backend.address=c8s-cds.c8s-system.svc:8443",
		"--set-string", "tlsLb.routes[0].backend.protocol=https",
		"--set", "tlsLb.routes[0].backend.tls.verify=true",
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

// --- install-time image pull secret (imagePullSecret, a Secret name) ---

// pullSecretNames flattens an imagePullSecrets list to the referenced names.
func pullSecretNames(refs []corev1.LocalObjectReference) []string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Name)
	}
	return names
}

// The invariant the value exists for: every pod the default chart ships can
// authenticate its image pull from first start — either its pod spec lists the
// install-time Secret or its ServiceAccount does (kubelet merges both). And
// the chart must not render a Secret of its own: the named Secret pre-exists
// (kubectl / external-secrets), and helm cannot adopt an object it does not
// own, so rendering one would abort the install.
func TestChartImagePullSecretReachesEveryPodSpecWithoutCreatingASecret(t *testing.T) {
	out, err := helmTemplate(t, "--set-string", "imagePullSecret=ghcr-secret")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	const secretName = "ghcr-secret"

	if kinds := renderedKinds(t, out); kinds["Secret"] > 0 {
		t.Errorf("imagePullSecret mode rendered %d Secret(s), want 0 (the Secret pre-exists)", kinds["Secret"])
	}

	sasWithSecret := map[string]bool{}
	iterateManifests(t, out, func(doc []byte) bool {
		var sa corev1.ServiceAccount
		if err := sigsyaml.Unmarshal(doc, &sa); err != nil || sa.Kind != "ServiceAccount" {
			return false
		}
		if slices.Contains(pullSecretNames(sa.ImagePullSecrets), secretName) {
			sasWithSecret[sa.Name] = true
		}
		return false
	})

	type workload struct {
		kind, name string
		spec       corev1.PodSpec
	}
	var workloads []workload
	iterateManifests(t, out, func(doc []byte) bool {
		var obj struct {
			docMeta
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		switch obj.Kind {
		case "Deployment", "DaemonSet", "Job":
			workloads = append(workloads, workload{obj.Kind, obj.Metadata.Name, obj.Spec.Template.Spec})
		}
		return false
	})
	// The default render ships at least operator, cds, and tls-lb Deployments
	// plus the attestation-api, ratls-mesh, and nri-image-policy DaemonSets;
	// fewer means the decode regressed and the loop below passes vacuously.
	if len(workloads) < 6 {
		t.Fatalf("decoded only %d pod-bearing workloads, want >= 6", len(workloads))
	}

	for _, w := range workloads {
		if slices.Contains(pullSecretNames(w.spec.ImagePullSecrets), secretName) {
			continue
		}
		if sasWithSecret[w.spec.ServiceAccountName] {
			continue
		}
		t.Errorf("%s %q can't reach the pull secret: pod spec lists %v, serviceAccount %q",
			w.kind, w.name, pullSecretNames(w.spec.ImagePullSecrets), w.spec.ServiceAccountName)
	}
}

// A component-local imagePullSecrets override replaces the chart-wide list but
// must NOT shed the install-time Secret — otherwise adding a credential for an
// extra registry would silently break pulling the component's own image.
func TestChartImagePullSecretAppendsToComponentLocalOverride(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "imagePullSecret=ghcr-secret",
		"--set", "tlsLb.imagePullSecrets[0].name=extra")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var names []string
	iterateManifests(t, out, func(doc []byte) bool {
		var obj struct {
			docMeta
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil || obj.Kind != "Deployment" || obj.Metadata.Name != "c8s-tls-lb" {
			return false
		}
		names = pullSecretNames(obj.Spec.Template.Spec.ImagePullSecrets)
		return true
	})
	for _, want := range []string{"extra", "ghcr-secret"} {
		if !slices.Contains(names, want) {
			t.Errorf("tls-lb imagePullSecrets = %v, missing %q", names, want)
		}
	}
}

// An operator who also lists the install-time Secret explicitly in the
// chart-wide imagePullSecrets must not get a duplicate entry.
func TestChartImagePullSecretDedupsExplicitReference(t *testing.T) {
	out, err := helmTemplate(t,
		"--set-string", "imagePullSecret=ghcr-secret",
		"--set", "imagePullSecrets[0].name=ghcr-secret")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := findRATLSMeshDaemonSet(t, out)
	names := pullSecretNames(ds.Spec.Template.Spec.ImagePullSecrets)
	want := []string{"ghcr-secret"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("ratls-mesh imagePullSecrets = %v, want %v (no duplicate)", names, want)
	}
}

// Without imagePullSecret (and with the imagePullSecrets lists empty), no
// manifest may carry an imagePullSecrets block at all — the with-guard in the
// c8s.imagePullSecrets helper must keep suppressing empty lists.
func TestChartDefaultRendersNoPullSecretRefs(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if strings.Contains(out, "imagePullSecrets") {
		t.Errorf("default render carries an imagePullSecrets block\n%s", out)
	}
}

// pullerDockercfgSecret returns the Secret name the kata-image-puller's
// dockercfg projected volume references, or "" when the volume is absent
// (anonymous oras pull). Fails the test if the puller DaemonSet is missing.
func pullerDockercfgSecret(t *testing.T, helmOut string) string {
	t.Helper()
	name := ""
	found := false
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var ds appsv1.DaemonSet
		if err := sigsyaml.Unmarshal(doc, &ds); err != nil || ds.Kind != "DaemonSet" || ds.Name != "c8s-kata-deploy-image-puller" {
			return false
		}
		found = true
		for _, v := range ds.Spec.Template.Spec.Volumes {
			if v.Name != "dockercfg" || v.Projected == nil {
				continue
			}
			for _, s := range v.Projected.Sources {
				if s.Secret != nil {
					name = s.Secret.Name
				}
			}
		}
		return true
	})
	if !found {
		t.Fatalf("kata-image-puller DaemonSet not found in helm template output\n%s", helmOut)
	}
	return name
}

// The puller's in-pod `oras pull` ignores kubelet imagePullSecrets, so the
// install-time pull secret must also feed its dockercfg mount — otherwise
// `c8s install --image-pull-secret` would cover every kubelet pull but leave
// the kata-guest-base fetch anonymous (401 against a private registry).
func TestChartImagePullSecretFeedsKataImagePuller(t *testing.T) {
	out, err := helmTemplateKata(t,
		"--set-string", "imagePullSecret=ghcr-secret")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := pullerDockercfgSecret(t, out); got != "ghcr-secret" {
		t.Errorf("puller dockercfg secret = %q, want ghcr-secret", got)
	}
}

// An explicit pullerAuthSecret wins over the imagePullSecret default — the
// guest-base artifact may need a different credential than the c8s images.
func TestChartKataPullerAuthSecretOverridesImagePullSecret(t *testing.T) {
	out, err := helmTemplateKata(t,
		"--set-string", "imagePullSecret=ghcr-secret",
		"--set-string", "kata.guestImage.pullerAuthSecret=other-creds")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := pullerDockercfgSecret(t, out); got != "other-creds" {
		t.Errorf("puller dockercfg secret = %q, want other-creds", got)
	}
}

// pullerEnv returns the value of the named env var on the kata-image-puller's
// container. Fails the test if the puller DaemonSet is missing.
func pullerEnv(t *testing.T, helmOut, name string) string {
	t.Helper()
	val := ""
	found := false
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var ds appsv1.DaemonSet
		if err := sigsyaml.Unmarshal(doc, &ds); err != nil || ds.Kind != "DaemonSet" || ds.Name != "c8s-kata-deploy-image-puller" {
			return false
		}
		found = true
		for _, c := range ds.Spec.Template.Spec.Containers {
			for _, e := range c.Env {
				if e.Name == name {
					val = e.Value
				}
			}
		}
		return true
	})
	if !found {
		t.Fatalf("kata-image-puller DaemonSet not found in helm template output\n%s", helmOut)
	}
	return val
}

// kata.guestImage.debug must repoint the puller at the `<tag>-debug` artifact
// — the variant whose guest policy allows host log/exec streams (published in
// lockstep by the kata-guest-base workflow; `c8s install --kata --debug` sets
// the value). Default off: a plain kata install pulls the locked image.
func TestChartKataGuestImageDebugSelectsDebugTag(t *testing.T) {
	out, err := helmTemplateKata(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := pullerEnv(t, out, "TAG"); got != "main" {
		t.Errorf("default puller TAG = %q, want main (locked image)", got)
	}

	out, err = helmTemplateKata(t, "--set", "kata.guestImage.debug=true")
	if err != nil {
		t.Fatalf("helm template (debug): %v\n%s", err, out)
	}
	if got := pullerEnv(t, out, "TAG"); got != "main-debug" {
		t.Errorf("debug puller TAG = %q, want main-debug", got)
	}
}

// GPU in-guest registry auth: "" inherits the non-GPU setting (the GPU guest
// bakes the same auth.json), "none" forces anonymous, anything else wins
// verbatim — the contract documented on kata.gpu.guestImage.registryAuth.
func TestChartKataGpuRegistryAuthInheritance(t *testing.T) {
	gpuAuth := func(t *testing.T, args ...string) string {
		t.Helper()
		out, err := helmTemplateKata(t, args...)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		puller := renderedDaemonSet(t, out, "c8s-kata-deploy-image-puller-nvidia")
		pc, ok := findContainer(puller.Spec.Template.Spec.Containers, "reconcile")
		if !ok {
			t.Fatalf("GPU puller missing reconcile container")
		}
		return envValue(pc.Env, "REGISTRY_AUTH")
	}
	if got := gpuAuth(t); got != "file:///run/image-security/auth.json" {
		t.Errorf("default GPU REGISTRY_AUTH = %q, want the inherited non-GPU baked-auth path", got)
	}
	if got := gpuAuth(t, "--set-string", "kata.gpu.guestImage.registryAuth=none"); got != "" {
		t.Errorf(`registryAuth=none GPU REGISTRY_AUTH = %q, want "" (anonymous)`, got)
	}
	if got := gpuAuth(t, "--set-string", "kata.gpu.guestImage.registryAuth=kbs:///default/creds/gpu"); got != "kbs:///default/creds/gpu" {
		t.Errorf("explicit registryAuth GPU REGISTRY_AUTH = %q, want the verbatim override", got)
	}
}

// kata.guestImage.debug must vary the GPU guest tag in lockstep with the
// non-GPU one: CI publishes `<tag>-nvidia` and `<tag>-nvidia-debug` together
// (kata-guest-base.yml build job, build.sh Step 6) — see
// c8s.kataGuestImageNvidiaTag.
func TestChartKataGuestImageDebugDerivesNvidiaDebugTag(t *testing.T) {
	out, err := helmTemplateKata(t, "--set", "kata.guestImage.debug=true")
	if err != nil {
		t.Fatalf("helm template (debug): %v\n%s", err, out)
	}
	puller := renderedDaemonSet(t, out, "c8s-kata-deploy-image-puller-nvidia")
	pc, ok := findContainer(puller.Spec.Template.Spec.Containers, "reconcile")
	if !ok {
		t.Fatalf("GPU puller missing reconcile container")
	}
	if got := envValue(pc.Env, "TAG"); got != "main-nvidia-debug" {
		t.Errorf("GPU puller TAG under debug = %q, want main-nvidia-debug (published in lockstep with main-nvidia)", got)
	}
	if got := envValue(pc.Env, "KATA_DEBUG"); got != "true" {
		t.Errorf("GPU puller KATA_DEBUG under debug = %q, want true", got)
	}
}

// With neither value set the pull stays anonymous: no dockercfg volume at all
// (the default shape — the published artifacts are public).
func TestChartKataPullerAnonymousWithoutSecrets(t *testing.T) {
	out, err := helmTemplateKata(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if got := pullerDockercfgSecret(t, out); got != "" {
		t.Errorf("puller dockercfg secret = %q, want none (anonymous pull)", got)
	}
}

// tlsLbUpstreamAddress returns the address from the catch-all location's
// `set $backend_addr <addr>;` directive in the rendered tls-lb nginx config.
func tlsLbUpstreamAddress(t *testing.T, manifest string) string {
	t.Helper()
	sets := renderedTLSLBNginxConfig(t, manifest).location(t, "prefix", "/").directives["set"]
	for _, args := range sets {
		if len(args) == 2 && args[0] == "$backend_addr" {
			return args[1]
		}
	}
	t.Fatalf("location / has no `set $backend_addr <addr>;` directive; got %v", sets)
	return ""
}

// TestChartTLSLBUpstreamChoice: there is no default upstream. An unset upstream
// is a legal install-then-attach state (tls-lb serves with no catch-all); when
// an upstream IS set that is not a c8s-<id> headless Service it must be https
// with tls.verify=true (app-TLS) — a plaintext http address or unverified https
// fails instead of shipping a silently-plaintext hop.
func TestChartTLSLBUpstreamChoice(t *testing.T) {
	// No upstream renders a healthy front door with NO catch-all: the operator
	// attaches a workload later via --upstream. The cert, discovery, and
	// /healthz still render; only location / is withheld.
	t.Run("no-upstream-renders-without-catch-all", func(t *testing.T) {
		out, err := helmTemplate(t, noUpstreamArgs()...)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		cfg := renderedTLSLBNginxConfig(t, out)
		if _, ok := cfg.locations[nginxLocationKey{match: "prefix", path: "/"}]; ok {
			t.Fatalf("no upstream should render no catch-all location /, but one is present\n%s", out)
		}
		// The front door is still healthy and serving.
		cfg.location(t, "prefix", "/healthz")
	})

	// An https upstream with tls.verify (verify defaults to true) terminates and
	// authenticates TLS itself: that hop is app-TLS, the only manual-address
	// shape the guard admits, and the address passes through verbatim.
	t.Run("verified-https-upstream-passes-verbatim", func(t *testing.T) {
		out, err := helmTemplate(t, noUpstreamArgs(
			"--set-string", "tlsLb.upstream.address=my-backend.other-ns.svc:8443",
			"--set", "tlsLb.upstream.protocol=https")...)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		if got, want := tlsLbUpstreamAddress(t, out), "my-backend.other-ns.svc:8443"; got != want {
			t.Fatalf("upstream = %q, want %q", got, want)
		}
	})

	// A disabled tls-lb needs no upstream, and a leftover upstream (e.g. a
	// migration that flips tlsLb.enabled=false without clearing the value)
	// must not trip the secured-backend check: the unmeshed-hop risk cannot
	// occur when tls-lb renders nothing.
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"tlslb-disabled-needs-no-upstream", noUpstreamArgs("--set", "tlsLb.enabled=false")},
		{"tlslb-disabled-ignores-leftover-upstream", noUpstreamArgs(
			"--set", "tlsLb.enabled=false",
			"--set-string", "tlsLb.upstream.address=my-router.ns.svc:9000")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			// The render must not just succeed: a disabled tls-lb must emit no
			// Deployment, so no upstream (leftover or otherwise) can ship.
			if renderedManifestHasNamedKind(t, out, "Deployment", "c8s-tls-lb") {
				t.Fatalf("tlsLb.enabled=false still rendered a c8s-tls-lb Deployment\n%s", out)
			}
		})
	}
}

func TestChartUpstreamValidation(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		kind string
	}{
		{
			// A c8s-<id> headless-Service address is recognized as mesh-wrapped
			// (plaintext http, the mesh secures it), so https can only fail at runtime.
			name: "mesh-wrapped-https",
			args: []string{
				"--set-string", "tlsLb.upstream.address=c8s-infer.c8s-system.svc.cluster.local:8000",
				"--set", "tlsLb.upstream.protocol=https",
			},
			kind: "workload_https_upstream",
		},
		{
			// A plaintext http manual upstream cannot render: there is no
			// acknowledgment, only https + verify is admitted.
			name: "http-upstream",
			args: noUpstreamArgs("--set-string", "tlsLb.upstream.address=my-router.ns.svc:9000"),
			kind: "tlslb_unsecured_upstream",
		},
		{
			// https alone does not secure the hop: verify=false is an
			// encrypted-but-unauthenticated backend, rejected like http.
			name: "unverified-https-upstream",
			args: noUpstreamArgs(
				"--set-string", "tlsLb.upstream.address=my-router.ns.svc:8443",
				"--set", "tlsLb.upstream.protocol=https",
				"--set", "tlsLb.upstream.tls.verify=false"),
			kind: "tlslb_unsecured_upstream",
		},
		{
			// A near-miss of the c8s-<id>.<ns>.svc.cluster.local shape (here the
			// short .svc form) is NOT recognized as mesh-wrapped, so plaintext
			// http fails closed: only the exact headless-Service FQDN gets the
			// plaintext pass. Guards the shape regex against being too loose.
			name: "c8s-shape-short-svc-not-meshwrapped",
			args: noUpstreamArgs("--set-string", "tlsLb.upstream.address=c8s-infer.vllm.svc:8000"),
			kind: "tlslb_unsecured_upstream",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := helmTemplate(t, tt.args...)
			if err == nil {
				t.Fatalf("helm template succeeded, want %s failure\n%s", tt.kind, out)
			}
			if got := parseValidationErrorKind(out); got != tt.kind {
				t.Fatalf("validation kind = %q, want %q\n%s", got, tt.kind, out)
			}
		})
	}
}

// TestChartTLSLBUpstreamDefaultEmpty guards the no-default-upstream invariant:
// a shipped default would silently render a catch-all and could put the
// inference hop back on an unmeshed Service VIP. Empty keeps the front door
// catch-all-free until an upstream is deliberately wired.
func TestChartTLSLBUpstreamDefaultEmpty(t *testing.T) {
	data, err := os.ReadFile("c8s/values.yaml")
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	var values struct {
		TLSLB struct {
			Upstream struct {
				Address string `yaml:"address"`
			} `yaml:"upstream"`
		} `yaml:"tlsLb"`
	}
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("unmarshal values.yaml: %v", err)
	}
	if values.TLSLB.Upstream.Address != "" {
		t.Fatalf("tlsLb.upstream.address default = %q, want empty: a shipped default silently renders a catch-all and can leave the hop unmeshed", values.TLSLB.Upstream.Address)
	}
}

// TestCDSPodDisruptionBudget guards the singleton trust root: the PDB must
// default to maxUnavailable: 0 (block voluntary drains so the in-memory CA is
// not silently evicted) and its selector must actually match the CDS
// Deployment's pods, not select nothing.
func TestCDSPodDisruptionBudget(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	var pdb policyv1.PodDisruptionBudget
	if !findDoc(t, out, "PodDisruptionBudget", "c8s-cds", &pdb) {
		t.Fatalf("rendered manifest missing CDS PodDisruptionBudget\n%s", out)
	}
	if pdb.Spec.MaxUnavailable == nil || pdb.Spec.MaxUnavailable.IntValue() != 0 {
		t.Fatalf("CDS PDB maxUnavailable = %v, want 0 (block voluntary disruption of the singleton trust root)", pdb.Spec.MaxUnavailable)
	}

	// The PDB selector must match the CDS Deployment's pod template labels, or
	// it protects nothing.
	dep := renderedDeployment(t, out, "c8s-cds")
	for k, v := range pdb.Spec.Selector.MatchLabels {
		if got := dep.Spec.Template.Labels[k]; got != v {
			t.Fatalf("CDS PDB selector %s=%q does not match Deployment pod label %q; PDB would select no pods", k, v, got)
		}
	}

	t.Run("maxUnavailable override", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "cds.podDisruptionBudget.maxUnavailable=1")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		var pdb policyv1.PodDisruptionBudget
		if !findDoc(t, out, "PodDisruptionBudget", "c8s-cds", &pdb) {
			t.Fatalf("rendered manifest missing CDS PodDisruptionBudget\n%s", out)
		}
		if pdb.Spec.MaxUnavailable == nil || pdb.Spec.MaxUnavailable.IntValue() != 1 {
			t.Fatalf("CDS PDB maxUnavailable = %v, want 1", pdb.Spec.MaxUnavailable)
		}
	})

	t.Run("disabled removes the PDB", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "cds.podDisruptionBudget.enabled=false")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		var pdb policyv1.PodDisruptionBudget
		if findDoc(t, out, "PodDisruptionBudget", "c8s-cds", &pdb) {
			t.Fatal("CDS PodDisruptionBudget rendered while podDisruptionBudget.enabled=false")
		}
	})
}

// TestAttestationApiSeccomp pins the seccomp profile on the attestation-api
// container. It must run privileged (device-cgroup access to the TEE device),
// but seccomp is independent of privileged and RuntimeDefault narrows the
// syscall surface of the node's widest container; it is easy to drop silently.
func TestAttestationApiSeccomp(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-attestation-api")
	c, ok := findContainer(ds.Spec.Template.Spec.Containers, "attestation-api")
	if !ok {
		t.Fatalf("attestation-api container not found; got %v", containerNames(ds.Spec.Template.Spec.Containers))
	}
	sc := c.SecurityContext
	if sc == nil || sc.Privileged == nil || !*sc.Privileged {
		t.Fatalf("attestation-api must be privileged (TEE device access); got %+v", sc)
	}
	if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("attestation-api must set seccompProfile.type: RuntimeDefault; got %+v", sc.SeccompProfile)
	}
}
