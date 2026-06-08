//go:build !c8s_node

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/lunal-dev/c8s/internal/helmchart"
)

var errTestResolve = errors.New("simulated resolve failure")

func TestDefaultInstallImageTag(t *testing.T) {
	tests := []struct {
		name         string
		buildVersion string
		want         string
	}{
		{name: "release tag used verbatim", buildVersion: "v0.1.0", want: "v0.1.0"},
		{name: "empty falls back", buildVersion: "", want: "main"},
		{name: "unstamped default falls back", buildVersion: "dev", want: "main"},
		{name: "git describe derivative falls back", buildVersion: "v0.1.0-5-gabc1234", want: "main"},
		{name: "dirty tree falls back", buildVersion: "v0.1.0-dirty", want: "main"},
		{name: "bare commit sha falls back", buildVersion: "abc1234", want: "main"},
		{name: "branch name falls back", buildVersion: "feat-phase5-chart-docs", want: "main"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultInstallImageTag(tt.buildVersion)
			if got != tt.want {
				t.Fatalf("defaultInstallImageTag(%q) = %q, want %q", tt.buildVersion, got, tt.want)
			}
		})
	}
}

func TestNamespaceManifestSetsPrivilegedPodSecurityLabels(t *testing.T) {
	data, err := namespaceManifest("c8s-system")
	if err != nil {
		t.Fatalf("namespaceManifest: %v", err)
	}

	var ns corev1.Namespace
	if err := json.Unmarshal(data, &ns); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, data)
	}

	if ns.APIVersion != "v1" || ns.Kind != "Namespace" {
		t.Fatalf("manifest TypeMeta = %s/%s, want v1/Namespace", ns.APIVersion, ns.Kind)
	}
	if ns.Name != "c8s-system" {
		t.Fatalf("manifest name = %q, want c8s-system", ns.Name)
	}
	// The install always ships privileged pods, so the namespace must permit
	// them regardless of flags; a CIS-hardened cluster default would otherwise
	// reject them at admission.
	for _, mode := range []string{"enforce", "warn", "audit"} {
		key := "pod-security.kubernetes.io/" + mode
		if got := ns.Labels[key]; got != "privileged" {
			t.Fatalf("label %s = %q, want privileged", key, got)
		}
	}
}

func TestAppendInstallCRDArgsDisablesStatusMirrorWhenSkippingCRDs(t *testing.T) {
	got := appendInstallCRDArgs([]string{"upgrade"}, false)
	want := []string{"upgrade", "--skip-crds", "--set", "statusMirror.enabled=false"}
	if len(got) != len(want) {
		t.Fatalf("args length = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; got %v", i, got[i], want[i], got)
		}
	}
}

func TestAppendInstallCRDArgsLeavesStatusMirrorEnabledWithCRDs(t *testing.T) {
	got := appendInstallCRDArgs([]string{"upgrade"}, true)
	want := []string{"upgrade"}
	if len(got) != len(want) {
		t.Fatalf("args length = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; got %v", i, got[i], want[i], got)
		}
	}
}

func TestAppendKataInstallArgsDisabledIsNoOp(t *testing.T) {
	got := appendKataInstallArgs([]string{"upgrade"}, false, false)
	assertArgsEqual(t, got, []string{"upgrade"})
}

func TestAppendKataInstallArgsEnabled(t *testing.T) {
	got := appendKataInstallArgs([]string{"upgrade"}, true, false)
	assertArgsEqual(t, got, []string{"upgrade", "--set", "kata.enabled=true"})
}

func TestAppendKataInstallArgsEnforceImpliesEnabled(t *testing.T) {
	// --kata-enforce alone (kata=false) must still install the kata stack.
	got := appendKataInstallArgs([]string{"upgrade"}, false, true)
	assertArgsEqual(t, got, []string{
		"upgrade",
		"--set", "kata.enabled=true",
		"--set", "kata.enforce.enabled=true",
	})
}

func TestAppendSingleNodeInstallArgsDisabledIsNoOp(t *testing.T) {
	got := appendSingleNodeInstallArgs([]string{"upgrade"}, false)
	assertArgsEqual(t, got, []string{"upgrade"})
}

func TestAppendSingleNodeInstallArgsClearsCDSNodePinning(t *testing.T) {
	// --single-node must null both the selector (drops the role=cds pin and
	// collapses the installer split) and the tolerations (the dedicated-node
	// taint is meaningless without a dedicated node).
	got := appendSingleNodeInstallArgs([]string{"upgrade"}, true)
	assertArgsEqual(t, got, []string{
		"upgrade",
		"--set", "cds.node.selector=null",
		"--set", "cds.node.tolerations=null",
	})
}

func TestAppendDistroInstallArgsSetsBothComponents(t *testing.T) {
	// --distro feeds both the kata-deploy and nri-image-policy installers;
	// nri-image-policy installs regardless of --kata, so distro always applies.
	for _, distro := range []string{"k8s", "rke2"} {
		t.Run(distro, func(t *testing.T) {
			got, err := appendDistroInstallArgs([]string{"upgrade"}, distro)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertArgsEqual(t, got, []string{
				"upgrade",
				"--set-string", "kata.distro=" + distro,
				"--set-string", "nriImagePolicy.distro=" + distro,
			})
		})
	}
}

func TestAppendDistroInstallArgsRejectsUnknownDistro(t *testing.T) {
	if _, err := appendDistroInstallArgs([]string{"upgrade"}, "openshift"); err == nil {
		t.Fatal("appendDistroInstallArgs accepted an unknown --distro, want error")
	}
}

func TestAppendCvmModeInstallArgsSetsAttestationApiValue(t *testing.T) {
	for _, mode := range []string{"baremetal", "managed"} {
		t.Run(mode, func(t *testing.T) {
			got, err := appendCvmModeInstallArgs([]string{"upgrade"}, mode)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertArgsEqual(t, got, []string{
				"upgrade",
				"--set-string", "attestationApi.cvmMode=" + mode,
			})
		})
	}
}

func TestAppendCvmModeInstallArgsRejectsUnknownMode(t *testing.T) {
	if _, err := appendCvmModeInstallArgs([]string{"upgrade"}, "azure"); err == nil {
		t.Fatal("appendCvmModeInstallArgs accepted an unknown --cvm-mode, want error")
	}
}

// testComponents mirrors the chart's c8sComponents for the resolver tests,
// which exercise buildDigestArgs without reading a real chart. The chart-read
// path (chartComponents) is covered separately by TestChartComponentsFromValues.
var testComponents = []c8sComponent{
	{"image", "ghcr.io/lunal-dev/c8s-operator"},
	{"attestationApi.image", "ghcr.io/lunal-dev/attestation-api"},
	{"cds.image", "ghcr.io/lunal-dev/cds"},
	{"ratlsMesh.image", "ghcr.io/lunal-dev/ratls-mesh"},
	{"nriImagePolicy.image", "ghcr.io/lunal-dev/nri-image-policy"},
	{"teeProxy.image", "ghcr.io/lunal-dev/tee-proxy"},
}

func TestBuildDigestArgsPinsEveryComponent(t *testing.T) {
	// Deterministic fake resolver: digest derived from the ref so each
	// component gets a distinct, predictable value.
	resolve := func(ref string) (string, error) {
		switch ref {
		case "ghcr.io/lunal-dev/c8s-operator:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000aa", nil
		case "ghcr.io/lunal-dev/attestation-api:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000bb", nil
		case "ghcr.io/lunal-dev/cds:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000cc", nil
		case "ghcr.io/lunal-dev/ratls-mesh:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000dd", nil
		case "ghcr.io/lunal-dev/nri-image-policy:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000ee", nil
		case "ghcr.io/lunal-dev/tee-proxy:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000ff", nil
		}
		t.Fatalf("unexpected ref resolved: %q", ref)
		return "", nil
	}

	got, err := buildDigestArgs([]string{"upgrade"}, "v1", testComponents, resolve)
	if err != nil {
		t.Fatalf("buildDigestArgs: %v", err)
	}
	assertArgsEqual(t, got, []string{
		"upgrade",
		// Each component pins both repository and digest so an -f repository
		// override cannot diverge from the digest resolved against it.
		"--set-string", "image.repository=ghcr.io/lunal-dev/c8s-operator",
		"--set-string", "image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000aa",
		"--set-string", "attestationApi.image.repository=ghcr.io/lunal-dev/attestation-api",
		"--set-string", "attestationApi.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000bb",
		"--set-string", "cds.image.repository=ghcr.io/lunal-dev/cds",
		"--set-string", "cds.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000cc",
		"--set-string", "ratlsMesh.image.repository=ghcr.io/lunal-dev/ratls-mesh",
		"--set-string", "ratlsMesh.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000dd",
		"--set-string", "nriImagePolicy.image.repository=ghcr.io/lunal-dev/nri-image-policy",
		"--set-string", "nriImagePolicy.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000ee",
		"--set-string", "teeProxy.image.repository=ghcr.io/lunal-dev/tee-proxy",
		"--set-string", "teeProxy.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000ff",
		// Resolving component digests enables their derivation into the NRI allowlist.
		"--set", "nriImagePolicy.bootstrapWhitelist.deriveComponents=true",
	})
}

// Each component repository is resolved at most once per install (no wasted
// registry round-trips).
func TestBuildDigestArgsResolvesEachComponentOnce(t *testing.T) {
	calls := map[string]int{}
	resolve := func(ref string) (string, error) {
		calls[ref]++
		return "sha256:1111111111111111111111111111111111111111111111111111111111111111", nil
	}
	if _, err := buildDigestArgs(nil, "v1", testComponents, resolve); err != nil {
		t.Fatalf("buildDigestArgs: %v", err)
	}
	for ref, n := range calls {
		if n != 1 {
			t.Errorf("ref %q resolved %d times, want 1", ref, n)
		}
	}
}

// A resolution failure for any component must abort: a partially pinned floor
// would pass the render guard while the served whitelist pointed at a wrong or
// missing digest.
func TestBuildDigestArgsFailsClosedOnResolveError(t *testing.T) {
	resolve := func(ref string) (string, error) {
		if ref == "ghcr.io/lunal-dev/cds:v1" {
			return "", errTestResolve
		}
		return "sha256:2222222222222222222222222222222222222222222222222222222222222222", nil
	}
	if _, err := buildDigestArgs(nil, "v1", testComponents, resolve); err == nil {
		t.Fatal("buildDigestArgs ignored a resolver error, want fail-closed")
	}
}

// chartComponents reads the component set from the chart's values.yaml; this
// asserts the parse against the embedded chart so the install-time list cannot
// silently diverge from what the chart declares.
func TestChartComponentsFromValues(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH")
	}
	dir, err := extractChart()
	if err != nil {
		t.Fatalf("extractChart: %v", err)
	}
	defer os.RemoveAll(dir)

	comps, err := chartComponents(context.Background(), filepath.Join(dir, helmchart.ChartRoot))
	if err != nil {
		t.Fatalf("chartComponents: %v", err)
	}

	got := map[string]string{}
	for _, c := range comps {
		got[c.valuePrefix] = c.repository
	}
	want := map[string]string{
		"image":                "ghcr.io/lunal-dev/c8s-operator",
		"attestationApi.image": "ghcr.io/lunal-dev/attestation-api",
		"cds.image":            "ghcr.io/lunal-dev/cds",
		"ratlsMesh.image":      "ghcr.io/lunal-dev/ratls-mesh",
		"nriImagePolicy.image": "ghcr.io/lunal-dev/nri-image-policy",
		"teeProxy.image":       "ghcr.io/lunal-dev/tee-proxy",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chart components = %v, want %v", got, want)
	}
}

func assertArgsEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("args = %v (len %d), want %v (len %d)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; got %v", i, got[i], want[i], got)
		}
	}
}
