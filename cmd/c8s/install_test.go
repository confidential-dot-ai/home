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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
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

func TestAppendKataInstallArgsEnabledIsEnforcing(t *testing.T) {
	// --kata is enforcing: alongside the kata stack it must turn off the
	// host-side components whose function runs inside the kata-guest-base
	// image (the chart's enforce_host_components validation rejects them left
	// on). Enforcement itself (webhook injection + ValidatingAdmissionPolicy)
	// is keyed on kata.enabled in the chart — no separate value.
	got := appendKataInstallArgs([]string{"upgrade"}, true, false)
	assertArgsEqual(t, got, []string{
		"upgrade",
		"--set", "kata.enabled=true",
		"--set", "ratlsMesh.enabled=false",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
	})
}

func TestAppendKataInstallArgsDebugSelectsDebugGuestImage(t *testing.T) {
	// --kata --debug keeps the enforcing shape and additionally points the
	// puller at the -debug guest image (host log/exec streams allowed).
	got := appendKataInstallArgs([]string{"upgrade"}, true, true)
	assertArgsEqual(t, got, []string{
		"upgrade",
		"--set", "kata.enabled=true",
		"--set", "ratlsMesh.enabled=false",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "kata.guestImage.debug=true",
	})
}

func TestAppendKataInstallArgsDebugWithoutKataIsNoOp(t *testing.T) {
	// RunE rejects --debug without --kata before args are built; the builder
	// still keys everything on kata so a call-order change cannot silently
	// emit a debug guest image for a non-kata install.
	got := appendKataInstallArgs([]string{"upgrade"}, false, true)
	assertArgsEqual(t, got, []string{"upgrade"})
}

// --debug without --kata is meaningless (the debug guest image only exists
// under the kata stack) and must error rather than silently no-op.
func TestValidateKataDebugFlagsRejectsDebugWithoutKata(t *testing.T) {
	err := validateKataDebugFlags(false, true)
	if err == nil {
		t.Fatal("--debug without --kata: want error, got nil")
	}
	for _, want := range []string{"--kata", "--debug"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q (should name both flags)", err.Error(), want)
		}
	}
	for _, tc := range []struct{ kata, debug bool }{{false, false}, {true, false}, {true, true}} {
		if err := validateKataDebugFlags(tc.kata, tc.debug); err != nil {
			t.Errorf("kata=%t debug=%t: unexpected error: %v", tc.kata, tc.debug, err)
		}
	}
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

func TestCheckImagePullSecret(t *testing.T) {
	tests := []struct {
		name    string
		sec     *corev1.Secret
		wantErr bool
		wantIn  []string // substrings the error must carry (the fix, not just the failure)
	}{
		{name: "dockerconfigjson secret exists", sec: &corev1.Secret{Type: corev1.SecretTypeDockerConfigJson}, wantErr: false},
		{name: "legacy dockercfg secret exists", sec: &corev1.Secret{Type: corev1.SecretTypeDockercfg}, wantErr: false},
		{
			name:    "missing secret",
			sec:     nil,
			wantErr: true,
			wantIn:  []string{"kubectl create secret docker-registry"},
		},
		{
			// kubelet silently skips non-registry Secret types, so this would
			// otherwise only surface as ImagePullBackOff.
			name:    "wrong secret type",
			sec:     &corev1.Secret{Type: corev1.SecretTypeOpaque},
			wantErr: true,
			wantIn:  []string{string(corev1.SecretTypeDockerConfigJson)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkImagePullSecret(tt.sec, "c8s-system", "ghcr-secret")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %t", err, tt.wantErr)
			}
			for _, want := range tt.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

func TestAppendDistroInstallArgsSetsBothComponents(t *testing.T) {
	// The detected distro feeds both the kata-deploy and nri-image-policy
	// installers; nri-image-policy installs regardless of --kata, so the two
	// values always travel together.
	for _, distro := range []string{"k8s", "rke2"} {
		t.Run(distro, func(t *testing.T) {
			got := appendDistroInstallArgs([]string{"upgrade"}, distro)
			assertArgsEqual(t, got, []string{
				"upgrade",
				"--set-string", "kata.distro=" + distro,
				"--set-string", "nriImagePolicy.distro=" + distro,
			})
		})
	}
}

// classifyDistroNodes splits "name\tkubeletVersion" lines by the "+rke2"
// build-metadata suffix RKE2's kubelet build carries. Anything else (vanilla
// upstream, k3s, future distros) lands in the "other" bucket — detection
// only owns the rke2 vs not-rke2 split.
func TestClassifyDistroNodesByKubeletVersionSuffix(t *testing.T) {
	lines := []string{
		"node-a\tv1.29.5+rke2r1",
		"node-b\tv1.29.5",        // vanilla upstream
		"node-c\tv1.30.1+rke2r2", // newer RKE2 build
		"node-d\tv1.30.0+k3s1",   // k3s lands in "other"
		"",                       // a trailing blank line from kubectl is ignored
		"malformed-no-tab",       // a line with no tab can't be classified, ignored
	}
	rke2, other := classifyDistroNodes(lines)
	wantRke2 := []string{"node-a", "node-c"}
	wantOther := []string{"node-b", "node-d"}
	if !reflect.DeepEqual(rke2, wantRke2) {
		t.Errorf("rke2 nodes = %v, want %v", rke2, wantRke2)
	}
	if !reflect.DeepEqual(other, wantOther) {
		t.Errorf("other nodes = %v, want %v", other, wantOther)
	}
}

// chooseDistro powers distro detection: the kubelet classification must map to
// the distro value the chart needs.
func TestChooseDistroHomogeneousClusters(t *testing.T) {
	got, err := chooseDistro([]string{"node-a", "node-b"}, nil)
	if err != nil || got != "rke2" {
		t.Errorf("all-RKE2 cluster: got (%q, %v), want (rke2, nil)", got, err)
	}
	got, err = chooseDistro(nil, []string{"node-a", "node-b"})
	if err != nil || got != "k8s" {
		t.Errorf("vanilla cluster: got (%q, %v), want (k8s, nil)", got, err)
	}
	// No classifiable nodes: fall back to the chart default rather than fail
	// an install on which nothing could schedule anyway.
	got, err = chooseDistro(nil, nil)
	if err != nil || got != "k8s" {
		t.Errorf("no classifiable nodes: got (%q, %v), want (k8s, nil)", got, err)
	}
}

// A mixed cluster has no single right distro — the installers patch a
// distro-specific containerd path on every selected node — so detection must
// demand explicit per-component values via -f instead of guessing.
func TestChooseDistroRejectsMixedClusters(t *testing.T) {
	_, err := chooseDistro([]string{"rke2-node"}, []string{"vanilla-node"})
	if err == nil {
		t.Fatal("mixed cluster: want error, got nil")
	}
	for _, want := range []string{"kata.distro", "nriImagePolicy.distro", "rke2-node", "vanilla-node"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q (should name the fix and both node sets)", err.Error(), want)
		}
	}
}

func TestAppendCvmModeInstallArgsSetsAttestationApiValue(t *testing.T) {
	// native /dev/sev-guest for baremetal AND gke (GKE confidential VMs use the
	// native ioctl, not a vTPM); vTPM /dev/tpm0 only for aks.
	native := func(mode string) []string {
		return []string{
			"upgrade",
			"--set-string", "attestationApi.cvmMode=" + mode,
			"--set", "attestationApi.teeDevices.sevGuest=true",
			"--set", "attestationApi.teeDevices.tpm=false",
		}
	}
	cases := map[string][]string{
		"baremetal": native("baremetal"),
		"gke":       native("gke"),
		"aks": {
			"upgrade",
			"--set-string", "attestationApi.cvmMode=aks",
			"--set", "attestationApi.teeDevices.sevGuest=false",
			"--set", "attestationApi.teeDevices.tpm=true",
		},
	}
	for mode, want := range cases {
		t.Run(mode, func(t *testing.T) {
			got, err := appendCvmModeInstallArgs([]string{"upgrade"}, mode)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertArgsEqual(t, got, want)
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
	{"image", "ghcr.io/confidential-dot-ai/c8s-operator"},
	{"attestationApi.image", "ghcr.io/confidential-dot-ai/attestation-api"},
	{"cds.image", "ghcr.io/confidential-dot-ai/cds"},
	{"ratlsMesh.image", "ghcr.io/confidential-dot-ai/ratls-mesh"},
	{"nriImagePolicy.image", "ghcr.io/confidential-dot-ai/nri-image-policy"},
	{"teeProxy.image", "ghcr.io/confidential-dot-ai/tee-proxy"},
}

func TestBuildDigestArgsPinsEveryComponent(t *testing.T) {
	// Deterministic fake resolver: digest derived from the ref so each
	// component gets a distinct, predictable value.
	resolve := func(ref string) (string, error) {
		switch ref {
		case "ghcr.io/confidential-dot-ai/c8s-operator:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000aa", nil
		case "ghcr.io/confidential-dot-ai/attestation-api:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000bb", nil
		case "ghcr.io/confidential-dot-ai/cds:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000cc", nil
		case "ghcr.io/confidential-dot-ai/ratls-mesh:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000dd", nil
		case "ghcr.io/confidential-dot-ai/nri-image-policy:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000ee", nil
		case "ghcr.io/confidential-dot-ai/tee-proxy:v1":
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
		"--set-string", "image.repository=ghcr.io/confidential-dot-ai/c8s-operator",
		"--set-string", "image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000aa",
		"--set-string", "attestationApi.image.repository=ghcr.io/confidential-dot-ai/attestation-api",
		"--set-string", "attestationApi.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000bb",
		"--set-string", "cds.image.repository=ghcr.io/confidential-dot-ai/cds",
		"--set-string", "cds.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000cc",
		"--set-string", "ratlsMesh.image.repository=ghcr.io/confidential-dot-ai/ratls-mesh",
		"--set-string", "ratlsMesh.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000dd",
		"--set-string", "nriImagePolicy.image.repository=ghcr.io/confidential-dot-ai/nri-image-policy",
		"--set-string", "nriImagePolicy.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000ee",
		"--set-string", "teeProxy.image.repository=ghcr.io/confidential-dot-ai/tee-proxy",
		"--set-string", "teeProxy.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000ff",
		// Resolving component digests enables their derivation into the NRI allowlist.
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
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
// would pass the render guard while the served allowlist pointed at a wrong or
// missing digest.
func TestBuildDigestArgsFailsClosedOnResolveError(t *testing.T) {
	resolve := func(ref string) (string, error) {
		if ref == "ghcr.io/confidential-dot-ai/cds:v1" {
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
		"image":                "ghcr.io/confidential-dot-ai/c8s-operator",
		"attestationApi.image": "ghcr.io/confidential-dot-ai/attestation-api",
		"cds.image":            "ghcr.io/confidential-dot-ai/cds",
		"ratlsMesh.image":      "ghcr.io/confidential-dot-ai/ratls-mesh",
		"nriImagePolicy.image": "ghcr.io/confidential-dot-ai/nri-image-policy",
		"teeProxy.image":       "ghcr.io/confidential-dot-ai/tee-proxy",
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
