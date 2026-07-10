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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

var errTestResolve = errors.New("simulated resolve failure")

func TestOperatorKeysPreflight(t *testing.T) {
	// Keys provided → no gate, no warning.
	if warn, err := operatorKeysPreflight("operator.pub", nil, false); err != nil || warn != "" {
		t.Fatalf("keys provided: want no error/warn, got warn=%q err=%v", warn, err)
	}
	// Default path, no keys, no force → hard error (must acknowledge).
	if _, err := operatorKeysPreflight("", nil, false); err == nil {
		t.Fatal("no keys + no force: expected an error requiring --operator-keys or --force")
	}
	// Default path, no keys, --force → allowed, but warns.
	if warn, err := operatorKeysPreflight("", nil, true); err != nil || warn == "" {
		t.Fatalf("no keys + force: want warn and no error, got warn=%q err=%v", warn, err)
	}
	// -f supplied → operator owns cds.operatorKeys in their values file; no gate.
	if warn, err := operatorKeysPreflight("", []string{"custom.yaml"}, false); err != nil || warn != "" {
		t.Fatalf("-f supplied: want no error/warn, got warn=%q err=%v", warn, err)
	}
}

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

func TestResolveImageTag(t *testing.T) {
	prev := installImageTag
	defer func() { installImageTag = prev }()

	// --image-tag set wins over the build-version default.
	installImageTag = "v9.9.9"
	if got := resolveImageTag(); got != "v9.9.9" {
		t.Errorf("with --image-tag set: got %q, want v9.9.9", got)
	}

	// Unset falls back to the build-version default. An unstamped test build is
	// not a release tag, so that default is the fallback tag.
	installImageTag = ""
	if got := resolveImageTag(); got != fallbackImageTag {
		t.Errorf("unset: got %q, want the fallback tag %q", got, fallbackImageTag)
	}
}

// labelSelector feeds the --kata SNP-node preflight: it must produce a stable
// kubectl -l selector from the chart's kata.snpNodeSelector map, and report
// ok=false for the empty (opt-out) and malformed shapes so the preflight
// skips rather than guesses.
func TestLabelSelector(t *testing.T) {
	tests := []struct {
		name string
		sel  map[string]any
		want string
		ok   bool
	}{
		{name: "chart default", sel: map[string]any{"confidential.ai/sev-snp": "true"}, want: "confidential.ai/sev-snp=true", ok: true},
		{name: "multiple pairs sorted", sel: map[string]any{"b": "2", "a": "1"}, want: "a=1,b=2", ok: true},
		{name: "empty map is the opt-out", sel: map[string]any{}, ok: false},
		{name: "nil map is the opt-out", sel: nil, ok: false},
		{name: "non-string value skips", sel: map[string]any{"a": true}, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := labelSelector(tt.sel)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("labelSelector(%v) = (%q, %t), want (%q, %t)", tt.sel, got, ok, tt.want, tt.ok)
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
	// Emits the value only; helm's --skip-crds invocation flag is added at the
	// install call site, not here (these args become a values tree).
	got := appendInstallCRDArgs([]string{"--set", "image.tag=main"}, false)
	want := []string{"--set", "image.tag=main", "--set", "statusMirror.enabled=false"}
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
	got := appendInstallCRDArgs([]string{"--set", "image.tag=main"}, true)
	want := []string{"--set", "image.tag=main"}
	if len(got) != len(want) {
		t.Fatalf("args length = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; got %v", i, got[i], want[i], got)
		}
	}
}

// The helm argv ordering is load-bearing: operator -f files before the computed
// file (last -f wins, so computed values win on the keys they set), and
// --skip-crds present iff CRDs are skipped.
func TestBuildInstallHelmArgsOrdering(t *testing.T) {
	prevRel, prevNs := installRelease, installNamespace
	defer func() { installRelease, installNamespace = prevRel, prevNs }()
	installRelease, installNamespace = "c8s", "c8s-system"

	// CRDs installed, two operator -f files, wait on: computed file is LAST -f.
	assertArgsEqual(t, buildInstallHelmArgs("/chart", "/tmp/computed.yaml", []string{"a.yaml", "b.yaml"}, true, true, false), []string{
		"upgrade", "--install", "c8s", "/chart", "--namespace", "c8s-system",
		"-f", "a.yaml", "-f", "b.yaml", "-f", "/tmp/computed.yaml",
		"--wait", "--timeout=5m",
	})

	// CRDs skipped, no operator -f, wait off: --skip-crds present, computed file
	// still the last (only) -f, no --wait.
	assertArgsEqual(t, buildInstallHelmArgs("/chart", "/tmp/computed.yaml", nil, false, false, false), []string{
		"upgrade", "--install", "c8s", "/chart", "--namespace", "c8s-system",
		"--skip-crds", "-f", "/tmp/computed.yaml",
	})

	// --kata raises the wait ceiling: kata-deploy's first-install payload
	// download routinely exceeds 5m (docs/pitfalls.md).
	assertArgsEqual(t, buildInstallHelmArgs("/chart", "/tmp/computed.yaml", nil, true, true, true), []string{
		"upgrade", "--install", "c8s", "/chart", "--namespace", "c8s-system",
		"-f", "/tmp/computed.yaml",
		"--wait", "--timeout=10m",
	})
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

func TestParseWorkloadRef(t *testing.T) {
	tests := []struct {
		ref     string
		want    workloadRef
		wantErr []string
	}{
		{
			ref:  "workloads/deployment/vllm",
			want: workloadRef{kind: "deployment", name: "vllm", namespace: "workloads"},
		},
		{
			ref:  "workloads/sts/infer",
			want: workloadRef{kind: "statefulset", name: "infer", namespace: "workloads"},
		},
		{
			ref:  "workloads/ds/gpu-worker",
			want: workloadRef{kind: "daemonset", name: "gpu-worker", namespace: "workloads"},
		},
		{
			// A non-stock kind passes through verbatim for kubectl to resolve.
			ref:  "workloads/controller/infer",
			want: workloadRef{kind: "controller", name: "infer", namespace: "workloads"},
		},
		{
			// A dotted kind.group survives the middle-'/' split.
			ref:  "workloads/nodeset.example.net/worker",
			want: workloadRef{kind: "nodeset.example.net", name: "worker", namespace: "workloads"},
		},
		{
			// An optional :<port> suffix is the tls-lb upstream port.
			ref:  "vllm/deployment/router:8000",
			want: workloadRef{kind: "deployment", name: "router", namespace: "vllm", port: 8000},
		},
		{
			ref:     "vllm/deployment/router:0",
			wantErr: []string{"--workload-ref", "1-65535"},
		},
		{
			ref:     "vllm/deployment/router:https",
			wantErr: []string{"--workload-ref", "1-65535"},
		},
		{
			ref:     "vllm/deployment/router:70000",
			wantErr: []string{"--workload-ref", "1-65535"},
		},
		{
			// A leading colon leaves an empty name before the :<port>.
			ref:     "vllm/deployment/:8000",
			wantErr: []string{"--workload-ref", "<namespace>/<kind>/<name>"},
		},
		{
			// Non-canonical port spellings Atoi would accept are rejected.
			ref:     "vllm/deployment/router:+8000",
			wantErr: []string{"--workload-ref", "1-65535"},
		},
		{
			ref:     "vllm/deployment/router:08000",
			wantErr: []string{"--workload-ref", "1-65535"},
		},
		{
			ref:     "deployment/vllm",
			wantErr: []string{"--workload-ref", "<namespace>/<kind>/<name>"},
		},
		{
			ref:     "vllm",
			wantErr: []string{"--workload-ref", "<namespace>/<kind>/<name>"},
		},
		{
			ref:     "",
			wantErr: []string{"--workload-ref", "<namespace>/<kind>/<name>"},
		},
		{
			// A mis-split leaking an '=' into the name.
			ref:     "ns/deployment/na=me",
			wantErr: []string{"--workload-ref", "DNS-1123"},
		},
		{
			ref:     "ns/deployment/UPPER",
			wantErr: []string{"--workload-ref", "DNS-1123"},
		},
		{
			ref:     "BadNS/deployment/vllm",
			wantErr: []string{"--workload-ref", "namespace", "DNS-1123"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			got, err := parseWorkloadRef(tt.ref, flagWorkloadRef)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("ref = %+v, want %+v", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %v, got nil", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

func TestValidateWorkloadAdoptionFlags(t *testing.T) {
	tests := []struct {
		name      string
		releaseNS string
		refs      []string
		wait      bool
		wantErr   []string
	}{
		{name: "no ref is valid", wait: false},
		{name: "adopt in a separate namespace is valid", releaseNS: "c8s-system", refs: []string{"router=workloads/deployment/vllm"}, wait: true},
		{name: "ref rejects release namespace", releaseNS: "c8s-system", refs: []string{"router=c8s-system/deployment/vllm"}, wait: true, wantErr: []string{"--workload-ref", "release namespace", "excluded"}},
		{name: "ref requires wait", releaseNS: "c8s-system", refs: []string{"router=workloads/deployment/vllm"}, wait: false, wantErr: []string{"--workload-ref", "--wait=true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adoptions, err := collectWorkloadAdoptions(tt.refs)
			if err != nil {
				t.Fatalf("collectWorkloadAdoptions: %v", err)
			}
			err = validateWorkloadAdoptionFlags(tt.releaseNS, adoptions, tt.wait)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %v, got nil", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

// TestUpstreamAddress drives the derivation buildValueArgs uses to set
// tlsLb.upstream.address, so it guards the address the chart receives against
// divergence from the RunE's --upstream validation. The port comes from the
// selected ref's :<port> suffix, not a separate flag.
func TestUpstreamAddress(t *testing.T) {
	tests := []struct {
		name     string
		refs     []string
		upstream string
		want     string
		wantErr  []string
	}{
		{name: "no upstream yields empty", refs: []string{"router=vllm/deployment/vllm-router:8000"}, want: ""},
		{name: "selects a ref by cw id", refs: []string{"router=vllm/deployment/vllm-router:8000", "engine=vllm/deployment/vllm-engine"}, upstream: "router", want: "c8s-router.vllm.svc.cluster.local:8000"},
		{name: "selects the other ref", refs: []string{"router=vllm/deployment/vllm-router", "engine=vllm/deployment/vllm-engine:30000"}, upstream: "engine", want: "c8s-engine.vllm.svc.cluster.local:30000"},
		{name: "upstream must name a ref", refs: []string{"router=vllm/deployment/vllm-router:8000"}, upstream: "missing", wantErr: []string{"--upstream", "missing", "--workload-ref"}},
		{name: "selected ref needs a port", refs: []string{"router=vllm/deployment/vllm-router"}, upstream: "router", wantErr: []string{"--upstream", "router", "no :<port>"}},
		// The port must be on the SELECTED ref: a port on a different ref does
		// not satisfy the selected one.
		{name: "port on a different ref does not count", refs: []string{"router=vllm/deployment/vllm-router", "engine=vllm/deployment/vllm-engine:30000"}, upstream: "router", wantErr: []string{"--upstream", "router", "no :<port>"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adoptions, err := collectWorkloadAdoptions(tt.refs)
			if err != nil {
				t.Fatalf("collectWorkloadAdoptions: %v", err)
			}
			got, err := upstreamAddress(tt.upstream, adoptions)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("upstreamAddress = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %v, got nil", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

func TestCollectWorkloadAdoptions(t *testing.T) {
	got, err := collectWorkloadAdoptions([]string{
		"vllm-router=vllm/deployment/vllm-deployment-router",
		"vllm-engine=vllm/deployment/vllm-engine",
	})
	if err != nil {
		t.Fatalf("collectWorkloadAdoptions: %v", err)
	}
	want := []workloadAdoption{
		{cwID: "vllm-router", ref: workloadRef{kind: "deployment", name: "vllm-deployment-router", namespace: "vllm"}},
		{cwID: "vllm-engine", ref: workloadRef{kind: "deployment", name: "vllm-engine", namespace: "vllm"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("adoptions = %+v, want %+v", got, want)
	}
}

func TestCollectWorkloadAdoptionsRejectsMalformedAdditionalRef(t *testing.T) {
	_, err := collectWorkloadAdoptions([]string{"vllm/deployment/vllm-engine"})
	if err == nil {
		t.Fatal("expected malformed --workload-ref to fail")
	}
	for _, want := range []string{"--workload-ref", "<cw-id>=<namespace>/<kind>/<name>"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestCollectWorkloadAdoptionsRejectsInvalidWorkloadID(t *testing.T) {
	_, err := collectWorkloadAdoptions([]string{"Bad_ID=vllm/deployment/vllm-engine"})
	if err == nil {
		t.Fatal("expected invalid workload id to fail")
	}
	for _, want := range []string{"--workload-ref", "Bad_ID", "DNS-1035"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestCollectWorkloadAdoptionsRejectsConflictingDuplicateRef(t *testing.T) {
	_, err := collectWorkloadAdoptions([]string{"vllm-router=vllm/deployment/vllm", "vllm-engine=vllm/deployment/vllm"})
	if err == nil {
		t.Fatal("expected conflicting duplicate workload ref to fail")
	}
	for _, want := range []string{"vllm/deployment/vllm", "vllm-router", "vllm-engine"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestCollectWorkloadAdoptionsRejectsConflictingPort(t *testing.T) {
	// Same workload + same cw id but different :<port> must error, not silently
	// dedup to the first ref's port.
	_, err := collectWorkloadAdoptions([]string{"vllm=vllm/deployment/x:8000", "vllm=vllm/deployment/x:9000"})
	if err == nil {
		t.Fatal("expected conflicting upstream ports to fail")
	}
	for _, want := range []string{"vllm/deployment/x", "8000", "9000"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestCollectWorkloadAdoptionsRejectsSharedCWID(t *testing.T) {
	_, err := collectWorkloadAdoptions([]string{"shared=vllm/deployment/a", "shared=vllm/deployment/b"})
	if err == nil {
		t.Fatal("expected one cw id on two workloads to fail")
	}
	for _, want := range []string{"shared", "vllm/deployment/a", "vllm/deployment/b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestConfidentialWorkloadPatchAnnotatesPodTemplate(t *testing.T) {
	data, err := confidentialWorkloadPatch("infer")
	if err != nil {
		t.Fatalf("confidentialWorkloadPatch: %v", err)
	}
	var patch map[string]any
	if err := json.Unmarshal(data, &patch); err != nil {
		t.Fatalf("patch is not JSON: %v\n%s", err, data)
	}
	spec := patch["spec"].(map[string]any)
	template := spec["template"].(map[string]any)
	metadata := template["metadata"].(map[string]any)
	annotations := metadata["annotations"].(map[string]any)
	if got := annotations[webhook.AnnotationWorkload]; got != "infer" {
		t.Fatalf("%s = %#v, want infer", webhook.AnnotationWorkload, got)
	}
}

func TestWorkloadPodTemplateImages(t *testing.T) {
	deployment := appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{Image: "ghcr.io/acme/init:v1"}},
					Containers: []corev1.Container{
						{Image: "ghcr.io/acme/router:v1"},
						{Image: "ghcr.io/acme/router:v1"},
					},
				},
			},
		},
	}
	data, err := json.Marshal(deployment)
	if err != nil {
		t.Fatalf("marshal deployment: %v", err)
	}
	template, err := workloadPodTemplate(data)
	if err != nil {
		t.Fatalf("workloadPodTemplate: %v", err)
	}
	got := podTemplateImages(template)
	want := []string{"ghcr.io/acme/init:v1", "ghcr.io/acme/router:v1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("images = %v, want %v", got, want)
	}

	// A CRD carrying its pod template at spec.template decodes the same way,
	// with no matching Go type.
	crd := []byte(`{
		"apiVersion": "example.net/v1beta1",
		"kind": "NodeSet",
		"spec": {"template": {"spec": {"containers": [{"image": "ghcr.io/acme/worker:v3"}]}}}
	}`)
	template, err = workloadPodTemplate(crd)
	if err != nil {
		t.Fatalf("workloadPodTemplate crd: %v", err)
	}
	if got, want := podTemplateImages(template), []string{"ghcr.io/acme/worker:v3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("crd images = %v, want %v", got, want)
	}
}

func TestBuildWorkloadImageArgsAddsNRIAllowlistDigests(t *testing.T) {
	resolve := func(ref string) (string, error) {
		switch ref {
		case "ghcr.io/acme/router:v1":
			return "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil
		case "ghcr.io/acme/engine:v2":
			return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
		}
		t.Fatalf("unexpected ref resolved: %q", ref)
		return "", nil
	}
	got, err := buildWorkloadImageArgs([]string{"upgrade"}, []string{
		"ghcr.io/acme/router:v1",
		"ghcr.io/acme/engine:v2",
		"ghcr.io/acme/router:v1",
		"busybox@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}, resolve)
	if err != nil {
		t.Fatalf("buildWorkloadImageArgs: %v", err)
	}
	assertArgsEqual(t, got, []string{
		"upgrade",
		"--set-string", "nriImagePolicy.bootstrapAllowlist.digests.sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=ghcr.io/acme/engine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"--set-string", "nriImagePolicy.bootstrapAllowlist.digests.sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=ghcr.io/acme/router@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"--set-string", "nriImagePolicy.bootstrapAllowlist.digests.sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc=docker.io/library/busybox@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	})
}

func TestBuildWorkloadImageArgsFailsClosedOnResolveError(t *testing.T) {
	_, err := buildWorkloadImageArgs(nil, []string{"ghcr.io/acme/router:v1"}, func(string) (string, error) {
		return "", errTestResolve
	})
	if err == nil {
		t.Fatal("expected workload image resolver failure to abort")
	}
}

// A workload image already pinned by a non-sha256 digest (distribution/reference
// accepts sha512) must fail closed with a message naming the sha256 constraint,
// since the NRI allowlist keys on sha256 only.
func TestBuildWorkloadImageArgsRejectsNonSHA256Digest(t *testing.T) {
	sha512Image := "busybox@sha512:ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
	_, err := buildWorkloadImageArgs(nil, []string{sha512Image}, func(string) (string, error) {
		t.Fatal("resolve must not run for an already-digested image")
		return "", nil
	})
	if err == nil {
		t.Fatal("expected non-sha256 pinned digest to be rejected")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("error %q should name the sha256 constraint", err.Error())
	}
}

func TestImagePinnedByDigest(t *testing.T) {
	cases := []struct {
		image string
		want  bool
	}{
		{"busybox@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", true},
		{"ghcr.io/acme/router:v1@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", true},
		{"ghcr.io/acme/router:v1", false},
		{"busybox", false},
		{"busybox:latest", false},
		{"not a ref", false},
	}
	for _, c := range cases {
		if got := imagePinnedByDigest(c.image); got != c.want {
			t.Errorf("imagePinnedByDigest(%q) = %v, want %v", c.image, got, c.want)
		}
	}
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

// A -f file suppresses distro auto-detection only when it actually sets a
// distro; passing -f for any other value must leave detection in force (the
// bug: any -f used to silently drop the CLI to the chart's k8s default).
func TestValuesFilesSetDistro(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "values.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write values: %v", err)
		}
		return p
	}
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"nri distro set", "nriImagePolicy:\n  distro: rke2\n", true},
		{"kata distro set", "kata:\n  distro: rke2\n", true},
		{"unrelated value only", "tlsLb:\n  enabled: false\n", false},
		{"distro key absent under section", "nriImagePolicy:\n  enabled: true\n", false},
		{"empty distro string is not a choice", "nriImagePolicy:\n  distro: \"\"\n", false},
		{"empty file", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := valuesFilesSetDistro([]string{write(t, tc.body)})
			if err != nil {
				t.Fatalf("valuesFilesSetDistro: %v", err)
			}
			if got != tc.want {
				t.Errorf("valuesFilesSetDistro(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}

	t.Run("no files means detect", func(t *testing.T) {
		got, err := valuesFilesSetDistro(nil)
		if err != nil || got {
			t.Errorf("valuesFilesSetDistro(nil) = (%v, %v), want (false, nil)", got, err)
		}
	})

	t.Run("one of several files sets it", func(t *testing.T) {
		a := write(t, "tlsLb:\n  enabled: false\n")
		b := write(t, "kata:\n  distro: rke2\n")
		got, err := valuesFilesSetDistro([]string{a, b})
		if err != nil || !got {
			t.Errorf("valuesFilesSetDistro(two files) = (%v, %v), want (true, nil)", got, err)
		}
	})
}

func TestTLSLBHostPort(t *testing.T) {
	hp := func(https any) map[string]any {
		return map[string]any{"tlsLb": map[string]any{"hostPort": map[string]any{"https": https}}}
	}
	for _, tc := range []struct {
		name string
		tree map[string]any
		want int32
	}{
		{"empty string derives 443", hp(""), 443},
		{"no hostPort map", map[string]any{"tlsLb": map[string]any{}}, 443},
		{"string override", hp("8443"), 8443},
		{"int override", hp(9443), 9443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tlsLBHostPort(tc.tree)
			if err != nil || got != tc.want {
				t.Fatalf("tlsLBHostPort = (%d, %v), want (%d, nil)", got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		https any
	}{
		{"non-numeric string", "https"},
		{"string overflows int32", "4294967297"}, // 2^32 + 1 — would wrap to 1 on a bare int32 cast
		{"string above port range", "70000"},
		{"int above port range", 70000},
		{"zero is not a port", 0},
	} {
		t.Run(tc.name+" errors", func(t *testing.T) {
			if _, err := tlsLBHostPort(hp(tc.https)); err == nil {
				t.Fatalf("want error for %v", tc.https)
			}
		})
	}
}

func TestHostPortConflict(t *testing.T) {
	pod := func(ns, name, node string, port int32) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec: corev1.PodSpec{
				NodeName:   node,
				Containers: []corev1.Container{{Name: "c", Ports: []corev1.ContainerPort{{HostPort: port}}}},
			},
		}
	}
	const ignoreNS = "c8s-system"

	for _, tc := range []struct {
		name        string
		pods        []corev1.Pod
		nodes       []string
		wantBlocked bool
		wantHolder  string // substring expected in holders, or "" for none
	}{
		{
			name:        "single node, ingress holds 443",
			pods:        []corev1.Pod{pod("kube-system", "rke2-ingress-nginx-abc", "node-a", 443)},
			nodes:       []string{"node-a"},
			wantBlocked: true,
			wantHolder:  "kube-system/rke2-ingress-nginx-abc",
		},
		{
			name: "two nodes, ingress on both",
			pods: []corev1.Pod{
				pod("kube-system", "ing-a", "node-a", 443),
				pod("kube-system", "ing-b", "node-b", 443),
			},
			nodes:       []string{"node-a", "node-b"},
			wantBlocked: true,
		},
		{
			name:        "two nodes, ingress on only one leaves a free node",
			pods:        []corev1.Pod{pod("kube-system", "ing-a", "node-a", 443)},
			nodes:       []string{"node-a", "node-b"},
			wantBlocked: false,
		},
		{
			name:        "holder only in ignored namespace",
			pods:        []corev1.Pod{pod(ignoreNS, "c8s-tls-lb", "node-a", 443)},
			nodes:       []string{"node-a"},
			wantBlocked: false,
		},
		{
			name:        "different port is not a conflict",
			pods:        []corev1.Pod{pod("kube-system", "ing-a", "node-a", 8080)},
			nodes:       []string{"node-a"},
			wantBlocked: false,
		},
		{
			name:        "unscheduled holder occupies no node",
			pods:        []corev1.Pod{pod("kube-system", "pending", "", 443)},
			nodes:       []string{"node-a"},
			wantBlocked: false,
			wantHolder:  "kube-system/pending",
		},
		{
			name:        "no nodes",
			pods:        []corev1.Pod{pod("kube-system", "ing-a", "node-a", 443)},
			nodes:       nil,
			wantBlocked: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocked, holders := hostPortConflict(tc.pods, tc.nodes, 443, ignoreNS)
			if blocked != tc.wantBlocked {
				t.Errorf("blocked = %v, want %v (holders=%v)", blocked, tc.wantBlocked, holders)
			}
			if tc.wantHolder != "" && !strings.Contains(strings.Join(holders, ","), tc.wantHolder) {
				t.Errorf("holders %v missing %q", holders, tc.wantHolder)
			}
		})
	}
}

func TestAppendCvmModeInstallArgsSetsAttestationApiValue(t *testing.T) {
	// Two orthogonal axes:
	//  --cvm-mode: baremetal / node (node-as-CVM) / gke (managed) / aks (vTPM)
	//  --hardware-platform: sev-snp (/dev/sev-guest) / tdx (/dev/tdx-guest)
	// baremetal+node+gke all take either hardware-platform; aks always emits vTPM
	// (and combining aks with tdx is rejected).
	build := func(mode string, sevGuest, tdxGuest, tpm string) []string {
		out := []string{
			"upgrade",
			"--set-string", "attestationApi.cvmMode=" + mode,
			"--set", "attestationApi.teeDevices.sevGuest=" + sevGuest,
			"--set", "attestationApi.teeDevices.tdxGuest=" + tdxGuest,
			"--set", "attestationApi.teeDevices.tpm=" + tpm,
		}
		// TDX (non-aks) also propagates the CPU TEE to the components that name
		// their RA-TLS platform, or CDS parses the TDX quote as an SNP report.
		if tdxGuest == "true" {
			out = append(out,
				"--set-string", "cds.ratlsPlatform=tdx",
				"--set-string", "ratlsMesh.platform=tdx",
			)
		}
		return out
	}
	cases := map[string]struct {
		cvmMode          string
		hardwarePlatform string
		want             []string
	}{
		"baremetal + sev-snp": {"baremetal", "sev-snp", build("baremetal", "true", "false", "false")},
		"gke + sev-snp":       {"gke", "sev-snp", build("gke", "true", "false", "false")},
		"node + sev-snp":      {"node", "sev-snp", build("node", "true", "false", "false")},
		"baremetal + tdx":     {"baremetal", "tdx", build("baremetal", "false", "true", "false")},
		"gke + tdx":           {"gke", "tdx", build("gke", "false", "true", "false")},
		"node + tdx":          {"node", "tdx", build("node", "false", "true", "false")},
		"aks + sev-snp":       {"aks", "sev-snp", build("aks", "false", "false", "true")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := appendCvmModeInstallArgs([]string{"upgrade"}, tc.cvmMode, tc.hardwarePlatform)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertArgsEqual(t, got, tc.want)
		})
	}
}

func TestAppendCvmModeInstallArgsRejectsUnknownMode(t *testing.T) {
	if _, err := appendCvmModeInstallArgs([]string{"upgrade"}, "azure", "sev-snp"); err == nil {
		t.Fatal("appendCvmModeInstallArgs accepted an unknown --cvm-mode, want error")
	}
}

func TestAppendCvmModeInstallArgsRejectsUnknownHardwarePlatform(t *testing.T) {
	if _, err := appendCvmModeInstallArgs([]string{"upgrade"}, "baremetal", "sgx"); err == nil {
		t.Fatal("appendCvmModeInstallArgs accepted an unknown --hardware-platform, want error")
	}
}

func TestAppendCvmModeInstallArgsRejectsAksWithTdx(t *testing.T) {
	// AKS is Azure vTPM-backed SEV-SNP; TDX support on AKS would need a
	// separate device path if it ever ships. Combining these axes silently
	// would install with mounts that can never be attested; refuse
	// explicitly instead.
	_, err := appendCvmModeInstallArgs([]string{"upgrade"}, "aks", "tdx")
	if err == nil {
		t.Fatal("appendCvmModeInstallArgs accepted --cvm-mode=aks with --hardware-platform=tdx, want error")
	}
	if !strings.Contains(err.Error(), "aks") || !strings.Contains(err.Error(), "tdx") {
		t.Errorf("error %q should mention both cvm-mode aks and hardware-platform tdx", err.Error())
	}
}

// testComponents mirrors the chart's c8sComponents for the resolver tests,
// which exercise buildDigestArgs without reading a real chart. The chart-read
// path (chartComponents) is covered separately by TestChartComponentsFromValues.
var testComponents = []c8sComponent{
	{valuePrefix: "image", repository: "ghcr.io/confidential-dot-ai/c8s-operator"},
	{valuePrefix: "attestationApi.image", repository: "ghcr.io/confidential-dot-ai/attestation-api"},
	{valuePrefix: "cds.image", repository: "ghcr.io/confidential-dot-ai/cds"},
	{valuePrefix: "ratlsMesh.image", repository: "ghcr.io/confidential-dot-ai/ratls-mesh"},
	{valuePrefix: "nriImagePolicy.image", repository: "ghcr.io/confidential-dot-ai/nri-image-policy"},
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

// A missing tag (registry MANIFEST_UNKNOWN) must abort with the tag-coupling
// guidance — pointing at kata.guestImage.tag for guest-image-only tags like
// gpu-test, and at the lockstep publish model — while preserving the cause.
func TestBuildDigestArgsExplainsTagCouplingOnMissingTag(t *testing.T) {
	notFound := errors.New(`crane digest "ghcr.io/confidential-dot-ai/c8s-operator:gpu-test": exit status 1: MANIFEST_UNKNOWN: manifest unknown`)
	resolve := func(string) (string, error) { return "", notFound }
	_, err := buildDigestArgs(nil, "gpu-test", testComponents, resolve)
	if err == nil {
		t.Fatal("buildDigestArgs accepted a missing tag, want fail-closed")
	}
	if !errors.Is(err, notFound) {
		t.Errorf("wrapped error must preserve the cause, got: %v", err)
	}
	// The hint must be self-contained (end users don't have the repo, so no
	// docs/ paths) and steer to the guest-image knob for guest-image tags.
	for _, want := range []string{"kata.guestImage.tag", "lockstep"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must mention %q, got: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "docs/") {
		t.Errorf("user-facing hint must not reference in-repo docs paths, got: %v", err)
	}
}

// Auth/network resolve failures must pass through without the tag-coupling
// hint — advising a tag change for a 401 would send the operator down the
// wrong path.
func TestBuildDigestArgsLeavesOtherResolveErrorsUnhinted(t *testing.T) {
	resolve := func(string) (string, error) { return "", errTestResolve }
	_, err := buildDigestArgs(nil, "v1", testComponents, resolve)
	if err == nil {
		t.Fatal("buildDigestArgs ignored a resolver error, want fail-closed")
	}
	if strings.Contains(err.Error(), "kata.guestImage.tag") {
		t.Errorf("non-not-found error must not carry the tag-coupling hint: %v", err)
	}
}

// isImageNotFound keys the tag-coupling guidance to the registry's own
// missing-reference error codes, so auth and network failures never
// masquerade as a missing tag.
func TestIsImageNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "missing tag", err: errors.New("crane digest: MANIFEST_UNKNOWN: manifest unknown"), want: true},
		{name: "missing repository", err: errors.New("crane digest: NAME_UNKNOWN: repository name not known to registry"), want: true},
		{name: "auth failure", err: errors.New("crane digest: UNAUTHORIZED: authentication required"), want: false},
		{name: "network failure", err: errors.New("dial tcp: lookup ghcr.io: no such host"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isImageNotFound(tt.err); got != tt.want {
				t.Fatalf("isImageNotFound(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
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
		"secretAgent.image":    "ghcr.io/openbao/openbao",
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
