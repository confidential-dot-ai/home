//go:build !c8s_node

package main

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestDefaultInstallImageTag(t *testing.T) {
	tests := []struct {
		name         string
		buildVersion string
		want         string
	}{
		{name: "unstamped dev build", buildVersion: "dev", want: "latest"},
		{name: "empty build version", buildVersion: "", want: "latest"},
		{name: "release tag", buildVersion: "v0.1.0", want: "v0.1.0"},
		{name: "branch tag", buildVersion: "feat-phase5-chart-docs", want: "feat-phase5-chart-docs"},
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
	data, err := namespaceManifest("c8s-system", true)
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
	for _, mode := range []string{"enforce", "warn", "audit"} {
		key := "pod-security.kubernetes.io/" + mode
		if got := ns.Labels[key]; got != "privileged" {
			t.Fatalf("label %s = %q, want privileged", key, got)
		}
	}
}

func TestNamespaceManifestOmitsPodSecurityLabelsWhenNotPrivileged(t *testing.T) {
	// Without --kata the install ships no privileged pods, so c8s-system
	// should run under the cluster's default pod-security profile.
	data, err := namespaceManifest("c8s-system", false)
	if err != nil {
		t.Fatalf("namespaceManifest: %v", err)
	}

	var ns corev1.Namespace
	if err := json.Unmarshal(data, &ns); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, data)
	}

	for _, mode := range []string{"enforce", "warn", "audit"} {
		key := "pod-security.kubernetes.io/" + mode
		if got, ok := ns.Labels[key]; ok {
			t.Fatalf("label %s = %q present, want unset", key, got)
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
				"--set-string", "nri-image-policy.distro=" + distro,
			})
		})
	}
}

func TestAppendDistroInstallArgsRejectsUnknownDistro(t *testing.T) {
	if _, err := appendDistroInstallArgs([]string{"upgrade"}, "openshift"); err == nil {
		t.Fatal("appendDistroInstallArgs accepted an unknown --distro, want error")
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
