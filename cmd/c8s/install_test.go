//go:build !c8s_node

package main

import "testing"

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
