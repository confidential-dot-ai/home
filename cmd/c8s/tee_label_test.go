//go:build !c8s_node

package main

import (
	"testing"
)

// singleLabelPair feeds the auto-labeller: only the chart's single-pair
// default shape may be applied automatically; the opt-out ({}), multi-pair,
// and non-string shapes must report ok=false so the labeller skips instead of
// guessing which label the operator owns.
func TestSingleLabelPair(t *testing.T) {
	tests := []struct {
		name   string
		sel    map[string]any
		wantK  string
		wantV  string
		wantOK bool
	}{
		{name: "chart default", sel: map[string]any{"confidential.ai/sev-snp": "true"}, wantK: "confidential.ai/sev-snp", wantV: "true", wantOK: true},
		{name: "empty is the opt-out", sel: map[string]any{}, wantOK: false},
		{name: "nil is the opt-out", sel: nil, wantOK: false},
		{name: "multi-pair is operator-owned", sel: map[string]any{"a": "1", "b": "2"}, wantOK: false},
		{name: "non-string value", sel: map[string]any{"a": true}, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, v, ok := singleLabelPair(tt.sel)
			if k != tt.wantK || v != tt.wantV || ok != tt.wantOK {
				t.Fatalf("singleLabelPair(%v) = (%q, %q, %t), want (%q, %q, %t)", tt.sel, k, v, ok, tt.wantK, tt.wantV, tt.wantOK)
			}
		})
	}
}

// planTEELabels maps the declared --hardware-platform to the label to apply
// and the other platform's label whose presence aborts the install. The two
// c8s-owned keys are a fixed contract with templates/kata.yaml (RC
// nodeSelectors) and the uninstall sweep — these tests pin the mapping.
func TestPlanTEELabels(t *testing.T) {
	chartDefaults := map[string]any{
		"kata": map[string]any{
			"nodeSelector":    map[string]any{},
			"snpNodeSelector": map[string]any{"confidential.ai/sev-snp": "true"},
			"tdxNodeSelector": map[string]any{"confidential.ai/tdx": "true"},
		},
	}

	t.Run("sev-snp applies the chart selector and conflict-checks the tdx label", func(t *testing.T) {
		plan, ok, err := planTEELabels(chartDefaults, "sev-snp")
		if err != nil || !ok {
			t.Fatalf("planTEELabels = ok=%t err=%v, want ok", ok, err)
		}
		if plan.targetKey != "confidential.ai/sev-snp" || plan.targetValue != "true" {
			t.Errorf("target = %s=%s, want confidential.ai/sev-snp=true", plan.targetKey, plan.targetValue)
		}
		if plan.otherKey != tdxHostLabelKey {
			t.Errorf("otherKey = %q, want %q", plan.otherKey, tdxHostLabelKey)
		}
		if plan.nodeSelector != "kubernetes.io/os=linux" {
			t.Errorf("nodeSelector = %q, want kubernetes.io/os=linux", plan.nodeSelector)
		}
	})

	t.Run("tdx applies the chart selector and conflict-checks the snp label", func(t *testing.T) {
		plan, ok, err := planTEELabels(chartDefaults, "tdx")
		if err != nil || !ok {
			t.Fatalf("planTEELabels = ok=%t err=%v, want ok", ok, err)
		}
		if plan.targetKey != tdxHostLabelKey || plan.targetValue != "true" {
			t.Errorf("target = %s=%s, want %s=true", plan.targetKey, plan.targetValue, tdxHostLabelKey)
		}
		if plan.otherKey != snpCapabilityNodeLabel {
			t.Errorf("otherKey = %q, want %q", plan.otherKey, snpCapabilityNodeLabel)
		}
	})

	t.Run("cleared snpNodeSelector skips labelling on sev-snp", func(t *testing.T) {
		tree := map[string]any{
			"kata": map[string]any{"snpNodeSelector": map[string]any{}},
		}
		if _, ok, err := planTEELabels(tree, "sev-snp"); ok || err != nil {
			t.Fatalf("planTEELabels = ok=%t err=%v, want skip (unrestricted-scheduling opt-out)", ok, err)
		}
	})

	t.Run("cleared tdxNodeSelector skips labelling on tdx", func(t *testing.T) {
		tree := map[string]any{
			"kata": map[string]any{"tdxNodeSelector": map[string]any{}},
		}
		if _, ok, err := planTEELabels(tree, "tdx"); ok || err != nil {
			t.Fatalf("planTEELabels = ok=%t err=%v, want skip (unrestricted-scheduling opt-out)", ok, err)
		}
	})

	t.Run("kata.nodeSelector narrows the labelled node set", func(t *testing.T) {
		tree := map[string]any{
			"kata": map[string]any{
				"nodeSelector":    map[string]any{"pool": "kata"},
				"snpNodeSelector": map[string]any{"confidential.ai/sev-snp": "true"},
			},
		}
		plan, ok, err := planTEELabels(tree, "sev-snp")
		if err != nil || !ok {
			t.Fatalf("planTEELabels = ok=%t err=%v, want ok", ok, err)
		}
		if plan.nodeSelector != "kubernetes.io/os=linux,pool=kata" {
			t.Errorf("nodeSelector = %q, want kubernetes.io/os=linux,pool=kata", plan.nodeSelector)
		}
	})

	t.Run("non-string kata.nodeSelector value errors", func(t *testing.T) {
		tree := map[string]any{
			"kata": map[string]any{
				"nodeSelector":    map[string]any{"pool": 3},
				"snpNodeSelector": map[string]any{"confidential.ai/sev-snp": "true"},
			},
		}
		if _, _, err := planTEELabels(tree, "sev-snp"); err == nil {
			t.Fatal("planTEELabels accepted a non-string kata.nodeSelector value, want error")
		}
	})
}
