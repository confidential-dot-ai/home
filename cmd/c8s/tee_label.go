//go:build !c8s_node

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// autoLabelTEENodes labels every kata-targeted node for the TEE the operator
// declared via --hardware-platform:
//
//	sev-snp → apply kata.snpNodeSelector (default confidential.ai/sev-snp=true)
//	tdx     → apply kata.tdxNodeSelector (default confidential.ai/tdx=true)
//
// The label is DECLARATIVE: the flag is trusted, there is no hardware probe.
// Declaring the wrong platform makes confidential pods fail at runtime on
// every node exactly as it would on one, so it fails loudly, and a node that
// lies about its hardware fails per-pod attestation regardless — the label is
// a scheduling aid, not a security control.
//
// A cluster still carrying the OTHER platform's c8s-owned label is refused,
// with the exact kubectl command to clear it: silently relabelling would
// re-point confidential scheduling on what is most likely a mistyped
// --hardware-platform or a leftover install — a platform switch must be the
// operator's explicit act. Only the two c8s-owned default keys are involved;
// a custom selector (NFD or provisioning-owned) is never applied, checked,
// or stripped by this path.
//
// Labelling is idempotent (kubectl --overwrite; a node already carrying the
// pair is a server-side no-op). Like the preflights, this reads the chart's
// default values and only runs on the default install path; -f installs own
// their node labels (caller skips).
func autoLabelTEENodes(ctx context.Context, chartPath, hardwarePlatform string) error {
	out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
	if err != nil {
		return fmt.Errorf("helm show values %q: %w", chartPath, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return fmt.Errorf("parse chart values: %w", err)
	}

	plan, ok, err := planTEELabels(tree, hardwarePlatform)
	if err != nil {
		return err
	}
	if !ok {
		// Empty kata.snpNodeSelector = confidential-class scheduling is
		// unrestricted, nothing to label (the documented opt-out).
		return nil
	}

	// Refuse to relabel over the other platform's label (see doc comment).
	// Selecting on key existence means zero matches is the happy path.
	if plan.otherKey != plan.targetKey {
		labelled, err := exec.CommandContext(ctx, "kubectl", "get", "nodes",
			"-l", plan.otherKey, "-o", "name").Output()
		if err != nil {
			return fmt.Errorf("kubectl get nodes -l %s: %w", plan.otherKey, err)
		}
		if nodes := strings.TrimSpace(string(labelled)); nodes != "" {
			return fmt.Errorf("--hardware-platform=%s, but these nodes still carry the other platform's label %s (from an earlier install or a different platform declaration):\n\n%s\n\nRefusing to relabel over it. If the platform switch is intended, clear the label and rerun:\n\n    kubectl label nodes -l %s %s-",
				hardwarePlatform, plan.otherKey, nodes, plan.otherKey, plan.otherKey)
		}
	}

	// Bulk-label the kata-targeted node set. Zero matching nodes is not an
	// error here — the platform preflight right after this reports it with
	// actionable context.
	fmt.Fprintf(os.Stdout, "+ kubectl label nodes -l %s %s=%s --overwrite # --hardware-platform=%s\n",
		plan.nodeSelector, plan.targetKey, plan.targetValue, hardwarePlatform)
	if err := kubectlRun(ctx, "label", "nodes", "-l", plan.nodeSelector,
		plan.targetKey+"="+plan.targetValue, "--overwrite"); err != nil {
		return fmt.Errorf("labelling %s nodes: %w", hardwarePlatform, err)
	}
	return nil
}

// teeLabelPlan is the label work a given --hardware-platform implies:
// apply targetKey=targetValue to nodes matching nodeSelector, after
// checking no node still carries otherKey (the other platform's c8s-owned
// default key — its presence aborts the install).
type teeLabelPlan struct {
	targetKey    string
	targetValue  string
	otherKey     string
	nodeSelector string
}

// planTEELabels derives the labelling plan from the chart's default values.
// ok=false means nothing should be labelled or conflict-checked:
// kata.snpNodeSelector was cleared (the documented unrestricted-scheduling
// opt-out) or reshaped into a custom multi-pair selector whose labels the
// operator owns.
func planTEELabels(tree map[string]any, hardwarePlatform string) (teeLabelPlan, bool, error) {
	// The kata-targeted node set: the same nodes kata-deploy installs on
	// (templates/kata.yaml — linux plus kata.nodeSelector).
	kataSelector := map[string]any{"kubernetes.io/os": "linux"}
	if ns, ok := nestedMap(tree, "kata", "nodeSelector"); ok {
		for k, v := range ns {
			if _, isString := v.(string); !isString {
				return teeLabelPlan{}, false, fmt.Errorf("kata.nodeSelector[%q] is not a string (%T)", k, v)
			}
			kataSelector[k] = v
		}
	}
	nodeSelector, ok := labelSelector(kataSelector)
	if !ok {
		return teeLabelPlan{}, false, fmt.Errorf("kata.nodeSelector is not a string map")
	}

	switch hardwarePlatform {
	case "tdx":
		sel, _ := nestedMap(tree, "kata", "tdxNodeSelector")
		key, value, ok := singleLabelPair(sel)
		if !ok {
			return teeLabelPlan{}, false, nil
		}
		return teeLabelPlan{
			targetKey:    key,
			targetValue:  value,
			otherKey:     snpCapabilityNodeLabel,
			nodeSelector: nodeSelector,
		}, true, nil
	default: // sev-snp — appendCvmModeInstallArgs already rejected anything else
		sel, _ := nestedMap(tree, "kata", "snpNodeSelector")
		key, value, ok := singleLabelPair(sel)
		if !ok {
			return teeLabelPlan{}, false, nil
		}
		return teeLabelPlan{
			targetKey:    key,
			targetValue:  value,
			otherKey:     tdxHostLabelKey,
			nodeSelector: nodeSelector,
		}, true, nil
	}
}

// singleLabelPair returns the sole key/value of a decoded selector map. The
// chart default (confidential.ai/sev-snp: "true") is a single pair; anything
// else — empty (the documented opt-out), multiple pairs, or a non-string
// value — reports ok=false so the auto-labeller skips instead of guessing.
func singleLabelPair(sel map[string]any) (key, value string, ok bool) {
	if len(sel) != 1 {
		return "", "", false
	}
	for k, v := range sel {
		s, isString := v.(string)
		if !isString {
			return "", "", false
		}
		key, value, ok = k, s, true
	}
	return key, value, ok
}
