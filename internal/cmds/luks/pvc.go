package luks

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// kubectlRun invokes kubectl (the same auth path `c8s install` relies on),
// feeding stdin when non-empty. Package-level so tests can stub the cluster.
var kubectlRun = func(ctx context.Context, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// claimName is the deterministic PVC name for a (workload, volume) pair —
// destroy recomputes it, so no state beyond openbao + the cluster is needed.
func claimName(workload, name string) string {
	return "c8s-luks-" + workload + "-" + name
}

// provisionPVC creates a raw-block PVC (volumeMode: Block) in the workload's
// namespace via kubectl. Nothing is formatted here — an unbound claim has no
// device to luksFormat — so the emitted annotation always carries
// mode=format-if-empty: the pod's c8s-luks-open init container formats the
// empty device on first boot, inside the TEE boundary, and the passphrase is
// only ever used by the workload that owns the volume.
func provisionPVC(ctx context.Context, cfg createConfig) (claim string, notes []string, err error) {
	claim = claimName(cfg.workload, cfg.name)

	out, err := kubectlRun(ctx, "", "get", "pvc", claim, "-n", cfg.namespace, "--ignore-not-found", "-o", "name")
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(out) != "" {
		return "", nil, fmt.Errorf("PVC %s/%s already exists — `c8s luks destroy --driver pvc` it first", cfg.namespace, claim)
	}

	spec := map[string]any{
		"accessModes": []string{"ReadWriteOnce"},
		"volumeMode":  "Block",
		"resources":   map[string]any{"requests": map[string]string{"storage": cfg.size.String()}},
	}
	if cfg.storageClass != "" {
		spec["storageClassName"] = cfg.storageClass
	}
	manifest, err := yaml.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "PersistentVolumeClaim",
		"metadata": map[string]any{
			"name":      claim,
			"namespace": cfg.namespace,
			"labels": map[string]string{
				"app.kubernetes.io/part-of":   "c8s",
				"confidential.ai/cw":          cfg.workload,
				"confidential.ai/luks-volume": cfg.name,
			},
		},
		"spec": spec,
	})
	if err != nil {
		return "", nil, fmt.Errorf("marshal PVC manifest: %w", err)
	}
	if _, err := kubectlRun(ctx, string(manifest), "apply", "-n", cfg.namespace, "-f", "-"); err != nil {
		return "", nil, err
	}

	notes = []string{
		"pvc driver — the webhook attaches the claim to the pod (raw volumeDevice on c8s-luks-open); no volume snippet or nodeSelector needed.",
		"mode=format-if-empty: the pod luksFormats + mkfs the empty device on first boot, so no node access is ever required.",
		"A WaitForFirstConsumer StorageClass leaves the PVC Pending until the first pod schedules — that is normal.",
	}
	return claim, notes, nil
}

// pvcConsumers lists pods in the namespace that mount the claim. Used by
// destroy's pre-check: deleting the passphrase under a live volume would
// orphan its data at the next open.
func pvcConsumers(ctx context.Context, claim, namespace string) ([]string, error) {
	out, err := kubectlRun(ctx, "", "get", "pods", "-n", namespace, "-o", "json")
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Volumes []struct {
					PersistentVolumeClaim *struct {
						ClaimName string `json:"claimName"`
					} `json:"persistentVolumeClaim"`
				} `json:"volumes"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("parse kubectl pods json: %w", err)
	}
	var users []string
	for _, p := range list.Items {
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == claim {
				users = append(users, p.Metadata.Name)
			}
		}
	}
	return users, nil
}

// destroyPVC deletes the claim. --wait=false: pvc-protection keeps a consumed
// claim Terminating until its pod is gone — surface that instead of hanging.
func destroyPVC(ctx context.Context, cfg destroyCfg) error {
	claim := claimName(cfg.workload, cfg.name)
	if _, err := kubectlRun(ctx, "", "delete", "pvc", claim, "-n", cfg.namespace, "--ignore-not-found", "--wait=false"); err != nil {
		return err
	}
	return nil
}
