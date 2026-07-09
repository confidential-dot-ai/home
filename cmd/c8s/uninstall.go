//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
)

// kataSweepScript reverses the kata host install on a single node. Kept as a
// standalone POSIX-shell file (like the chart's files/scripts/*) so it gets
// shellcheck; it runs as the init container of the sweep DaemonSet built in
// kataSweepDaemonSet.
//
//go:embed kata-sweep.sh
var kataSweepScript string

var (
	uninstallNamespace       string
	uninstallRelease         string
	uninstallWait            bool
	uninstallKataSweep       bool
	uninstallHostSweepOnly   bool
	uninstallForce           bool
	uninstallDeleteCRDs      bool
	uninstallDeleteNamespace bool
)

// kataRuntimeClassNames are the RuntimeClass objects the chart renders under
// kata.enabled — a fixed contract with templates/kata.yaml (and, there, with
// kata-deploy's SHIMS_X86_64 and the kata-enforcement allowlist).
// kata-qemu-snp-nvidia / kata-qemu-tdx-nvidia are the confidential-GPU classes
// that ship with every kata install; listing them here keeps the running-pods
// guard covering GPU pods too.
var kataRuntimeClassNames = []string{"kata-qemu", "kata-clh", "kata-qemu-snp", "kata-qemu-tdx", "kata-qemu-snp-nvidia", "kata-qemu-tdx-nvidia"}

// confidentialWorkloadCRD is the chart's one CRD (crds/ dir, so helm never
// deletes it); --delete-crds removes it by name.
const confidentialWorkloadCRD = "confidentialworkloads.confidential.ai"

// kataRuntimeNodeLabel is the label kata-deploy stamps on each node once the
// runtime is installed (and removes again in its cleanup, when that runs to
// completion).
const kataRuntimeNodeLabel = "katacontainers.io/kata-runtime"

// snpCapabilityNodeLabel is the c8s-owned SNP platform label the install
// applies under --hardware-platform=sev-snp (the chart's kata.snpNodeSelector
// default — keep in lockstep with internal/helmchart/c8s/values.yaml). The
// sweep removes only this exact key (plus tdxHostLabelKey, the TDX
// counterpart the install applies under --hardware-platform=tdx): a custom
// kata.snpNodeSelector (an NFD or provisioning-owned label) was never applied
// by c8s and is not c8s's to strip.
const snpCapabilityNodeLabel = "confidential.ai/sev-snp"

// kataUninstallConfig is the slice of the release's computed values the kata
// host sweep needs. It is read from `helm get values --all` BEFORE the
// release is deleted — afterwards the -f/--set overrides from install time
// (custom guestImage.hostPath, distro, nodeSelector) are unrecoverable.
type kataUninstallConfig struct {
	Enabled             bool
	Distro              string
	ContainerdConfigDir string // resolved absolute host dir
	GuestImageHostPath  string
	// GuestImageNvidiaHostPath is the GPU guest-image dir (kata.gpu.guestImage.hostPath).
	// The GPU stack ships with every kata install, so it is set for any kata
	// release; empty only for a pre-GPU release (no kata.gpu block), where the
	// sweep skips it.
	GuestImageNvidiaHostPath string
	SweepImage               string
	NodeSelector             map[string]string
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the c8s Helm release and sweep kata artifacts off the hosts",
	Long: `Removes the release 'c8s install' deployed and, for a --kata install,
sweeps the host-side kata artifacts off every node.

'helm uninstall' already unwinds most of the install: the release resources
(operator, CDS, attestation-api, ratls-mesh, tls-lb, webhook
configuration, RuntimeClasses, enforcement policy), the NRI image-policy host
plugin (pre-delete hook), and — best-effort — the kata runtime itself:
deleting the kata-deploy DaemonSet runs 'kata-deploy cleanup' in its preStop
hook on each node.

The kata host sweep then nukes what that path cannot guarantee. The preStop
hook is bounded by the pod's termination grace period (and the runtime
restart it triggers can kill the pod mid-cleanup), and it knows nothing about
the c8s-side artifacts. After the release is gone the sweep runs a
short-lived privileged DaemonSet (the same digest-pinned busybox image the
install's containerd-prep uses) on the nodes kata-deploy targeted and
removes, idempotently:

  - /opt/kata (the kata-static payload) and the containerd-shim-kata-*
    symlinks
  - kata-deploy's containerd runtime drop-in, restarting containerd/RKE2
    only if the drop-in was still registered
  - the pulled kata-guest-base artifact (kata.guestImage.hostPath, multi-GB —
    nothing else cleans this up), and the separate GPU guest image
    (kata.gpu.guestImage.hostPath)
  - on RKE2: the c8s-managed containerd template and the containerd-prep lock
  - the katacontainers.io/kata-runtime node labels and the
    confidential.ai/sev-snp capability labels the install's probe applied
    (via kubectl)

Whether kata was installed — and which host paths, distro layout, and node
set to sweep — is read from the release's computed values
('helm get values --all') before the release is deleted, so -f overrides from
install time are honored. For a release that is already gone (e.g. a previous
bare 'helm uninstall' left the hosts dirty), pass --host-sweep-only: the helm
step is skipped and the sweep uses the embedded chart's defaults plus the
distro detected from the cluster.

The uninstall refuses to proceed while pods with a kata RuntimeClass are
still running — removing the runtime under a running confidential workload
kills it without cleanup. Delete those workloads first, or pass --force.

Left in place by default: the ConfidentialWorkload CRD (helm never deletes
crds/; --delete-crds removes it ALONG WITH EVERY ConfidentialWorkload object)
and the release namespace (--delete-namespace).

Requires the 'helm' and 'kubectl' CLIs to be on PATH.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateUninstallFlags(uninstallKataSweep, uninstallHostSweepOnly); err != nil {
			return err
		}
		if _, err := exec.LookPath("helm"); err != nil {
			return fmt.Errorf("helm CLI not found on PATH: %w", err)
		}
		if _, err := exec.LookPath("kubectl"); err != nil {
			return fmt.Errorf("kubectl CLI not found on PATH: %w", err)
		}

		ctx := cmd.Context()
		values, found, err := releaseValues(ctx, uninstallRelease, uninstallNamespace)
		if err != nil {
			return err
		}
		if !found && !uninstallHostSweepOnly {
			return fmt.Errorf("helm release %q not found in namespace %q — nothing to uninstall. If a previous uninstall already deleted the release but left kata artifacts on the nodes, re-run with --host-sweep-only", uninstallRelease, uninstallNamespace)
		}

		var cfg kataUninstallConfig
		if found {
			cfg, err = kataConfigFromValues(values)
			if err != nil {
				return fmt.Errorf("read kata config from release values: %w", err)
			}
		} else {
			fmt.Fprintf(os.Stdout, "+ release %q not found — sweeping with chart defaults and detected distro\n", uninstallRelease)
			cfg, err = chartDefaultKataConfig(ctx)
			if err != nil {
				return err
			}
		}
		// --host-sweep-only is an explicit "the hosts are dirty" claim, so it
		// sweeps even when the release values say kata was off (the dirt may
		// be from an earlier kata-enabled install of the same release name).
		sweep := uninstallKataSweep && (cfg.Enabled || uninstallHostSweepOnly)

		// Deleting the kata-deploy DaemonSet removes the runtime from under
		// any pod still using a kata RuntimeClass (its preStop cleanup runs
		// regardless of the sweep), so the guard applies whenever kata is
		// being uninstalled, not only when the sweep runs.
		if (cfg.Enabled || uninstallHostSweepOnly) && !uninstallForce {
			pods, err := listKataPods(ctx)
			if err != nil {
				return err
			}
			if len(pods) > 0 {
				return fmt.Errorf("pods with a kata RuntimeClass are still running and would lose their runtime:\n  %s\ndelete them first, or pass --force to uninstall anyway", strings.Join(pods, "\n  "))
			}
		}

		if !uninstallHostSweepOnly {
			helmArgs := buildHelmUninstallArgs(uninstallRelease, uninstallNamespace, uninstallWait)
			fmt.Fprintf(os.Stdout, "+ helm %s\n", strings.Join(helmArgs, " "))
			hc := exec.CommandContext(ctx, "helm", helmArgs...)
			hc.Stdout = os.Stdout
			hc.Stderr = os.Stderr
			if err := hc.Run(); err != nil {
				return fmt.Errorf("helm uninstall failed: %w", err)
			}
		}

		if sweep {
			if err := runKataSweep(ctx, uninstallNamespace, uninstallRelease, cfg); err != nil {
				return err
			}
		} else if uninstallKataSweep {
			fmt.Fprintln(os.Stdout, "+ kata not enabled in the release values — host sweep skipped")
		}

		if uninstallDeleteCRDs {
			if err := kubectlRun(ctx, "delete", "crd", confidentialWorkloadCRD, "--ignore-not-found"); err != nil {
				return err
			}
		}
		if uninstallDeleteNamespace {
			if err := kubectlRun(ctx, "delete", "namespace", uninstallNamespace, "--ignore-not-found"); err != nil {
				return err
			}
		}
		return nil
	},
}

// validateUninstallFlags rejects --host-sweep-only with --kata-sweep=false:
// the former exists only to run the sweep, so together they ask for nothing.
func validateUninstallFlags(kataSweep, hostSweepOnly bool) error {
	if hostSweepOnly && !kataSweep {
		return fmt.Errorf("--host-sweep-only runs only the kata host sweep, which --kata-sweep=false disables; drop one of the two flags")
	}
	return nil
}

// buildHelmUninstallArgs assembles the helm uninstall invocation. --wait
// holds helm until the release resources are actually gone — which is also
// when the kata-deploy preStop cleanup has had its chance to run — with the
// same fixed timeout the install uses.
func buildHelmUninstallArgs(release, namespace string, wait bool) []string {
	helmArgs := []string{"uninstall", release, "--namespace", namespace}
	if wait {
		helmArgs = append(helmArgs, "--wait", "--timeout=5m")
	}
	return helmArgs
}

// releaseValues reads the release's computed values (chart defaults merged
// with install-time -f/--set) as a decoded tree. found=false means the
// release does not exist; any other helm failure is an error.
func releaseValues(ctx context.Context, release, namespace string) (map[string]any, bool, error) {
	out, err := exec.CommandContext(ctx, "helm", "get", "values", release,
		"--namespace", namespace, "--all", "--output", "json").Output()
	if err != nil {
		var ee *exec.ExitError
		// helm reports a missing release as "Error: release: not found".
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "release: not found") {
			return nil, false, nil
		}
		if errors.As(err, &ee) {
			return nil, false, fmt.Errorf("helm get values %s -n %s: %w: %s", release, namespace, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, false, fmt.Errorf("helm get values %s -n %s: %w", release, namespace, err)
	}
	var tree map[string]any
	if err := json.Unmarshal(out, &tree); err != nil {
		return nil, false, fmt.Errorf("parse release values: %w", err)
	}
	return tree, true, nil
}

// chartDefaultKataConfig builds the sweep config for the --host-sweep-only
// path when the release (and with it the install-time values) is already
// gone: the embedded chart's defaults, with the distro detected from the
// cluster exactly as the install detects it (the chart default k8s would
// silently mis-target RKE2 hosts).
func chartDefaultKataConfig(ctx context.Context) (kataUninstallConfig, error) {
	dir, err := extractChart()
	if err != nil {
		return kataUninstallConfig{}, fmt.Errorf("extract embedded chart: %w", err)
	}
	defer os.RemoveAll(dir)

	out, err := exec.CommandContext(ctx, "helm", "show", "values", filepath.Join(dir, helmchart.ChartRoot)).Output()
	if err != nil {
		return kataUninstallConfig{}, fmt.Errorf("helm show values: %w", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return kataUninstallConfig{}, fmt.Errorf("parse chart values: %w", err)
	}

	distro, err := detectDistro(ctx)
	if err != nil {
		return kataUninstallConfig{}, err
	}
	fmt.Fprintf(os.Stdout, "+ detected host distro: %s\n", distro)
	kata, ok := nestedMap(tree, "kata")
	if !ok {
		return kataUninstallConfig{}, fmt.Errorf("embedded chart values carry no kata block")
	}
	kata["distro"] = distro

	cfg, err := kataConfigFromValues(tree)
	if err != nil {
		return kataUninstallConfig{}, err
	}
	// The sweep is the whole point of this path; the chart default
	// kata.enabled=false must not veto it.
	cfg.Enabled = true
	return cfg, nil
}

// kataConfigFromValues extracts the sweep config from a decoded values tree
// (helm get values --all, or helm show values for the chart-defaults path).
// Any missing piece is an error: sweeping with a guessed path either misses
// the artifacts or removes the wrong directory, both silently.
func kataConfigFromValues(tree map[string]any) (kataUninstallConfig, error) {
	kata, ok := nestedMap(tree, "kata")
	if !ok {
		return kataUninstallConfig{}, fmt.Errorf("values carry no kata block — is this release the c8s chart?")
	}
	cfg := kataUninstallConfig{}
	cfg.Enabled, _ = kata["enabled"].(bool)

	distro, err := stringAtPath(tree, "kata.distro")
	if err != nil {
		return kataUninstallConfig{}, err
	}
	cfg.Distro = distro

	override, _ := kata["containerdConfigDir"].(string)
	cfg.ContainerdConfigDir, err = kataContainerdDir(override, distro)
	if err != nil {
		return kataUninstallConfig{}, err
	}

	cfg.GuestImageHostPath, err = stringAtPath(tree, "kata.guestImage.hostPath")
	if err != nil {
		return kataUninstallConfig{}, err
	}

	// GPU guest image — a second multi-GB dir the GPU puller wrote; see
	// GuestImageNvidiaHostPath.
	if gpuImg, ok := nestedMap(tree, "kata", "gpu", "guestImage"); ok {
		cfg.GuestImageNvidiaHostPath, _ = gpuImg["hostPath"].(string)
	}

	cfg.SweepImage, err = sweepImageRef(tree)
	if err != nil {
		return kataUninstallConfig{}, err
	}

	if sel, ok := nestedMap(tree, "kata", "nodeSelector"); ok {
		cfg.NodeSelector = make(map[string]string, len(sel))
		for k, v := range sel {
			s, ok := v.(string)
			if !ok {
				return kataUninstallConfig{}, fmt.Errorf("kata.nodeSelector[%q] is not a string (%T)", k, v)
			}
			cfg.NodeSelector[k] = s
		}
	}
	return cfg, nil
}

// kataContainerdDir resolves the host containerd config directory the sweep
// targets — the same mapping as the chart's c8s.kataContainerdConfigDir
// helper, so the sweep cleans exactly where the install wrote.
func kataContainerdDir(override, distro string) (string, error) {
	if override != "" {
		return override, nil
	}
	switch distro {
	case "rke2":
		return "/var/lib/rancher/rke2/agent/etc/containerd", nil
	case "k8s":
		return "/etc/containerd", nil
	}
	return "", fmt.Errorf("kata.distro %q has no known containerd config dir and kata.containerdConfigDir is unset", distro)
}

// kataRestartCommand picks the host service restart that makes containerd
// drop the kata runtime registration — the same per-distro choice as the
// chart's nri-image-policy.restartCommand helper. The sweep only runs it
// when it removed a still-registered drop-in.
func kataRestartCommand(distro string) string {
	if distro == "rke2" {
		// A server/control-plane node runs rke2-server (which owns
		// containerd); a worker runs rke2-agent. Restart whichever is active
		// so single-node/server clusters work too.
		return "if systemctl is-active --quiet rke2-server; then systemctl restart rke2-server; else systemctl restart rke2-agent; fi"
	}
	return "systemctl restart containerd"
}

// sweepImageRef picks the image the sweep DaemonSet runs: the chart's
// containerd-prep image (kata.containerdPrep.image). The sweep has the same
// shape — pure POSIX shell, privileged, host root mounted — so it inherits
// the same digest-pinned, already-vetted image instead of introducing a new
// supply-chain entry. Digest wins over tag, mirroring the chart helper;
// neither set is an error, never a silently-floating default.
func sweepImageRef(tree map[string]any) (string, error) {
	img, ok := nestedMap(tree, "kata", "containerdPrep", "image")
	if !ok {
		return "", fmt.Errorf("values carry no kata.containerdPrep.image block")
	}
	repo, _ := img["repository"].(string)
	digest, _ := img["digest"].(string)
	tag, _ := img["tag"].(string)
	if repo == "" {
		return "", fmt.Errorf("kata.containerdPrep.image.repository is unset")
	}
	if digest != "" {
		return repo + "@" + digest, nil
	}
	if tag != "" {
		return repo + ":" + tag, nil
	}
	return "", fmt.Errorf("kata.containerdPrep.image has neither digest nor tag")
}

// listKataPods returns "namespace/name (runtimeClass)" for every pod whose
// runtimeClassName is one of the chart's kata RuntimeClasses. runtimeClassName
// is not a server-side field selector, so the filter runs client-side over a
// one-line-per-pod jsonpath dump.
func listKataPods(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "pods", "--all-namespaces",
		"-o", `jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.runtimeClassName}{"\n"}{end}`).Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get pods --all-namespaces: %w", err)
	}
	return filterKataPods(strings.Split(strings.TrimSpace(string(out)), "\n")), nil
}

// filterKataPods keeps the "namespace\tname\truntimeClass" lines whose class
// is a kata RuntimeClass. Pods without a runtimeClassName emit an empty third
// field and are skipped, as is anything malformed.
func filterKataPods(lines []string) []string {
	var pods []string
	for _, l := range lines {
		fields := strings.Split(l, "\t")
		if len(fields) != 3 || !slices.Contains(kataRuntimeClassNames, fields[2]) {
			continue
		}
		pods = append(pods, fmt.Sprintf("%s/%s (%s)", fields[0], fields[1], fields[2]))
	}
	return pods
}

// runKataSweep removes the kata host artifacts from every node kata-deploy
// targeted, after the release is gone: a short-lived privileged DaemonSet
// runs kata-sweep.sh as an init container on each node, the CLI waits for it
// to complete everywhere (rollout status blocks until every pod has passed
// init), then deletes it.
func runKataSweep(ctx context.Context, namespace, release string, cfg kataUninstallConfig) error {
	// The kata-deploy preStop cleanup and the image-puller's reconcile loop
	// both race the sweep (the puller re-pulls a guest image it sees
	// missing), so wait for their pods to be fully gone first. A no-op when
	// helm --wait already drained them or the release was already deleted.
	// Polled via kubectl get rather than `kubectl wait --for=delete`, whose
	// zero-matches exit status varies across kubectl versions.
	for _, component := range []string{"kata-deploy", "kata-image-puller", "kata-image-puller-nvidia"} {
		selector := fmt.Sprintf("app.kubernetes.io/instance=%s,app.kubernetes.io/component=%s", release, component)
		if err := waitPodsGone(ctx, namespace, selector); err != nil {
			return fmt.Errorf("waiting for %s pods to terminate: %w", component, err)
		}
	}

	// The sweep pods are privileged; re-assert the namespace's privileged
	// pod-security labels (idempotent — the install already set them, but on
	// the --host-sweep-only path the namespace may have been deleted).
	if err := applyNamespace(ctx, namespace); err != nil {
		return err
	}

	// kata-deploy's cleanup unlabels nodes when it runs to completion; sweep
	// the stragglers. The platform labels the install applied from
	// --hardware-platform are swept the same way (only the c8s-owned default
	// keys — see snpCapabilityNodeLabel). Best-effort — a leftover label is
	// cosmetic and must not abort the nuke mid-flight. The pre-check avoids
	// handing `kubectl label` an empty node set, whose exit status varies
	// across kubectl versions.
	for _, label := range []string{kataRuntimeNodeLabel, snpCapabilityNodeLabel, tdxHostLabelKey} {
		labelled, err := exec.CommandContext(ctx, "kubectl", "get", "nodes",
			"-l", label, "-o", "name").Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: listing %s-labelled nodes failed (continuing): %v\n", label, err)
		} else if strings.TrimSpace(string(labelled)) != "" {
			fmt.Fprintf(os.Stdout, "+ kubectl label nodes -l %s %s-\n", label, label)
			if out, err := exec.CommandContext(ctx, "kubectl", "label", "nodes",
				"-l", label, label+"-").CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: removing %s node labels failed (continuing): %v: %s\n", label, err, bytes.TrimSpace(out))
			}
		}
	}

	manifest, err := json.Marshal(kataSweepDaemonSet(release, namespace, cfg))
	if err != nil {
		return fmt.Errorf("render sweep manifest: %w", err)
	}
	name := kataSweepName(release)
	fmt.Fprintf(os.Stdout, "+ kubectl apply -f - # DaemonSet/%s (kata host sweep)\n", name)
	kc := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	kc.Stdin = bytes.NewReader(manifest)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl apply sweep DaemonSet: %w", err)
	}

	if err := kubectlRun(ctx, "rollout", "status", "daemonset/"+name,
		"-n", namespace, "--timeout=5m"); err != nil {
		// Leave the DaemonSet in place: its sweep container logs are the
		// only record of which node failed and why.
		return fmt.Errorf("kata host sweep did not complete: %w — inspect with 'kubectl -n %s logs ds/%s -c sweep', then remove it with 'kubectl -n %s delete ds %s'", err, namespace, name, namespace, name)
	}

	return kubectlRun(ctx, "delete", "daemonset", name, "-n", namespace, "--ignore-not-found")
}

func kataSweepName(release string) string {
	return release + "-kata-sweep"
}

// waitPodsGone polls until no pod in the namespace matches the selector.
// Terminating pods still list, so an empty result means every container —
// including any preStop hook — is finished.
func waitPodsGone(ctx context.Context, namespace, selector string) error {
	const timeout = 5 * time.Minute
	fmt.Fprintf(os.Stdout, "+ waiting for pods -l %s to terminate\n", selector)
	deadline := time.Now().Add(timeout)
	for {
		out, err := exec.CommandContext(ctx, "kubectl", "get", "pods",
			"-n", namespace, "-l", selector, "-o", "name").Output()
		if err != nil {
			return fmt.Errorf("kubectl get pods -n %s -l %s: %w", namespace, selector, err)
		}
		if strings.TrimSpace(string(out)) == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pods -l %s still present after %s", selector, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// kataSweepDaemonSet renders the sweep DaemonSet: same node set (linux +
// kata.nodeSelector), tolerations, and privilege shape as the kata-deploy
// DaemonSet it cleans up after, with kata-sweep.sh as an init container and a
// pause container whose readiness lets `kubectl rollout status` double as
// "every node finished sweeping".
func kataSweepDaemonSet(release, namespace string, cfg kataUninstallConfig) *appsv1.DaemonSet {
	labels := map[string]string{
		"app.kubernetes.io/name":      "c8s-operator",
		"app.kubernetes.io/instance":  release,
		"app.kubernetes.io/component": "kata-sweep",
	}
	nodeSelector := map[string]string{"kubernetes.io/os": "linux"}
	for k, v := range cfg.NodeSelector {
		nodeSelector[k] = v
	}
	privileged := true
	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "DaemonSet"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      kataSweepName(release),
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					// hostPID: the sweep nsenters into PID 1 to restart the
					// runtime when it deregisters a leftover drop-in.
					HostPID:      true,
					NodeSelector: nodeSelector,
					// Sweep everywhere kata-deploy installed — including
					// control-plane and otherwise-tainted nodes (mirrors the
					// install's one-shot posture).
					Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					InitContainers: []corev1.Container{{
						Name:            "sweep",
						Image:           cfg.SweepImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"/bin/sh", "-c"},
						Args:            []string{kataSweepScript},
						Env: []corev1.EnvVar{
							{Name: "HOST_CONTAINERD_DIR", Value: cfg.ContainerdConfigDir},
							{Name: "GUEST_IMAGE_DIR", Value: cfg.GuestImageHostPath},
							// Empty only for a pre-GPU release; the sweep skips it then.
							{Name: "GUEST_IMAGE_DIR_NVIDIA", Value: cfg.GuestImageNvidiaHostPath},
							{Name: "RKE2_PREP", Value: strconv.FormatBool(cfg.Distro == "rke2")},
							{Name: "RESTART_COMMAND", Value: kataRestartCommand(cfg.Distro)},
						},
						// Privileged with the host root mounted — the same
						// posture as kata-deploy: removing a runtime from a
						// host is inherently this shape.
						SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
						VolumeMounts:    []corev1.VolumeMount{{Name: "host", MountPath: "/host"}},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("32Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("200m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
					}},
					Containers: []corev1.Container{{
						Name:            "pause",
						Image:           cfg.SweepImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						// busybox sleep has no "infinity"; the pod lives only
						// until the CLI's rollout-status wait returns anyway.
						Command: []string{"/bin/sh", "-c", "sleep 2147483647"},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("10m"),
								corev1.ResourceMemory: resource.MustParse("16Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("32Mi"),
							},
						},
					}},
					Volumes: []corev1.Volume{{
						Name: "host",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/"},
						},
					}},
				},
			},
		},
	}
}

// kubectlRun executes kubectl streaming output to the user, prefixed with the
// echoed command line like the install's helm/kubectl calls.
func kubectlRun(ctx context.Context, args ...string) error {
	fmt.Fprintf(os.Stdout, "+ kubectl %s\n", strings.Join(args, " "))
	kc := exec.CommandContext(ctx, "kubectl", args...)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func init() {
	uninstallCmd.Flags().StringVar(&uninstallNamespace, "namespace", "c8s-system", "namespace the release was installed into")
	uninstallCmd.Flags().StringVar(&uninstallRelease, "release", "c8s", "Helm release name")
	uninstallCmd.Flags().BoolVar(&uninstallWait, "wait", true, "wait for the release deletion to complete (helm --wait); the kata host sweep additionally waits for the kata pods to be gone either way")
	uninstallCmd.Flags().BoolVar(&uninstallKataSweep, "kata-sweep", true, "after the release is deleted, sweep the kata host artifacts (/opt/kata, containerd drop-in, kata-guest-base image, RKE2 prep template, node labels) off every kata node via a short-lived privileged DaemonSet. Skipped automatically when the release was installed without --kata")
	uninstallCmd.Flags().BoolVar(&uninstallHostSweepOnly, "host-sweep-only", false, "skip the helm uninstall and only run the kata host sweep — for a cluster whose release is already gone (e.g. a previous bare 'helm uninstall') but whose nodes still carry kata artifacts. Uses the chart defaults and the distro detected from the cluster when the release values are unavailable")
	uninstallCmd.Flags().BoolVar(&uninstallForce, "force", false, "uninstall even while pods with a kata RuntimeClass are running (they lose their runtime: kata VMs keep running unmanaged but cannot restart)")
	uninstallCmd.Flags().BoolVar(&uninstallDeleteCRDs, "delete-crds", false, "also delete the ConfidentialWorkload CRD — this deletes EVERY ConfidentialWorkload object in the cluster with it")
	uninstallCmd.Flags().BoolVar(&uninstallDeleteNamespace, "delete-namespace", false, "also delete the release namespace (and everything left in it, e.g. an operator-created image pull Secret)")
	rootCmd.AddCommand(uninstallCmd)
}
