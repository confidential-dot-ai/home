//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/version"
)

var (
	installNamespace string
	installRelease   string
	installValues    []string
	installWait      bool
	installCRDs      bool

	installCertFSGroup          int64
	installCertKeyMode          string
	installGetCertRenewInterval time.Duration
	installGetCertRunAsUser     int64
	installGetCertRunAsGroup    int64
	installGetCertRunAsNonRoot  bool

	installKata            bool
	installKataDebug       bool
	installCvmMode         string
	installSingleNode      bool
	installImagePullSecret string

	installResolveDigests bool
)

// Flag names referenced in more than one place (registration plus a Changed()
// gate or an arg-builder call). Naming them once keeps the references from
// drifting.
const (
	flagCvmMode = "cvm-mode"
)

// c8sComponent maps a chart image to the helm value keys --resolve-digests
// pins. valuePrefix is the values path whose image the chart renders;
// repository is that path's values.yaml default, against which the tag is
// resolved. resolveDigests pins both the repository and the digest it resolved
// against, so an operator's -f override of a repository cannot leave the chart
// deploying repoA@<digest-of-repoB>.
type c8sComponent struct {
	valuePrefix string // values path, e.g. "cds.image" (renders {repository}@{digest})
	repository  string // values.yaml default repository resolved against
}

// chartComponents reads the component set from the chart at chartPath via
// `helm show values` (which dumps values.yaml without rendering templates, so
// no render guard fires). The valuePath list and each component's repository
// both live in that one values tree, so a single decode serves both. This is
// the single source shared with the chart's c8s.components helper; the Go side
// does not duplicate the list.
func chartComponents(ctx context.Context, chartPath string) ([]c8sComponent, error) {
	out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
	if err != nil {
		return nil, fmt.Errorf("helm show values %q: %w", chartPath, err)
	}

	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return nil, fmt.Errorf("parse chart values: %w", err)
	}

	list, ok := tree["c8sComponents"].([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("chart declares no c8sComponents")
	}

	comps := make([]c8sComponent, 0, len(list))
	for _, entry := range list {
		m, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("c8sComponents entry is not a mapping: %T", entry)
		}
		valuePath, ok := m["valuePath"].(string)
		if !ok {
			return nil, fmt.Errorf("c8sComponents entry missing string valuePath: %v", m)
		}
		repo, err := stringAtPath(tree, valuePath+".repository")
		if err != nil {
			return nil, fmt.Errorf("component %q: %w", valuePath, err)
		}
		comps = append(comps, c8sComponent{valuePrefix: valuePath, repository: repo})
	}
	return comps, nil
}

// preflightCDSNode fails fast (before the helm install) when no node carries
// the CDS node-selector label. The chart pins the singleton CDS pod to that
// label, so without a matching node CDS stays Pending and `helm --wait` would
// block for the full timeout before failing with an opaque message. The label
// requirement is exact (read straight from the chart's cds.node.selector), not
// a heuristic.
//
// It reads the chart's default values, so it only guards the default path; an
// operator who customizes via -f is trusted to manage node labels themselves
// (the caller skips this when -f is supplied).
func preflightCDSNode(ctx context.Context, chartPath string) error {
	out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
	if err != nil {
		return fmt.Errorf("helm show values %q: %w", chartPath, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return fmt.Errorf("parse chart values: %w", err)
	}

	sel, ok := nestedMap(tree, "cds", "node", "selector")
	if !ok || len(sel) != 1 {
		// The chart's own one-pair guard will report a malformed selector; the
		// preflight only owns the "no matching node" case.
		return nil
	}
	var key, val string
	for k, v := range sel {
		key = k
		val, _ = v.(string)
	}

	labeled, err := exec.CommandContext(ctx, "kubectl", "get", "nodes",
		"-l", key+"="+val, "-o", "name").Output()
	if err != nil {
		return fmt.Errorf("kubectl get nodes -l %s=%s: %w", key, val, err)
	}
	if strings.TrimSpace(string(labeled)) == "" {
		return fmt.Errorf("no node is labelled %s=%s, so the CDS pod cannot schedule (image policy pins it there). Label one: kubectl label node <node> %s=%s", key, val, key, val)
	}
	return nil
}

// clusterDistroNodes reads every node's kubeletVersion via kubectl and splits
// the nodes into RKE2-built vs upstream-built buckets.
//
// Detection: RKE2's bundled kubelet stamps a "+rke2" build suffix onto
// status.nodeInfo.kubeletVersion (e.g. v1.29.5+rke2r1); vanilla upstream
// kubelet has no suffix. The suffix is the only reliable distro signal
// kubectl can see without going on-host.
func clusterDistroNodes(ctx context.Context) (rke2, other []string, err error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes",
		"-o", `jsonpath={range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\n"}{end}`).Output()
	if err != nil {
		return nil, nil, fmt.Errorf("kubectl get nodes: %w", err)
	}
	rke2, other = classifyDistroNodes(strings.Split(strings.TrimSpace(string(out)), "\n"))
	return rke2, other, nil
}

// detectDistro picks the host distro for an install, from the cluster's
// kubelet versions.
func detectDistro(ctx context.Context) (string, error) {
	rke2Nodes, otherNodes, err := clusterDistroNodes(ctx)
	if err != nil {
		return "", err
	}
	return chooseDistro(rke2Nodes, otherNodes)
}

// classifyDistroNodes splits "name\tkubeletVersion" lines into RKE2-built vs
// upstream-built buckets by the "+rke2" build-metadata suffix RKE2's kubelet
// build carries. Lines without a tab (no kubeletVersion reported) are skipped
// — a node Status with no kubeletVersion can't be classified either way, so
// detection ignores it rather than guessing.
func classifyDistroNodes(lines []string) (rke2, other []string) {
	for _, l := range lines {
		name, ver, ok := strings.Cut(l, "\t")
		if !ok || name == "" {
			continue
		}
		if strings.Contains(ver, "+rke2") {
			rke2 = append(rke2, name)
		} else {
			other = append(other, name)
		}
	}
	return
}

// chooseDistro maps the node classification to a distro value: any RKE2 node
// (and no upstream ones) selects rke2; otherwise k8s, which also covers an
// empty or unclassifiable node list — the chart default and the only safe
// guess. A mixed cluster has no single right answer — kata-deploy and
// nri-image-policy patch a distro-specific containerd path on every selected
// node — so it demands an explicit per-component choice via -f instead of
// guessing.
func chooseDistro(rke2Nodes, otherNodes []string) (string, error) {
	if len(rke2Nodes) > 0 && len(otherNodes) > 0 {
		return "", fmt.Errorf("cannot detect the host distro: the cluster mixes RKE2 nodes (%s) and non-RKE2 nodes (%s). Set kata.distro / nriImagePolicy.distro and restrict the install with kata.nodeSelector / nriImagePolicy.nodeSelector via -f", strings.Join(rke2Nodes, ", "), strings.Join(otherNodes, ", "))
	}
	if len(rke2Nodes) > 0 {
		return "rke2", nil
	}
	return "k8s", nil
}

// nestedMap walks map keys and returns the map[string]any at the path.
func nestedMap(tree map[string]any, keys ...string) (map[string]any, bool) {
	cur := tree
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// stringAtPath walks a dotted path through a decoded YAML tree and returns the
// string at it, erroring if a segment is missing or the leaf is not a string.
func stringAtPath(tree map[string]any, path string) (string, error) {
	var cur any = tree
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("path %q: %q is not a mapping", path, seg)
		}
		cur, ok = m[seg]
		if !ok {
			return "", fmt.Errorf("path %q: missing segment %q", path, seg)
		}
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("path %q: not a string (%T)", path, cur)
	}
	return s, nil
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the c8s operator, CRDs, attestation-api, and component charts via Helm",
	Long: `Extracts the bundled c8s Helm chart and runs
'helm upgrade --install' against the current kubeconfig context. Deploys:

  - the install namespace (labeled pod-security=privileged)
  - the c8s Deployment + Service (admission webhook + status-mirror controllers)
  - the ConfidentialWorkload CRD
  - the mutating admission webhook configuration
  - the attestation-api DaemonSet (per-node /attest + /verify)
  - the CDS trust root (attestation, EAR issuance, mesh CA, leaf signing)
  - the ratls-mesh, nri-image-policy, tee-proxy, and tls-lb components

Under --kata the install is ENFORCING: every workload pod runs as a kata VM
(injected and validated at admission), and the host-side ratls-mesh,
attestation-api, and nri-image-policy are replaced by their in-guest
counterparts baked into the kata-guest-base image.

--debug (with --kata) selects the kata-guest-base DEBUG image variant, whose
baked guest policy allows the host log/exec stream RPCs so 'kubectl logs' and
'kubectl exec' work against kata pods. Container I/O then crosses the TEE
boundary in plaintext, and the debug image's SNP launch measurement differs
from the locked one (attestation pinned to the locked value rejects it).
Development only.

The host distro (k8s vs rke2) is detected from the cluster's kubelet versions;
override kata.distro / nriImagePolicy.distro via -f for a layout detection
cannot see. On RKE2 the kata-deploy and nri-image-policy DaemonSets carry a
containerd-prep initContainer that wires up the drop-in import; no node
preparation is required beyond a running cluster.

By default each component image tag is resolved to its registry digest (via the
'crane' CLI) and pinned, including the CDS digest the image-policy floor and
render guard require, and nriImagePolicy.bootstrapAllowlist.deriveComponents is
enabled so the resolved images are added to the NRI allowlist. This makes a
plain install satisfy the floor with no hand-written values. Pass
--resolve-digests=false when you supply the digests yourself via -f; the
render guards then require those values.

When the c8s images live in a registry that requires authentication, create a
kubernetes.io/dockerconfigjson Secret in the release namespace and pass
--image-pull-secret <name>: the chart wires it into every component's
imagePullSecrets, so pods authenticate from first start. Under --kata the
same Secret also authenticates the kata-image-puller's in-pod oras pull of
the kata-guest-base artifact (override: kata.guestImage.pullerAuthSecret).
This is the cluster-side (kubelet) credential; digest resolution runs locally
via crane and uses your local docker login.

Requires the 'helm' and 'kubectl' CLIs to be on PATH, and 'crane' unless
--resolve-digests=false.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateKataDebugFlags(installKata, installKataDebug); err != nil {
			return err
		}
		if _, err := exec.LookPath("helm"); err != nil {
			return fmt.Errorf("helm CLI not found on PATH: %w", err)
		}
		if _, err := exec.LookPath("kubectl"); err != nil {
			return fmt.Errorf("kubectl CLI not found on PATH: %w", err)
		}

		dir, err := extractChart()
		if err != nil {
			return fmt.Errorf("extract embedded chart: %w", err)
		}
		defer os.RemoveAll(dir)

		chartPath := filepath.Join(dir, helmchart.ChartRoot)
		components, err := chartComponents(cmd.Context(), chartPath)
		if err != nil {
			return fmt.Errorf("read chart components: %w", err)
		}
		imageTag := defaultInstallImageTag(version.Version)
		helmArgs := []string{
			"upgrade", "--install", installRelease, chartPath,
			"--namespace", installNamespace,
		}
		// Chart has no default image tags; chart images are released in lockstep
		// with the CLI, so pass the CLI's build version for every component.
		// A non-release build has no published image tag and falls back to the
		// main branch tag (see defaultInstallImageTag).
		for _, c := range components {
			helmArgs = append(helmArgs, "--set", c.valuePrefix+".tag="+imageTag)
		}
		helmArgs = appendInstallCRDArgs(helmArgs, installCRDs)
		// kata-deploy and nri-image-policy must bind the host's containerd
		// layout in every install mode, so the distro is detected from the
		// cluster's kubelet versions and plumbed; letting the chart default
		// (k8s) stand would silently mis-target RKE2. With -f nothing is
		// plumbed — helm gives --set precedence over -f, and the values-file
		// owner owns the layout (kata.distro / nriImagePolicy.distro there if
		// the chart default doesn't fit).
		if len(installValues) == 0 {
			distro, err := detectDistro(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "+ detected host distro: %s\n", distro)
			helmArgs = appendDistroInstallArgs(helmArgs, distro)
		}
		// Only emit --set when the operator passed --cvm-mode, so a value from
		// -f (or the chart default) wins when the flag is unset; helm gives
		// --set strict precedence over -f.
		if cmd.Flags().Changed(flagCvmMode) {
			helmArgs, err = appendCvmModeInstallArgs(helmArgs, installCvmMode)
			if err != nil {
				return err
			}
		}
		helmArgs = appendKataInstallArgs(helmArgs, installKata, installKataDebug)
		if installKataDebug {
			fmt.Fprintln(os.Stdout, "+ kata guest image: DEBUG variant — container logs/exec are host-readable; SNP launch measurement differs from the locked image")
		}
		helmArgs = appendSingleNodeInstallArgs(helmArgs, installSingleNode)
		if installImagePullSecret != "" {
			helmArgs = append(helmArgs, "--set-string", "imagePullSecret="+installImagePullSecret)
		}
		if installResolveDigests {
			helmArgs, err = appendResolvedDigestArgs(cmd.Context(), helmArgs, imageTag, components)
			if err != nil {
				return err
			}
		}
		if cmd.Flags().Changed("webhook-cert-fs-group") {
			helmArgs = append(helmArgs, "--set", fmt.Sprintf("webhook.certVolume.fsGroup=%d", installCertFSGroup))
		}
		if cmd.Flags().Changed("webhook-cert-key-mode") {
			helmArgs = append(helmArgs, "--set-string", "webhook.certVolume.keyMode="+installCertKeyMode)
		}
		if cmd.Flags().Changed("webhook-get-cert-renew-interval") {
			helmArgs = append(helmArgs, "--set-string", "webhook.getCert.renewInterval="+installGetCertRenewInterval.String())
		}
		if cmd.Flags().Changed("webhook-get-cert-run-as-user") {
			helmArgs = append(helmArgs, "--set", fmt.Sprintf("webhook.getCert.runAsUser=%d", installGetCertRunAsUser))
		}
		if cmd.Flags().Changed("webhook-get-cert-run-as-group") {
			helmArgs = append(helmArgs, "--set", fmt.Sprintf("webhook.getCert.runAsGroup=%d", installGetCertRunAsGroup))
		}
		if cmd.Flags().Changed("webhook-get-cert-run-as-non-root") {
			helmArgs = append(helmArgs, "--set", fmt.Sprintf("webhook.getCert.runAsNonRoot=%t", installGetCertRunAsNonRoot))
		}
		for _, vf := range installValues {
			helmArgs = append(helmArgs, "-f", vf)
		}
		if installWait {
			helmArgs = append(helmArgs, "--wait", "--timeout=5m")
		}

		// Fail fast on the default path if the CDS node is unlabelled, before
		// mutating the cluster. Skipped when -f is supplied: a custom values
		// file may disable image policy or change the selector, and the operator
		// owns node labels in that case. Also skipped under --single-node, which
		// clears the selector so no node needs the label.
		if len(installValues) == 0 && !installSingleNode {
			if err := preflightCDSNode(cmd.Context(), chartPath); err != nil {
				return err
			}
		}

		if installImagePullSecret != "" {
			if err := preflightImagePullSecret(cmd.Context(), installNamespace, installImagePullSecret); err != nil {
				return err
			}
		}

		// The install always ships pods that exceed the restricted pod-security
		// profile: nri-image-policy runs privileged unconditionally, ratls-mesh's
		// iptables init containers run as root with NET_ADMIN/NET_RAW, and
		// attestation-api needs SYS_RAWIO (baremetal/gke) or privileged (aks).
		// --kata adds kata-deploy on top. No supported shape fits restricted, so
		// the namespace is always labelled privileged (a CIS-hardened cluster, e.g.
		// RKE2 with profile: cis, would otherwise reject those pods at admission).
		if err := applyNamespace(cmd.Context(), installNamespace); err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "+ helm %s\n", strings.Join(helmArgs, " "))
		hc := exec.CommandContext(cmd.Context(), "helm", helmArgs...)
		hc.Stdout = os.Stdout
		hc.Stderr = os.Stderr
		if err := hc.Run(); err != nil {
			return fmt.Errorf("helm install failed: %w", err)
		}

		return nil
	},
}

// extractChart writes the embedded chart tree to a fresh tmpdir and returns
// its path. Caller must RemoveAll when done.
func extractChart() (string, error) {
	dir, err := os.MkdirTemp("", "c8s-chart-*")
	if err != nil {
		return "", err
	}
	if err := os.CopyFS(dir, helmchart.ChartFS); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// applyNamespace creates the install namespace before helm, labelled to allow
// privileged pods (the install's privileged components, see RunE). helm
// --create-namespace cannot set labels, so we always pre-apply.
func applyNamespace(ctx context.Context, namespace string) error {
	manifest, err := namespaceManifest(namespace)
	if err != nil {
		return fmt.Errorf("render namespace manifest: %w", err)
	}
	fmt.Fprintf(os.Stdout, "+ kubectl apply -f - # Namespace/%s (pod-security=privileged)\n", namespace)
	kc := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	kc.Stdin = bytes.NewReader(manifest)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl apply namespace %q: %w", namespace, err)
	}
	return nil
}

// namespaceManifest renders the release Namespace as JSON (valid kubectl apply
// input), labelled privileged at the enforce, warn, and audit modes so the
// install's privileged pods admit on a cluster whose default profile is
// stricter (e.g. CIS-hardened restricted).
func namespaceManifest(namespace string) ([]byte, error) {
	ns := corev1.Namespace{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce": "privileged",
				"pod-security.kubernetes.io/warn":    "privileged",
				"pod-security.kubernetes.io/audit":   "privileged",
			},
		},
	}
	return json.Marshal(ns)
}

// fallbackImageTag is installed whenever the build is not stamped with a
// release version. It is the branch every c8s component publishes; it is
// deliberately not "latest", which cds does not publish (so
// `crane digest ghcr.io/confidential-dot-ai/cds:latest` under --resolve-digests would
// abort with MANIFEST_UNKNOWN).
const fallbackImageTag = "main"

// releaseVersion matches a clean release tag (vMAJOR.MINOR.PATCH), the only
// version for which CI publishes a matching image tag. A `git describe`
// derivative (e.g. v1.2.3-5-gabc, a bare commit SHA, or empty) has no published
// image, so defaultInstallImageTag falls back to fallbackImageTag.
var releaseVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// defaultInstallImageTag picks the image tag for an install: the build version
// when it is a published release tag, otherwise fallbackImageTag.
func defaultInstallImageTag(buildVersion string) string {
	if releaseVersion.MatchString(buildVersion) {
		return buildVersion
	}
	return fallbackImageTag
}

func appendInstallCRDArgs(helmArgs []string, installCRDs bool) []string {
	if installCRDs {
		return helmArgs
	}
	return append(helmArgs, "--skip-crds", "--set", "statusMirror.enabled=false")
}

// appendDistroInstallArgs translates the detected host distro into the
// per-component values. Both targets are always set — each install shape uses
// exactly one of them (nri-image-policy on the host shape, kata-deploy under
// --kata) and both must bind the containerd config layout the host distro
// uses; the unused one is inert. No enum guard: the value comes from
// chooseDistro, and the chart re-validates anyway.
func appendDistroInstallArgs(helmArgs []string, distro string) []string {
	return append(helmArgs,
		"--set-string", "kata.distro="+distro,
		"--set-string", "nriImagePolicy.distro="+distro,
	)
}

// appendCvmModeInstallArgs translates --cvm-mode into the attestation-api
// values. The chart re-validates, so the allowed check is a fast typo guard
// before shelling to helm.
//
// cvm-mode selects which TEE device gets mounted (it does NOT vary the privilege
// level — all modes render privileged: true, since a hostPath device mount alone
// does not grant device-cgroup access):
//
//	baremetal, gke → native /dev/sev-guest
//	aks            → vTPM /dev/tpm0
//
// GKE is the reason a plain managed→vTPM mapping is wrong: GKE confidential VMs
// are a managed cloud but still expose the native /dev/sev-guest ioctl, not a
// vTPM. The chart's teeDevices default is the native shape; this only flips it
// to the vTPM for aks. Without it a `--cvm-mode aks` install would mount
// /dev/sev-guest (absent on AKS), and the attestation-api pod would fail the
// hostPath CharDevice check. Override individual teeDevices via -f for hosts
// that don't fit the pairing (e.g. a TDX host needs tdxGuest).
func appendCvmModeInstallArgs(helmArgs []string, cvmMode string) ([]string, error) {
	allowed := []string{"baremetal", "gke", "aks"}
	if !slices.Contains(allowed, cvmMode) {
		return nil, fmt.Errorf("--%s must be one of %s, got %q", flagCvmMode, strings.Join(allowed, ", "), cvmMode)
	}
	helmArgs = append(helmArgs, "--set-string", "attestationApi.cvmMode="+cvmMode)
	// aks → vTPM /dev/tpm0; baremetal and gke → native /dev/sev-guest.
	sevGuest, tpm := "true", "false"
	if cvmMode == "aks" {
		sevGuest, tpm = "false", "true"
	}
	return append(helmArgs,
		"--set", "attestationApi.teeDevices.sevGuest="+sevGuest,
		"--set", "attestationApi.teeDevices.tpm="+tpm,
	), nil
}

// validateKataDebugFlags rejects --debug without --kata: the flag selects the
// kata-guest-base debug image, which only exists under the kata stack, so a
// bare --debug is meaningless and almost certainly a mistaken expectation
// (e.g. hoping for verbose install output). Checked first in RunE, before
// anything touches the cluster.
func validateKataDebugFlags(kata, debug bool) error {
	if debug && !kata {
		return fmt.Errorf("--debug selects the kata-guest-base debug image, which only exists under --kata; add --kata or drop --debug")
	}
	return nil
}

// appendKataInstallArgs translates --kata into helm --set values. kata is
// enforcing — there is no kata-without-enforcement shape: the chart renders
// the runtime stack, the runtimeClass-injecting webhook behavior, and the
// ValidatingAdmissionPolicy together off kata.enabled.
//
// It also turns off the host-side ratls-mesh, attestation-api, and
// nri-image-policy: under kata every workload runs as a kata CVM, where their
// function is served by the in-guest counterparts baked into kata-guest-base
// (in-VM ratls routing, in-guest attestation-api on loopback, in-guest
// policy-monitor image admission). The chart fails the render if they are
// left enabled alongside kata.enabled (see validations.yaml).
//
// debug selects the kata-guest-base debug image variant (--debug; the chart
// derives the `<tag>-debug` artifact tag). RunE rejects --debug without
// --kata before args are built; everything here still keys on kata so a
// call-order change cannot emit a debug value for a non-kata install.
func appendKataInstallArgs(helmArgs []string, kata, debug bool) []string {
	if !kata {
		return helmArgs
	}
	helmArgs = append(helmArgs,
		"--set", "kata.enabled=true",
		"--set", "ratlsMesh.enabled=false",
		"--set", "attestationApi.enabled=false",
		"--set", "nriImagePolicy.enabled=false",
	)
	if debug {
		helmArgs = append(helmArgs, "--set", "kata.guestImage.debug=true")
	}
	return helmArgs
}

// preflightImagePullSecret reads the Secret --image-pull-secret names (absent
// is reported by checkImagePullSecret, not the kubectl error) and delegates to
// checkImagePullSecret. A kubectl failure other than NotFound aborts: the
// check cannot be made, and the states it guards fail late and opaquely if
// installed blind.
func preflightImagePullSecret(ctx context.Context, namespace, name string) error {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "secret", name, "-n", namespace, "-o", "json").Output()
	if err != nil {
		var ee *exec.ExitError
		// NotFound covers both a missing Secret and a not-yet-created release
		// namespace; either way the Secret is not in the cluster.
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "NotFound") {
			return checkImagePullSecret(nil, namespace, name)
		}
		if errors.As(err, &ee) {
			return fmt.Errorf("kubectl get secret %s -n %s: %w: %s", name, namespace, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return fmt.Errorf("kubectl get secret %s -n %s: %w", name, namespace, err)
	}
	var sec corev1.Secret
	if err := json.Unmarshal(out, &sec); err != nil {
		return fmt.Errorf("parse secret %s/%s: %w", namespace, name, err)
	}
	return checkImagePullSecret(&sec, namespace, name)
}

// checkImagePullSecret validates the Secret --image-pull-secret names
// (sec == nil means it is not in the cluster). The Secret must exist and be a
// registry-credential type: kubelet silently skips a missing pull secret and
// ignores non-registry Secret types, so both states would otherwise surface
// only as ImagePullBackOff after a successful-looking install.
func checkImagePullSecret(sec *corev1.Secret, namespace, name string) error {
	if sec == nil {
		return fmt.Errorf("--image-pull-secret %q: no such Secret in namespace %q. Create it first: kubectl create namespace %s; kubectl create secret docker-registry %s -n %s --docker-server=<registry> --docker-username=<user> --docker-password=<token>", name, namespace, namespace, name, namespace)
	}
	if sec.Type != corev1.SecretTypeDockerConfigJson && sec.Type != corev1.SecretTypeDockercfg {
		return fmt.Errorf("--image-pull-secret %q: Secret has type %q, want %s (or legacy %s) — kubelet ignores other Secret types for image pulls", name, sec.Type, corev1.SecretTypeDockerConfigJson, corev1.SecretTypeDockercfg)
	}
	return nil
}

// appendSingleNodeInstallArgs collapses the dedicated-CDS-node partition for a
// single-node / single-CVM cluster: an empty cds.node.selector makes every node
// CDS-eligible (one push-mode installer everywhere, no worker split), and the
// dedicated-node taint toleration is meaningless without it. helm renders =null
// as an empty value the chart reads as "no partition". --set wins over -f, so
// the flag is authoritative if both are supplied.
func appendSingleNodeInstallArgs(helmArgs []string, singleNode bool) []string {
	if !singleNode {
		return helmArgs
	}
	return append(helmArgs,
		"--set", "cds.node.selector=null",
		"--set", "cds.node.tolerations=null",
	)
}

// craneDigest resolves an image reference to its registry digest by shelling
// out to `crane digest <ref>`. crane handles registry auth (docker config),
// manifest lists, and the v2 protocol — reimplementing that in-process would
// pull a heavyweight registry client for one lookup. The returned value is a
// bare "sha256:<hex>".
func craneDigest(ctx context.Context, ref string) (string, error) {
	out, err := exec.CommandContext(ctx, "crane", "digest", ref).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("crane digest %q: %w: %s", ref, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("crane digest %q: %w", ref, err)
	}
	digest := strings.TrimSpace(string(out))
	if !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("crane digest %q returned unexpected value %q", ref, digest)
	}
	return digest, nil
}

// appendResolvedDigestArgs resolves each chart component's repo:tag to its
// registry digest (via crane) and appends the helm --set flags that pin it.
func appendResolvedDigestArgs(ctx context.Context, helmArgs []string, tag string, components []c8sComponent) ([]string, error) {
	if _, err := exec.LookPath("crane"); err != nil {
		return nil, fmt.Errorf("digest resolution needs the 'crane' CLI on PATH; install it or pass --resolve-digests=false and supply digests via -f: %w", err)
	}
	return buildDigestArgs(helmArgs, tag, components, func(ref string) (string, error) {
		digest, err := craneDigest(ctx, ref)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stdout, "+ resolved %s -> %s\n", ref, digest)
		return digest, nil
	})
}

// buildDigestArgs appends, for every component, the --set flags that pin both
// its repository and the digest resolved against that repository. Pinning the
// repository too means an operator's -f override of a repository cannot leave
// the chart deploying repoA@<digest-of-repoB>: helm gives --set strict
// precedence over -f, so the repository and digest move together. cds.image
// covers both the CDS Deployment and the NRI push-hook / allowlist-seed
// self-entry, which all read it. Any resolution failure aborts: a
// partially-pinned floor would let the render guard pass while the served
// allowlist pointed at the wrong digest. The resolver is injected so the arg
// assembly is testable without a registry.
func buildDigestArgs(helmArgs []string, tag string, components []c8sComponent, resolve func(ref string) (string, error)) ([]string, error) {
	for _, c := range components {
		repo := c.repository
		digest, err := resolve(repo + ":" + tag)
		if err != nil {
			return nil, err
		}
		helmArgs = append(helmArgs,
			"--set-string", c.valuePrefix+".repository="+repo,
			"--set-string", c.valuePrefix+".digest="+digest,
		)
	}
	// Resolving the component digests is exactly when you want them in the NRI
	// allowlist, so turn on derivation (off by default in the chart; the
	// resolve path enables it).
	helmArgs = append(helmArgs, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true")
	return helmArgs, nil
}

func init() {
	installCmd.Flags().StringVar(&installNamespace, "namespace", "c8s-system", "namespace to install into")
	installCmd.Flags().StringVar(&installRelease, "release", "c8s", "Helm release name")
	installCmd.Flags().StringSliceVarP(&installValues, "values", "f", nil, "values files (repeatable)")
	installCmd.Flags().BoolVar(&installWait, "wait", true, "wait for the release to become ready (helm --wait)")
	installCmd.Flags().BoolVar(&installCRDs, "install-crds", true, "install chart CRDs (false passes helm --skip-crds)")
	installCmd.Flags().Int64Var(&installCertFSGroup, "webhook-cert-fs-group", 65532, "fsGroup for injected certificate volume")
	installCmd.Flags().StringVar(&installCertKeyMode, "webhook-cert-key-mode", "0640", "octal mode for injected tls.key")
	installCmd.Flags().DurationVar(&installGetCertRenewInterval, "webhook-get-cert-renew-interval", 6*time.Hour, "renewal interval for injected workload certificates")
	installCmd.Flags().Int64Var(&installGetCertRunAsUser, "webhook-get-cert-run-as-user", 65532, "runAsUser for injected get-cert containers")
	installCmd.Flags().Int64Var(&installGetCertRunAsGroup, "webhook-get-cert-run-as-group", 65532, "runAsGroup for injected get-cert containers")
	installCmd.Flags().BoolVar(&installGetCertRunAsNonRoot, "webhook-get-cert-run-as-non-root", true, "set runAsNonRoot for injected get-cert containers")
	installCmd.Flags().BoolVar(&installSingleNode, "single-node", false, "single-node / single-CVM cluster: clear the dedicated-CDS-node selector and taint toleration so every node is CDS-eligible (no role=cds label or dedicated node needed). Sets cds.node.selector={} and cds.node.tolerations=[]")
	installCmd.Flags().StringVar(&installCvmMode, flagCvmMode, "baremetal", "CVM platform shape — selects the TEE device: baremetal or gke (native /dev/sev-guest) or aks (vTPM /dev/tpm0). All modes render a privileged attestation-api (a hostPath device mount alone does not grant device-cgroup access)")
	installCmd.Flags().BoolVar(&installKata, "kata", false, "install the Kata Containers runtime stack (kata-deploy DaemonSet + RuntimeClasses) and enforce it: workload pods are injected with kata RuntimeClasses and non-kata classes are rejected. Also disables the host-side ratls-mesh, attestation-api, and nri-image-policy — under kata their function runs inside the kata-guest-base VM image")
	installCmd.Flags().BoolVar(&installKataDebug, "debug", false, "use the kata-guest-base DEBUG image variant (tag <tag>-debug, kata.guestImage.debug=true): its baked guest policy allows host log/exec streams so 'kubectl logs' and 'kubectl exec' work on kata pods — container I/O becomes readable by the untrusted host and the SNP launch measurement differs from the locked image. Requires --kata; development only")
	installCmd.Flags().BoolVar(&installResolveDigests, "resolve-digests", true, "resolve each c8s component image tag to its registry digest (via crane), pin it, and add the resolved images to the NRI allowlist (enables deriveComponents). On by default; pass --resolve-digests=false when supplying digests via -f")
	installCmd.Flags().StringVar(&installImagePullSecret, "image-pull-secret", "", "name of an existing registry-credential Secret (kubernetes.io/dockerconfigjson) in the release namespace; the chart appends it to every component's imagePullSecrets, so all pods can pull private c8s images from first start. The Secret itself is never created or managed by the install — the install fails fast if it is missing or has the wrong type")
	rootCmd.AddCommand(installCmd)
}
