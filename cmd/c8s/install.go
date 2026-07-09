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

	installKata             bool
	installKataDebug        bool
	installCvmMode          string
	installHardwarePlatform string
	installSingleNode       bool
	installImagePullSecret  string
	installImageTag         string
	installOperatorKeys     string
	installForce            bool

	installEngine           string
	installEngineWorkloadID string
	installEngineNamespace  string

	installResolveDigests bool
)

// Flag names referenced in more than one place (registration plus a Changed()
// gate or an arg-builder call). Naming them once keeps the references from
// drifting.
const (
	flagCvmMode          = "cvm-mode"
	flagHardwarePlatform = "hardware-platform"
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

// operatorKeysPreflight enforces that installing without pinned operator keys is
// a deliberate choice. On the default path — no --operator-keys and no -f values
// file that could carry cds.operatorKeys — it requires --force, because the
// resulting CDS has allowlist writes disabled and nobody could add/remove/upload
// allowlist entries via `c8s allowlist`. When keys are supplied, or the operator
// is managing values via -f, it is a no-op (consistent with the other -f-gated
// preflights). It returns a warning to print when --force lets it pass.
func operatorKeysPreflight(operatorKeys string, valuesFiles []string, force bool) (warn string, err error) {
	if operatorKeys != "" || len(valuesFiles) > 0 {
		return "", nil
	}
	if !force {
		return "", fmt.Errorf("no operator keys provided: allowlist writes will be DISABLED — nobody can add/remove/upload allowlist entries via `c8s allowlist`. Re-run with --operator-keys <file> to enable writes, or --force to install with writes disabled anyway")
	}
	return "installing with allowlist writes DISABLED (no --operator-keys); `c8s allowlist` add/remove/upload will not work until you set cds.operatorKeys and reinstall", nil
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

// preflightTDXNodes fails fast when --hardware-platform=tdx but no node carries
// the confidential.ai/tdx=true label — the label the kata-qemu-tdx*
// RuntimeClass nodeSelectors expect (kata.tdxNodeSelector default). On the
// default --kata path the install applies it itself right before this check
// (autoLabelTEENodes, trusting --hardware-platform), so a failure there means
// no node matched the kata node selector at all; with -f, or without --kata
// (e.g. --cvm-mode=node), the operator owns the label. Without a labelled
// node, TDX pods would sit Pending until timeout with an opaque scheduler
// error.
//
// Runs regardless of -f: the label requirement is a fact about the cluster,
// not a values choice, and every TDX install needs it. Note the label says
// nothing about qgsd or its vsock bridge being up — quote generation failing
// on a labelled-but-unready host surfaces at attestation time, not here.
const tdxHostLabelKey = "confidential.ai/tdx"

func preflightTDXNodes(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes",
		"-l", tdxHostLabelKey+"=true", "-o", "name").Output()
	if err != nil {
		return fmt.Errorf("kubectl get nodes -l %s=true: %w", tdxHostLabelKey, err)
	}
	if strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf("--hardware-platform=tdx but no node is labelled %s=true. A default `c8s install --kata` labels every kata-targeted node automatically, so either no node matched the kata node selector, or this is a -f/non-kata install where labels are yours to manage. A TDX node also needs /dev/tdx_guest available, qgsd (Intel DCAP Quote Generation Service) running, and a socat unix→vsock bridge so kata's QGS-over-vsock path reaches qgsd. To label a host yourself:\n\n    kubectl label node <node> %s=true",
			tdxHostLabelKey, tdxHostLabelKey)
	}
	return nil
}

// preflightTEENodes fails fast (before the helm install) when a --kata
// install would schedule confidential pods that can never start: the
// platform's confidential RuntimeClasses select platform-labelled nodes
// (kata.snpNodeSelector / kata.tdxNodeSelector), and the chart-managed CDS
// and tls-lb both pin the platform's CPU class — with no labelled
// node the whole release sits Pending and `helm --wait` blocks for the full
// timeout before failing opaquely. It runs right after autoLabelTEENodes,
// which labels every kata-targeted node from --hardware-platform, so "no
// labelled node" means no node matched the kata node selector at all. (Why a
// wrong-TEE node cannot run these pods: docs/pitfalls.md "kata-qemu-snp on a
// non-SNP host is a QEMU crash-loop".)
//
// Like preflightCDSNode it reads the chart's default values, so it guards the
// default path only; an operator who customizes via -f owns node labels (the
// caller skips this when -f is supplied).
func preflightTEENodes(ctx context.Context, chartPath, hardwarePlatform string) error {
	out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
	if err != nil {
		return fmt.Errorf("helm show values %q: %w", chartPath, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return fmt.Errorf("parse chart values: %w", err)
	}

	selKey, otherPlatform := "snpNodeSelector", "tdx"
	if hardwarePlatform == "tdx" {
		selKey, otherPlatform = "tdxNodeSelector", "sev-snp"
	}
	sel, _ := nestedMap(tree, "kata", selKey)
	selector, ok := labelSelector(sel)
	if !ok {
		// Empty/cleared selector means unrestricted confidential scheduling —
		// nothing to preflight (and the chart renders no scheduling block).
		return nil
	}

	labeled, err := exec.CommandContext(ctx, "kubectl", "get", "nodes",
		"-l", selector, "-o", "name").Output()
	if err != nil {
		return fmt.Errorf("kubectl get nodes -l %s: %w", selector, err)
	}
	if strings.TrimSpace(string(labeled)) == "" {
		return fmt.Errorf("no node is labelled %s: the install labels every kata-targeted node from --hardware-platform=%s, so no node matched the kata node selector — without a labelled node no confidential pod can schedule, including the chart's own CDS and tls-lb. Check the cluster has schedulable Linux nodes; on a %s cluster pass --hardware-platform=%s instead. To label a host yourself: kubectl label node <node> %s", selector, hardwarePlatform, otherPlatform, otherPlatform, strings.ReplaceAll(selector, ",", " "))
	}
	return nil
}

// labelSelector flattens a decoded values map into a kubectl -l selector
// ("k=v,k2=v2", keys sorted for determinism). ok=false for an empty map or a
// non-string value — an empty kata.snpNodeSelector is the documented opt-out,
// and a malformed one is the chart's to reject, not the preflight's.
func labelSelector(sel map[string]any) (string, bool) {
	if len(sel) == 0 {
		return "", false
	}
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		v, ok := sel[k].(string)
		if !ok {
			return "", false
		}
		pairs = append(pairs, k+"="+v)
	}
	return strings.Join(pairs, ","), true
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
  - the ratls-mesh, nri-image-policy, and tls-lb components

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
		if warn, err := operatorKeysPreflight(installOperatorKeys, installValues, installForce); err != nil {
			return err
		} else if warn != "" {
			fmt.Fprintln(os.Stderr, "warning: "+warn)
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
		imageTag := resolveImageTag()
		// kata-deploy and nri-image-policy must bind the host's containerd
		// layout in every install mode, so the distro is detected from the
		// cluster's kubelet versions and plumbed; letting the chart default
		// (k8s) stand would silently mis-target RKE2. With -f nothing is
		// plumbed — helm gives --set precedence over -f, and the values-file
		// owner owns the layout (kata.distro / nriImagePolicy.distro there if
		// the chart default doesn't fit). buildValueArgs skips the distro when
		// it is empty.
		distro := ""
		if len(installValues) == 0 {
			distro, err = detectDistro(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "+ detected host distro: %s\n", distro)
		}
		if installKataDebug {
			fmt.Fprintln(os.Stdout, "+ kata guest image: DEBUG variant — container logs/exec are host-readable; SNP launch measurement differs from the locked image")
		}
		// The computed values are shared with `c8s render-values` via
		// buildValueArgs, then written to one values file rather than passed as a
		// pile of --set flags. The contract that the CLI's flag-derived values
		// override an operator's -f is preserved by ordering: the computed file
		// is the LAST -f, so it wins on the keys it sets (matching the previous
		// "--set beats -f" precedence) while the operator's files supply the rest.
		setArgs, err := buildValueArgs(cmd.Context(), cmd, components, imageTag, distro, appendResolvedDigestArgs)
		if err != nil {
			return err
		}
		computedValues, err := writeComputedValues(setArgs)
		if err != nil {
			return err
		}
		defer os.Remove(computedValues)
		helmArgs := buildInstallHelmArgs(chartPath, computedValues, installValues, installCRDs, installWait, installKata)

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

		// Digest resolution off + default values: verify at least the
		// operator image exists (see preflightOperatorImage); a -f owner may
		// pin different repositories or digests.
		if !installResolveDigests && len(installValues) == 0 {
			if err := preflightOperatorImage(cmd.Context(), components, imageTag); err != nil {
				return err
			}
		}

		if installImagePullSecret != "" {
			if err := preflightImagePullSecret(cmd.Context(), installNamespace, installImagePullSecret); err != nil {
				return err
			}
		}

		// --kata: label every kata-targeted node for the declared
		// --hardware-platform (refusing if the other platform's label is
		// still present — a platform switch must be the operator's explicit
		// act), then fail fast if the platform's confidential pods still
		// have nowhere to schedule. Declarative — the flag is trusted, no
		// hardware probe (see autoLabelTEENodes). Runs after the read-only
		// preflights above — it mutates the cluster (node labels). Skipped
		// with -f, whose owner owns node labels; NOT skipped under
		// --single-node — even a one-node cluster needs its platform label
		// for confidential pods to schedule.
		kataDefaultPath := installKata && len(installValues) == 0
		if kataDefaultPath {
			if err := autoLabelTEENodes(cmd.Context(), chartPath, installHardwarePlatform); err != nil {
				return err
			}
			if err := preflightTEENodes(cmd.Context(), chartPath, installHardwarePlatform); err != nil {
				return err
			}
		}

		// Fail fast when --hardware-platform=tdx but no node carries the TDX
		// label. Under --kata the TDX RuntimeClasses have a nodeSelector on
		// it; under --cvm-mode=node the attestationApi DaemonSet needs at
		// least one TDX-capable node. Checks a fact about the cluster, not
		// the values, so it runs with -f too — but the default --kata path
		// above already checked the chart's actual tdxNodeSelector (which
		// may be customized or cleared), so skip the fixed-key check there.
		if installHardwarePlatform == "tdx" && installCvmMode != "aks" && !kataDefaultPath {
			if err := preflightTDXNodes(cmd.Context()); err != nil {
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

// buildInstallHelmArgs assembles the `helm upgrade --install` argv. Ordering is
// load-bearing: the operator's -f files come first and the computed values file
// LAST, so the CLI's computed values win on the keys they set (helm merges -f
// last-wins) — matching the prior "--set beats -f" precedence. --skip-crds is a
// helm invocation flag (not a value), emitted iff CRDs are skipped. A --kata
// install waits 10m instead of 5m: on a node without a prior kata install,
// kata-deploy downloads the multi-GB kata-static payload inside the --wait
// window, and 5m routinely left the release `failed` with the cluster
// converging fine underneath.
func buildInstallHelmArgs(chartPath, computedValues string, valueFiles []string, installCRDs, wait, kata bool) []string {
	helmArgs := []string{
		"upgrade", "--install", installRelease, chartPath,
		"--namespace", installNamespace,
	}
	if !installCRDs {
		helmArgs = append(helmArgs, "--skip-crds")
	}
	for _, vf := range valueFiles {
		helmArgs = append(helmArgs, "-f", vf)
	}
	helmArgs = append(helmArgs, "-f", computedValues)
	if wait {
		timeout := "--timeout=5m"
		if kata {
			timeout = "--timeout=10m"
		}
		helmArgs = append(helmArgs, "--wait", timeout)
	}
	return helmArgs
}

// writeComputedValues turns the buildValueArgs --set/--set-string pairs into a
// values.yaml in a tmpfile and returns its path (caller removes it). install
// passes it as a -f instead of shelling a pile of --set flags; the conversion
// is the same one `c8s render-values` uses for its output.
func writeComputedValues(setArgs []string) (string, error) {
	values, err := valueArgsToTree(setArgs)
	if err != nil {
		return "", err
	}
	out, err := yaml.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("marshal computed values: %w", err)
	}
	// Echo the computed values so the install is still legible now that they are
	// a -f file rather than inline --set flags (stderr; helm's own output stays
	// on stdout).
	fmt.Fprintf(os.Stderr, "+ computed values:\n%s", out)
	f, err := os.CreateTemp("", "c8s-install-values-*.yaml")
	if err != nil {
		return "", fmt.Errorf("create computed values file: %w", err)
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("write computed values: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("close computed values: %w", err)
	}
	return f.Name(), nil
}

// resolveImageTag returns the tag to resolve component images at: the explicit
// --image-tag when set, otherwise the build-version default. The CLI and its
// component images publish in lockstep, so the default is correct for a normal
// install; --image-tag overrides it to pin a specific branch/tag/release —
// e.g. a fleet promoting `main` from a release-stamped CLI build.
func resolveImageTag() string {
	if installImageTag != "" {
		return installImageTag
	}
	return defaultInstallImageTag(version.Version)
}

// appendInstallCRDArgs emits the value that disables the CRD-dependent
// status-mirror when CRDs are skipped. It returns value args only — the helm
// `--skip-crds` invocation flag is added at the helm call site (install), not
// here, since these args are converted to a values tree and `--skip-crds` is
// not a value.
func appendInstallCRDArgs(setArgs []string, installCRDs bool) []string {
	if installCRDs {
		return setArgs
	}
	return append(setArgs, "--set", "statusMirror.enabled=false")
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
//	baremetal, node, gke → native /dev/sev-guest (SEV-SNP) by default, or
//	                       /dev/tdx-guest (Intel TDX) if --hardware-platform tdx
//	aks                  → vTPM /dev/tpm0
//
// node and gke are distinct deployment targets that happen to share the
// native-TEE-device wiring (they are NOT aliases):
//
//	node → generalized node-as-CVM: our own nodes (bare-metal TDX/SNP,
//	       self-managed) are themselves confidential VMs. Pods run as ordinary
//	       processes attested via the node's own quote. Cloud-agnostic.
//	gke  → GKE specifically: Google's managed confidential VMs.
//
// GKE is the reason a plain managed→vTPM mapping is wrong: GKE confidential VMs
// are a managed cloud but still expose the native /dev/sev-guest ioctl, not a
// vTPM. The chart's teeDevices default is the SNP shape; this flips it as
// needed per (mode, platform). Without it a `--cvm-mode aks` install would
// mount /dev/sev-guest (absent on AKS), and a bare-metal TDX host would
// similarly mount the wrong device — the attestation-api pod would fail the
// hostPath CharDevice check.
//
// `--cvm-mode` (deployment shape) and `--hardware-platform` (CPU TEE) are
// ORTHOGONAL axes. baremetal/gke pair with either SEV-SNP
// (--hardware-platform sev-snp, default) or Intel TDX (--hardware-platform
// tdx). aks uses its own vTPM path regardless, and combining `--cvm-mode aks`
// with `--hardware-platform tdx` is refused (AKS doesn't expose
// /dev/tdx-guest to guest workloads).
//
// Mixed-hardware inside a single cluster (some SNP hosts, some TDX hosts) is
// out of scope for now — a cluster is one hardware platform. Mixed support
// would want the attestation-api DaemonSet split per-platform with per-node
// label selectors, and ratlsmesh's `--platform` similarly per-node.
// Follow-up work.
//
// aks also opts the pod-injector MutatingWebhookConfiguration out of AKS's
// "admissionsenforcer" controller (annotation admissions.enforcer/disabled),
// which otherwise rewrites the webhook namespaceSelector and makes every helm
// re-apply conflict. That is rendered chart-side off attestationApi.cvmMode (so
// GitOps/HelmRelease installs get it too), not emitted as a --set here; see
// internal/helmchart/c8s/templates/webhook.yaml.
func appendCvmModeInstallArgs(helmArgs []string, cvmMode, hardwarePlatform string) ([]string, error) {
	allowedModes := []string{"baremetal", "node", "gke", "aks"}
	if !slices.Contains(allowedModes, cvmMode) {
		return nil, fmt.Errorf("--%s must be one of %s, got %q", flagCvmMode, strings.Join(allowedModes, ", "), cvmMode)
	}
	allowedPlatforms := []string{"sev-snp", "tdx"}
	if !slices.Contains(allowedPlatforms, hardwarePlatform) {
		return nil, fmt.Errorf("--%s must be one of %s, got %q", flagHardwarePlatform, strings.Join(allowedPlatforms, ", "), hardwarePlatform)
	}
	if cvmMode == "aks" && hardwarePlatform == "tdx" {
		return nil, fmt.Errorf("--%s=aks is Azure vTPM-backed SEV-SNP; combining with --%s=tdx is not supported (AKS does not expose /dev/tdx-guest to guest workloads)", flagCvmMode, flagHardwarePlatform)
	}
	helmArgs = append(helmArgs, "--set-string", "attestationApi.cvmMode="+cvmMode)
	// aks: vTPM regardless of --hardware-platform (validated above; only
	// --hardware-platform sev-snp reaches here)
	// baremetal/gke + --hardware-platform sev-snp: native /dev/sev-guest
	// baremetal/gke + --hardware-platform tdx:     native /dev/tdx-guest
	sevGuest, tdxGuest, tpm := "false", "false", "false"
	switch {
	case cvmMode == "aks":
		tpm = "true"
	case hardwarePlatform == "tdx":
		tdxGuest = "true"
	default:
		sevGuest = "true"
	}
	helmArgs = append(helmArgs,
		"--set", "attestationApi.teeDevices.sevGuest="+sevGuest,
		"--set", "attestationApi.teeDevices.tdxGuest="+tdxGuest,
		"--set", "attestationApi.teeDevices.tpm="+tpm,
	)
	// Propagate the CPU TEE to every component that names its RA-TLS platform.
	// These default to SNP in the chart; on a TDX cluster CDS (which self-warms
	// its serving cert via the attestation-api and is non-privileged, so it
	// cannot probe /dev/tdx_guest to auto-detect) and the ratls-mesh must be
	// told `tdx` explicitly, or CDS parses the attestation-api's TDX quote as an
	// SNP report and crash-loops ("evidence contains neither attestation_report
	// nor hcl_report"). aks stays on the SNP vTPM path. cds.ratlsPlatform uses
	// `snp`/`tdx`; ratlsMesh.platform uses `sev-snp`/`tdx`.
	if cvmMode != "aks" && hardwarePlatform == "tdx" {
		helmArgs = append(helmArgs,
			"--set-string", "cds.ratlsPlatform=tdx",
			"--set-string", "ratlsMesh.platform=tdx",
		)
	}
	return helmArgs, nil
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
// derives the `<tag>-debug` artifact tag). The confidential-GPU stack (runtime
// class, shim, GPU image puller, sandbox device plugin) ships with every kata
// install — it renders off kata.enabled, so there is no GPU flag here. RunE
// rejects --debug without --kata before args are built; everything here still
// keys on kata so a call-order change cannot emit a debug value for a non-kata
// install.
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

// preflightOperatorImage verifies the operator image exists in the registry
// before installing, for the path where digest resolution is off
// (--resolve-digests=false). With resolution on, appendResolvedDigestArgs
// already fails fast for every component; without it a missing tag surfaces
// only as ImagePullBackOff after a successful-looking install — and the
// tempting fallback (an older tag like :main) is worse: an operator that
// predates the chart's webhook features silently mis-injects
// (docs/pitfalls.md). The operator is the one component checked: this path
// deliberately opted out of full resolution, and the operator is the image
// whose chart coupling bites hardest. Best-effort beyond that: crane absent
// or an auth/network failure warns and continues; only a confirmed missing
// tag aborts.
func preflightOperatorImage(ctx context.Context, components []c8sComponent, tag string) error {
	// The operator's valuePath in c8sComponents is the top-level "image".
	var repo string
	for _, c := range components {
		if c.valuePrefix == "image" {
			repo = c.repository
			break
		}
	}
	if repo == "" {
		return nil
	}
	if _, err := exec.LookPath("crane"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot verify operator image %s:%s exists (crane not on PATH); a missing tag surfaces only as ImagePullBackOff after install\n", repo, tag)
		return nil
	}
	if _, err := craneDigest(ctx, repo+":"+tag); err != nil {
		if isImageNotFound(err) {
			return fmt.Errorf("operator image %s:%s is not published — %s: %w", repo, tag, tagCouplingHint(repo, tag), err)
		}
		fmt.Fprintf(os.Stderr, "warning: could not verify operator image %s:%s exists (%v); continuing\n", repo, tag, err)
	}
	return nil
}

// appendSingleNodeInstallArgs collapses the dedicated-CDS-node partition for a
// single-node / single-CVM cluster: an empty cds.node.selector makes every node
// CDS-eligible (worker/pull installer everywhere, no split; the node pulls from
// its co-hosted CDS), and the dedicated-node taint toleration is meaningless
// without it. helm renders =null as an empty value the chart reads as "no
// partition". --set wins over -f, so the flag is authoritative if both are supplied.
func appendSingleNodeInstallArgs(helmArgs []string, singleNode bool) []string {
	if !singleNode {
		return helmArgs
	}
	return append(helmArgs,
		"--set", "cds.node.selector=null",
		"--set", "cds.node.tolerations=null",
	)
}

// appendEngineInstallArgs emits the engine-preset values that derive tls-lb's
// mesh-wrapped upstream. Empty values are not plumbed so an operator's -f (or
// the chart's no-catch-all install-then-attach state) stands. The chart
// validates the combinations (engine_missing_workload_id, unknown_engine, ...),
// so no CLI-side checks here.
func appendEngineInstallArgs(setArgs []string, engine, workloadID, namespace string) []string {
	if engine != "" {
		setArgs = append(setArgs, "--set-string", "engine.name="+engine)
	}
	if workloadID != "" {
		setArgs = append(setArgs, "--set-string", "engine.workloadId="+workloadID)
	}
	if namespace != "" {
		setArgs = append(setArgs, "--set-string", "engine.namespace="+namespace)
	}
	return setArgs
}

// isImageNotFound reports whether a resolve error means the reference does
// not exist in the registry (as opposed to auth/network trouble). crane
// surfaces the registry's OCI error codes verbatim: MANIFEST_UNKNOWN for a
// missing tag, NAME_UNKNOWN for a missing repository. Matching them lets the
// callers attach the tag-coupling guidance only when the tag is genuinely
// absent — a 401 or a DNS failure gets the raw error instead.
func isImageNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "MANIFEST_UNKNOWN") || strings.Contains(msg, "NAME_UNKNOWN")
}

// tagCouplingHint explains a missing component image in terms of the c8s
// publish model, so the operator lands on the right knob instead of retrying
// tags. The c8s component images (operator, cds, …) publish in lockstep
// (docker.yml) and the chart+operator ship as a unit; a tag that exists only
// for some other artifact — e.g. a kata-guest-base guest-image tag like
// branch-<name> — is not an install tag, and falling back to a mismatched
// component tag is worse than failing (an operator predating the chart's
// webhook features silently mis-injects; docs/pitfalls.md).
func tagCouplingHint(repo, tag string) string {
	return fmt.Sprintf("every c8s component image must be published at the install tag (they publish in lockstep; a mismatched older operator would silently lack webhook features the chart expects). If %q is a kata-guest-base guest-image tag, that is a separate axis: keep --image-tag on a published component tag and set kata.guestImage.tag=%s via -f instead. Verify with: crane ls %s", tag, tag, repo)
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
		// Progress to stderr: render-values writes the values bundle to stdout,
		// so stdout must stay clean. Install's stdout is diagnostic too.
		fmt.Fprintf(os.Stderr, "+ resolved %s -> %s\n", ref, digest)
		return digest, nil
	})
}

// buildDigestArgs appends, for every component, the --set flags that pin both
// its repository and the digest resolved against that repository. Pinning the
// repository too means an operator's -f override of a repository cannot leave
// the chart deploying repoA@<digest-of-repoB>: helm gives --set strict
// precedence over -f, so the repository and digest move together. cds.image
// covers both the CDS Deployment and the allowlist-seed / floor self-entry,
// which all read it. Any resolution failure aborts: a
// partially-pinned floor would let the render guard pass while the served
// allowlist pointed at the wrong digest. The resolver is injected so the arg
// assembly is testable without a registry.
func buildDigestArgs(helmArgs []string, tag string, components []c8sComponent, resolve func(ref string) (string, error)) ([]string, error) {
	for _, c := range components {
		repo := c.repository
		digest, err := resolve(repo + ":" + tag)
		if err != nil {
			if isImageNotFound(err) {
				return nil, fmt.Errorf("component %s: image %s:%s is not published — %s: %w", c.valuePrefix, repo, tag, tagCouplingHint(repo, tag), err)
			}
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
	installCmd.Flags().StringVar(&installEngine, "engine", "", "inference engine preset deriving tls-lb's upstream (chart engine.name): vllm or sglang. Requires --engine-workload-id. Without this or a verified-https tlsLb.upstream, tls-lb renders no catch-all route until one is attached")
	installCmd.Flags().StringVar(&installEngineWorkloadID, "engine-workload-id", "", "confidential.ai/cw id of the engine workload (chart engine.workloadId); with --engine, derives the mesh-wrapped upstream c8s-<id>.<ns>.svc.cluster.local:<port>")
	installCmd.Flags().StringVar(&installEngineNamespace, "engine-namespace", "", "namespace the engine workload runs in (chart engine.namespace); empty = release namespace")
	installCmd.Flags().StringVar(&installCvmMode, flagCvmMode, "baremetal", "CVM deployment shape (orthogonal to --hardware-platform): baremetal, or node (generalized node-as-CVM: our own TDX/SNP nodes are themselves confidential VMs, pods run as ordinary processes), or gke (GKE managed confidential VMs), or aks (vTPM /dev/tpm0). All modes render a privileged attestation-api (a hostPath device mount alone does not grant device-cgroup access)")
	installCmd.Flags().StringVar(&installHardwarePlatform, flagHardwarePlatform, "sev-snp", "CPU-level TEE hardware (orthogonal to --cvm-mode): sev-snp (default, /dev/sev-guest) or tdx (Intel TDX, /dev/tdx-guest). Ignored when --cvm-mode=aks (Azure vTPM path); combining --cvm-mode=aks with --hardware-platform=tdx is refused")
	installCmd.Flags().BoolVar(&installKata, "kata", false, "install and enforce the Kata Containers runtime stack: every workload pod runs as a confidential VM (kata RuntimeClass injected; non-kata classes rejected), including NVIDIA GPU pods. Labels every kata node for the declared --hardware-platform (clearing the other platform's label), failing fast when no node qualifies")
	installCmd.Flags().BoolVar(&installKataDebug, "debug", false, "use the kata-guest-base DEBUG guest variant (<tag>-debug): kubectl logs/exec work on kata pods, but container I/O becomes readable by the untrusted host and the launch measurement differs from the locked image. Requires --kata; development only")
	installCmd.Flags().BoolVar(&installResolveDigests, "resolve-digests", true, "resolve each c8s component image tag to its registry digest (via crane), pin it, and add the resolved images to the NRI allowlist (enables deriveComponents). On by default; pass --resolve-digests=false when supplying digests via -f")
	installCmd.Flags().StringVar(&installImagePullSecret, "image-pull-secret", "", "name of an existing registry-credential Secret (kubernetes.io/dockerconfigjson) in the release namespace; the chart appends it to every component's imagePullSecrets, so all pods can pull private c8s images from first start. The Secret itself is never created or managed by the install — the install fails fast if it is missing or has the wrong type")
	installCmd.Flags().StringVar(&installImageTag, "image-tag", "", "component image tag to resolve digests at (default: the CLI build version, or 'main' for an unstamped build). Override to pin a specific branch/tag/release")
	installCmd.Flags().StringVar(&installOperatorKeys, "operator-keys", "", "path to a PEM bundle of operator EC public keys that authorize `c8s allowlist` writes; sets cds.operatorKeys. Without it, allowlist writes are disabled (reads still served). See the README \"Operator allowlist credentials\"")
	installCmd.Flags().BoolVar(&installForce, "force", false, "proceed past guarded prompts — currently: install without --operator-keys (allowlist writes disabled)")
	rootCmd.AddCommand(installCmd)
}
