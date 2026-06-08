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

	"github.com/lunal-dev/c8s/internal/helmchart"
	"github.com/lunal-dev/c8s/internal/version"
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

	installKata        bool
	installKataEnforce bool
	installDistro      string
	installCvmMode     string

	installResolveDigests bool
)

// Flag names referenced in more than one place (registration plus a Changed()
// gate or an arg-builder call). Naming them once keeps the references from
// drifting.
const (
	flagDistro  = "distro"
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

On RKE2 (--distro rke2) the kata-deploy and nri-image-policy DaemonSets carry
a containerd-prep initContainer that wires up the drop-in import; no node
preparation is required beyond a running cluster.

By default each component image tag is resolved to its registry digest (via the
'crane' CLI) and pinned, including the CDS digest the image-policy floor and
render guard require, and nriImagePolicy.bootstrapWhitelist.deriveComponents is
enabled so the resolved images are added to the NRI allowlist. This makes a
plain install satisfy the floor with no hand-written values. Pass
--resolve-digests=false when you supply the digests yourself via -f; the
render guards then require those values.

Requires the 'helm' and 'kubectl' CLIs to be on PATH, and 'crane' unless
--resolve-digests=false.`,
	RunE: func(cmd *cobra.Command, args []string) error {
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
		helmArgs, err = appendDistroInstallArgs(helmArgs, installDistro)
		if err != nil {
			return err
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
		helmArgs = appendKataInstallArgs(helmArgs, installKata, installKataEnforce)
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
		// owns node labels in that case.
		if len(installValues) == 0 {
			if err := preflightCDSNode(cmd.Context(), chartPath); err != nil {
				return err
			}
		}

		// The install always ships pods that exceed the restricted pod-security
		// profile: nri-image-policy runs privileged unconditionally, ratls-mesh's
		// iptables init containers run as root with NET_ADMIN/NET_RAW, and
		// attestation-api needs SYS_RAWIO (baremetal) or privileged (managed).
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
// `crane digest ghcr.io/lunal-dev/cds:latest` under --resolve-digests would
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

// appendEnumSetArg validates value against allowed, then appends a
// --set-string <path>=<value> for each path. Used by the enum install flags
// (--distro, --cvm-mode) so they share one validate-then-set shape. The chart
// re-validates, so the allowed check is a fast typo guard before shelling to
// helm; flag names the offending flag in the error.
func appendEnumSetArg(helmArgs []string, flag, value string, allowed, paths []string) ([]string, error) {
	if !slices.Contains(allowed, value) {
		return nil, fmt.Errorf("--%s must be one of %s, got %q", flag, strings.Join(allowed, ", "), value)
	}
	for _, path := range paths {
		helmArgs = append(helmArgs, "--set-string", path+"="+value)
	}
	return helmArgs, nil
}

// appendDistroInstallArgs translates --distro into the per-component host-distro
// values. It always applies: nri-image-policy installs regardless of --kata,
// and both it and kata-deploy must bind the containerd config layout the host
// distro uses.
func appendDistroInstallArgs(helmArgs []string, distro string) ([]string, error) {
	return appendEnumSetArg(helmArgs, flagDistro, distro,
		[]string{"k8s", "rke2"},
		[]string{"kata.distro", "nriImagePolicy.distro"})
}

// appendCvmModeInstallArgs translates --cvm-mode into the attestation-api
// value. managed renders a privileged attestation-api for managed-cloud
// CVMs that gate TEE device access below the device/capability layer; baremetal
// keeps the least-privilege securityContext.
func appendCvmModeInstallArgs(helmArgs []string, cvmMode string) ([]string, error) {
	return appendEnumSetArg(helmArgs, flagCvmMode, cvmMode,
		[]string{"baremetal", "managed"},
		[]string{"attestationApi.cvmMode"})
}

// appendKataInstallArgs translates the --kata / --kata-enforce flags into helm
// --set values. --kata-enforce implies --kata: enforcement is meaningless
// without the kata stack it injects and validates.
func appendKataInstallArgs(helmArgs []string, kata, enforce bool) []string {
	if !kata && !enforce {
		return helmArgs
	}
	helmArgs = append(helmArgs, "--set", "kata.enabled=true")
	if enforce {
		helmArgs = append(helmArgs, "--set", "kata.enforce.enabled=true")
	}
	return helmArgs
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
// covers both the CDS Deployment and the NRI push-hook / whitelist-seed
// self-entry, which all read it. Any resolution failure aborts: a
// partially-pinned floor would let the render guard pass while the served
// whitelist pointed at the wrong digest. The resolver is injected so the arg
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
	helmArgs = append(helmArgs, "--set", "nriImagePolicy.bootstrapWhitelist.deriveComponents=true")
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
	installCmd.Flags().StringVar(&installDistro, flagDistro, "k8s", "host Kubernetes distro: k8s (vanilla/kubeadm) or rke2 — selects containerd config paths for kata and nri-image-policy")
	installCmd.Flags().StringVar(&installCvmMode, flagCvmMode, "baremetal", "CVM platform shape: baremetal (least-privilege device access) or managed (privileged attestation-service for managed-cloud CVMs that gate TEE device access)")
	installCmd.Flags().BoolVar(&installKata, "kata", false, "install the Kata Containers runtime stack (kata-deploy DaemonSet + RuntimeClasses)")
	installCmd.Flags().BoolVar(&installKataEnforce, "kata-enforce", false, "enable kata enforcement: inject runtimeClasses into workload pods and reject non-kata RuntimeClasses (implies --kata)")
	installCmd.Flags().BoolVar(&installResolveDigests, "resolve-digests", true, "resolve each c8s component image tag to its registry digest (via crane), pin it, and add the resolved images to the NRI allowlist (enables deriveComponents). On by default; pass --resolve-digests=false when supplying digests via -f")
	rootCmd.AddCommand(installCmd)
}
