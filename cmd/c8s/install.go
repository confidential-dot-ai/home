//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
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
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the c8s operator, CRDs, attestation-service, and component charts via Helm",
	Long: `Extracts the bundled c8s Helm chart and runs
'helm upgrade --install' against the current kubeconfig context. Deploys:

  - the install namespace (labeled pod-security=privileged when --kata is set)
  - the c8s Deployment + Service (admission webhook + status-mirror controllers)
  - the ConfidentialWorkload CRD
  - the mutating admission webhook configuration
  - the attestation-service DaemonSet (per-node /attest + /verify)
  - chart-managed Assam and cert-issuer
  - vendored component charts from lunal-dev/c8s-charts

On RKE2 (--distro rke2) the kata-deploy and nri-image-policy DaemonSets carry
a containerd-prep initContainer that wires up the drop-in import; no node
preparation is required beyond a running cluster.

Requires the 'helm' and 'kubectl' CLIs to be on PATH.`,
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
		imageTag := defaultInstallImageTag(version.Version)
		helmArgs := []string{
			"upgrade", "--install", installRelease, chartPath,
			"--namespace", installNamespace,
			// Chart has no default image tags; chart images are released
			// in lockstep with the CLI, so pass the CLI's build version.
			// Unstamped local builds report "dev"; use latest for that
			// bootstrap path because CI does not publish a dev tag.
			"--set", "image.tag=" + imageTag,
			"--set", "attestationService.image.tag=" + imageTag,
			"--set", "assam.image.tag=" + imageTag,
			"--set", "certIssuer.image.tag=" + imageTag,
			"--set", "ratls-mesh.image.tag=" + imageTag,
			"--set", "nri-image-policy.image.tag=" + imageTag,
			"--set", "tee-proxy.image.tag=" + imageTag,
		}
		helmArgs = appendInstallCRDArgs(helmArgs, installCRDs)
		helmArgs, err = appendDistroInstallArgs(helmArgs, installDistro)
		if err != nil {
			return err
		}
		helmArgs = appendKataInstallArgs(helmArgs, installKata, installKataEnforce)
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

		// Only the kata stack ships privileged pods (kata-deploy DaemonSet);
		// without --kata, the c8s-system namespace can run under the default
		// pod-security baseline.
		privileged := installKata || installKataEnforce
		if err := applyNamespace(cmd.Context(), installNamespace, privileged); err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "+ helm %s\n", strings.Join(helmArgs, " "))
		hc := exec.CommandContext(cmd.Context(), "helm", helmArgs...)
		hc.Stdout = os.Stdout
		hc.Stderr = os.Stderr
		if err := hc.Run(); err != nil {
			return fmt.Errorf("helm install failed: %w", err)
		}

		fmt.Fprintln(os.Stdout)
		fmt.Fprint(os.Stdout, installNextSteps)
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

// applyNamespace creates the install namespace before helm. When privileged
// is true the namespace is labeled to allow privileged pods (kata-deploy);
// otherwise it is created without pod-security overrides. helm
// --create-namespace cannot set labels, so we always pre-apply.
func applyNamespace(ctx context.Context, namespace string, privileged bool) error {
	manifest, err := namespaceManifest(namespace, privileged)
	if err != nil {
		return fmt.Errorf("render namespace manifest: %w", err)
	}
	psa := "baseline"
	if privileged {
		psa = "privileged"
	}
	fmt.Fprintf(os.Stdout, "+ kubectl apply -f - # Namespace/%s (pod-security=%s)\n", namespace, psa)
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
// input). When privileged is true it sets pod-security labels at the enforce,
// warn, and audit modes; otherwise the namespace inherits the cluster default.
func namespaceManifest(namespace string, privileged bool) ([]byte, error) {
	ns := corev1.Namespace{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	if privileged {
		ns.Labels = map[string]string{
			"pod-security.kubernetes.io/enforce": "privileged",
			"pod-security.kubernetes.io/warn":    "privileged",
			"pod-security.kubernetes.io/audit":   "privileged",
		}
	}
	return json.Marshal(ns)
}

func defaultInstallImageTag(buildVersion string) string {
	if buildVersion == "" || buildVersion == "dev" {
		return "latest"
	}
	return buildVersion
}

func appendInstallCRDArgs(helmArgs []string, installCRDs bool) []string {
	if installCRDs {
		return helmArgs
	}
	return append(helmArgs, "--skip-crds", "--set", "statusMirror.enabled=false")
}

// appendDistroInstallArgs validates --distro and translates it into the
// per-component host-distro values. It always applies: nri-image-policy
// installs regardless of --kata, and both it and kata-deploy must bind the
// containerd config layout the host distro uses.
func appendDistroInstallArgs(helmArgs []string, distro string) ([]string, error) {
	switch distro {
	case "k8s", "rke2":
	default:
		return nil, fmt.Errorf("--distro must be k8s or rke2, got %q", distro)
	}
	return append(helmArgs,
		"--set-string", "kata.distro="+distro,
		"--set-string", "nri-image-policy.distro="+distro,
	), nil
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

const installNextSteps = `Next steps:

  1. Deploy this chart inside the intended CVM trust boundary. The supported
     install shape wires chart-managed Assam, cert-issuer, and
     attestation-service together.

  2. (Optional) Mirror status with a ConfidentialWorkload CR:

       kubectl apply -f samples/confidentialworkload.yaml

     When injection is enabled, annotate your workload's pod template:
       confidential.ai/cw: <workload-id>

  3. Inspect mirrored workloads:

       kubectl get cwl -A
`

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
	installCmd.Flags().StringVar(&installDistro, "distro", "k8s", "host Kubernetes distro: k8s (vanilla/kubeadm) or rke2 — selects containerd config paths for kata and nri-image-policy")
	installCmd.Flags().BoolVar(&installKata, "kata", false, "install the Kata Containers runtime stack (kata-deploy DaemonSet + RuntimeClasses)")
	installCmd.Flags().BoolVar(&installKataEnforce, "kata-enforce", false, "enable kata enforcement: inject runtimeClasses into workload pods and reject non-kata RuntimeClasses (implies --kata)")
	rootCmd.AddCommand(installCmd)
}
