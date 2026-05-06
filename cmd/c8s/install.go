//go:build !c8s_node

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lunal-dev/c8s/internal/helmchart"
	"github.com/lunal-dev/c8s/internal/version"
)

var (
	installNamespace string
	installRelease   string
	installValues    []string
	installWait      bool
	installCRDs      bool

	installEnableWebhook         bool
	installAssam                 bool
	installAssamURL              string
	installAssamCertIssuerURL    string
	installCertIssuer            bool
	installCertIssuerJWKSURL     string
	installAttestationSecretName string
	installAttestationSecretKey  string
	installWorkloadNamespaces    []string
	installCertFSGroup           int64
	installCertKeyMode           string
	installInitRunAsUser         int64
	installInitRunAsGroup        int64
	installInitRunAsNonRoot      bool
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the c8s operator, CRDs, attestation-service, and component charts via Helm",
	Long: `Extracts the bundled c8s Helm chart and runs
'helm upgrade --install' against the current kubeconfig context. Deploys:

  - the c8s Deployment + Service (admission webhook + status-mirror controllers)
  - the ConfidentialWorkload CRD
  - the mutating admission webhook configuration
  - the attestation-service DaemonSet (per-node /attest + /verify)
  - chart-managed Assam, cert-issuer, and bootstrap mesh CA
  - vendored component charts from lunal-dev/c8s-charts

Requires the 'helm' CLI to be on PATH.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := exec.LookPath("helm"); err != nil {
			return fmt.Errorf("helm CLI not found on PATH: %w", err)
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
			"--namespace", installNamespace, "--create-namespace",
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
			"--set", "tls-lb.initContainer.image.tag=" + imageTag,
		}
		helmArgs = appendInstallCRDArgs(helmArgs, installCRDs)
		if installEnableWebhook {
			helmArgs = append(helmArgs, "--set", "webhook.enabled=true")
		}
		if installAssam {
			helmArgs = append(helmArgs, "--set", "assam.enabled=true")
		}
		if installCertIssuer || (installAssam && installAssamCertIssuerURL == "") {
			helmArgs = append(helmArgs, "--set", "certIssuer.enabled=true")
		}
		if installAssamURL != "" {
			helmArgs = append(helmArgs, "--set-string", "assam.url="+installAssamURL)
		}
		if installAssamCertIssuerURL != "" {
			helmArgs = append(helmArgs, "--set-string", "assam.certIssuerURL="+installAssamCertIssuerURL)
		}
		if installCertIssuerJWKSURL != "" {
			helmArgs = append(helmArgs, "--set-string", "certIssuer.jwksURL="+installCertIssuerJWKSURL)
		}
		if installAttestationSecretName != "" {
			helmArgs = append(helmArgs, "--set-string", "webhook.apiKeySecret.name="+installAttestationSecretName)
		}
		if installAttestationSecretKey != "" {
			helmArgs = append(helmArgs, "--set-string", "webhook.apiKeySecret.key="+installAttestationSecretKey)
		}
		if len(installWorkloadNamespaces) > 0 {
			helmArgs = append(helmArgs, "--set", "webhook.apiKeySecret.createInNamespaces={"+strings.Join(installWorkloadNamespaces, ",")+"}")
		}
		if installEnableWebhook {
			helmArgs = append(helmArgs,
				"--set", fmt.Sprintf("webhook.certVolume.fsGroup=%d", installCertFSGroup),
				"--set-string", "webhook.certVolume.keyMode="+installCertKeyMode,
				"--set", fmt.Sprintf("webhook.initContainer.runAsUser=%d", installInitRunAsUser),
				"--set", fmt.Sprintf("webhook.initContainer.runAsGroup=%d", installInitRunAsGroup),
				"--set", fmt.Sprintf("webhook.initContainer.runAsNonRoot=%t", installInitRunAsNonRoot),
			)
		}
		for _, vf := range installValues {
			helmArgs = append(helmArgs, "-f", vf)
		}
		if installWait {
			helmArgs = append(helmArgs, "--wait", "--timeout=5m")
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

const installNextSteps = `Next steps:

  1. Enable pod injection only after Assam and cert-issuer are reachable.
     Use an external assam.url/cert issuer pair, or enable chart-managed
     Assam and cert-issuer together. Chart-managed Assam/cert-issuer are
     bootstrap/dev convenience unless deployed as attested trust-boundary
     infrastructure.

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
	installCmd.Flags().BoolVar(&installEnableWebhook, "enable-webhook", false, "enable pod injection webhook (requires --assam-url or --install-assam)")
	installCmd.Flags().BoolVar(&installAssam, "install-assam", false, "install chart-managed Assam (bootstrap/dev unless deployed as attested trust-boundary infrastructure)")
	installCmd.Flags().StringVar(&installAssamURL, "assam-url", "", "assam URL for injected get-cert containers")
	installCmd.Flags().StringVar(&installAssamCertIssuerURL, "assam-cert-issuer-url", "", "external cert-issuer URL for chart-managed Assam (empty installs chart-managed cert-issuer with --install-assam)")
	installCmd.Flags().BoolVar(&installCertIssuer, "install-cert-issuer", false, "install chart-managed cert-issuer and bootstrap mesh CA Secret")
	installCmd.Flags().StringVar(&installCertIssuerJWKSURL, "cert-issuer-jwks-url", "", "JWKS URL for chart-managed cert-issuer (empty uses chart-managed Assam when enabled)")
	installCmd.Flags().StringVar(&installAttestationSecretName, "attestation-secret-name", "", "workload-namespace Secret name injected for attestation-service auth")
	installCmd.Flags().StringVar(&installAttestationSecretKey, "attestation-secret-key", "apiKey", "Secret key injected for attestation-service auth")
	installCmd.Flags().StringArrayVar(&installWorkloadNamespaces, "workload-namespace", nil, "namespace where the chart should create a workload auth Secret (repeatable)")
	installCmd.Flags().Int64Var(&installCertFSGroup, "webhook-cert-fs-group", 65532, "fsGroup for injected certificate volume")
	installCmd.Flags().StringVar(&installCertKeyMode, "webhook-cert-key-mode", "0640", "octal mode for injected tls.key")
	installCmd.Flags().Int64Var(&installInitRunAsUser, "webhook-init-run-as-user", 65532, "runAsUser for injected init container")
	installCmd.Flags().Int64Var(&installInitRunAsGroup, "webhook-init-run-as-group", 65532, "runAsGroup for injected init container")
	installCmd.Flags().BoolVar(&installInitRunAsNonRoot, "webhook-init-run-as-non-root", true, "set runAsNonRoot for injected init container")
	rootCmd.AddCommand(installCmd)
}
