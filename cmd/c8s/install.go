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

	installEnableWebhook         bool
	installAssam                 bool
	installAssamURL              string
	installAssamCertIssuerURL    string
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
	Short: "Install the c8s operator, CRDs, node-labeler, attestation-service, and optional Assam via Helm",
	Long: `Extracts the bundled c8s Helm chart and runs
'helm upgrade --install' against the current kubeconfig context. Deploys:

  - the c8s Deployment + Service (admission webhook + status-mirror controllers)
  - the TrustDomain and ConfidentialWorkload CRDs
  - the mutating admission webhook configuration
  - the attestation-service DaemonSet (per-node /attest + /verify)
  - optional chart-managed Assam when --install-assam is set

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
		helmArgs := []string{
			"upgrade", "--install", installRelease, chartPath,
			"--namespace", installNamespace, "--create-namespace",
			// Chart has no default image tags; chart images are released
			// in lockstep with the CLI, so pass the CLI's build Version.
			// Overridable via -f.
			"--set", "image.tag=" + version.Version,
			"--set", "attestationService.image.tag=" + version.Version,
			"--set", "assam.image.tag=" + version.Version,
		}
		if installEnableWebhook {
			helmArgs = append(helmArgs, "--set", "webhook.enabled=true")
		}
		if installAssam {
			helmArgs = append(helmArgs, "--set", "assam.enabled=true")
		}
		if installAssamURL != "" {
			helmArgs = append(helmArgs, "--set-string", "assam.url="+installAssamURL)
		}
		if installAssamCertIssuerURL != "" {
			helmArgs = append(helmArgs, "--set-string", "assam.certIssuerURL="+installAssamCertIssuerURL)
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

const installNextSteps = `Next steps:

  1. Create a TrustDomain (if not using the default):

       kubectl apply -f config/samples/confidential.ai_v1alpha2_trustdomain.yaml

  2. Enable pod injection only after Assam is installed and reachable.
     Use an external assam.url, or enable chart-managed Assam with
     assam.enabled=true and assam.certIssuerURL. Chart-managed Assam is
     bootstrap/dev convenience unless it is deployed as attested
     trust-boundary infrastructure.

  3. (Optional) Mirror status with a ConfidentialWorkload CR:

       kubectl apply -f config/samples/confidential.ai_v1alpha2_confidentialworkload.yaml

     When injection is enabled, annotate your workload's pod template:
       confidential.ai/cw: <workload-id>

  4. Inspect mirrored workloads:

       kubectl get cwl -A
`

func init() {
	installCmd.Flags().StringVar(&installNamespace, "namespace", "c8s-system", "namespace to install into")
	installCmd.Flags().StringVar(&installRelease, "release", "c8s", "Helm release name")
	installCmd.Flags().StringSliceVarP(&installValues, "values", "f", nil, "values files (repeatable)")
	installCmd.Flags().BoolVar(&installWait, "wait", true, "wait for the release to become ready (helm --wait)")
	installCmd.Flags().BoolVar(&installEnableWebhook, "enable-webhook", false, "enable pod injection webhook (requires --assam-url or --install-assam with --assam-cert-issuer-url)")
	installCmd.Flags().BoolVar(&installAssam, "install-assam", false, "install chart-managed Assam (bootstrap/dev unless deployed as attested trust-boundary infrastructure)")
	installCmd.Flags().StringVar(&installAssamURL, "assam-url", "", "assam URL for injected get-cert containers")
	installCmd.Flags().StringVar(&installAssamCertIssuerURL, "assam-cert-issuer-url", "", "cert-issuer URL for chart-managed Assam (required with --install-assam)")
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
