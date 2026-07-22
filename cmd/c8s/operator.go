//go:build !c8s_node

package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/controller"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

var operatorCmd = &cobra.Command{
	Use:   "operator",
	Short: "Run the c8s controller-manager and admission webhook",
	Long: `Runs the controller-runtime manager that mirrors per-pod attestation
state into ConfidentialWorkload status. Also hosts the mutating admission
webhook that injects get-cert bootstrap and renewal containers into pods opted
in via annotation.

Pod-to-pod mTLS is handled by the node-level ratls-mesh DaemonSet, not
by this command.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Fail at start, not at first injection: an unknown platform would
		// otherwise silently select the SNP classes.
		switch operatorHardwarePlatform {
		case webhook.HardwarePlatformSNP, webhook.HardwarePlatformTDX:
		default:
			return fmt.Errorf("--hardware-platform must be %s or %s, got %q",
				webhook.HardwarePlatformSNP, webhook.HardwarePlatformTDX, operatorHardwarePlatform)
		}
		return controller.Run(cmd.Context(), controller.Options{
			MetricsAddr:             metricsAddr,
			HealthAddr:              healthAddr,
			LeaderElection:          leaderElection,
			LeaderElectionID:        "c8s-operator.confidential.ai",
			LeaderElectionNS:        leaderElectionNS,
			DisableStatusMirror:     !statusMirrorEnabled,
			GetCertImage:            getCertImage,
			CDSURL:                  cdsURL,
			AttestationApiURL:       attestationApiURL,
			ExcludeNamespaces:       excludeNamespaces,
			WebhookConfigName:       webhookConfigName,
			WebhookServiceName:      webhookServiceName,
			WebhookServiceNamespace: webhookServiceNamespace,
			CertFSGroup:             certFSGroup,
			CertKeyMode:             certKeyMode,
			CertRenewInterval:       certRenewInterval,
			GetCertRunAsUser:        getCertRunAsUser,
			GetCertRunAsGroup:       getCertRunAsGroup,
			GetCertRunAsNonRoot:     getCertRunAsNonRoot,
			SecretAgentImage:        secretAgentImage,
			SecretAgentCommand:      secretAgentCommand,
			SecretBrokerURL:         secretBrokerURL,
			LUKSOpenImage:           luksOpenImage,
			KataEnforce:             kataEnforce,
			HardwarePlatform:        operatorHardwarePlatform,
			WorkloadClaimsHostDir:   workloadClaimsHostDir,
		})
	},
}

var (
	metricsAddr             string
	healthAddr              string
	leaderElection          bool
	leaderElectionNS        string
	statusMirrorEnabled     bool
	getCertImage            string
	cdsURL                  string
	attestationApiURL       string
	webhookConfigName       string
	webhookServiceName      string
	webhookServiceNamespace string
	excludeNamespaces       []string
	certFSGroup             int64
	certKeyMode             string
	certRenewInterval       time.Duration
	getCertRunAsUser        int64
	getCertRunAsGroup       int64
	getCertRunAsNonRoot     bool

	secretAgentImage   string
	secretAgentCommand string
	secretBrokerURL    string
	luksOpenImage      string

	kataEnforce              bool
	operatorHardwarePlatform string
	workloadClaimsHostDir    string
)

func init() {
	operatorCmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8080", "address for Prometheus metrics")
	operatorCmd.Flags().StringVar(&healthAddr, "health-probe-bind-address", ":8081", "address for health/readyz probes")
	operatorCmd.Flags().BoolVar(&leaderElection, "leader-elect", true, "enable leader election for HA")
	operatorCmd.Flags().StringVar(&leaderElectionNS, "leader-election-namespace", "c8s-system", "namespace holding the leader-election Lease")
	operatorCmd.Flags().BoolVar(&statusMirrorEnabled, "status-mirror-enabled", true, "enable CRD-backed ConfidentialWorkload status mirror controller")
	operatorCmd.Flags().StringVar(&getCertImage, "get-cert-image", "", "image reference the admission webhook injects for get-cert containers (empty = webhook disabled)")
	operatorCmd.Flags().StringVar(&cdsURL, "cds-url", "", "CDS Service URL the injected get-cert containers POST to")
	operatorCmd.Flags().StringVar(&attestationApiURL, "attestation-api-url", "", "attestation-api endpoint (empty = no verification)")
	operatorCmd.Flags().StringSliceVar(&excludeNamespaces, "exclude-namespaces", nil, "extra namespaces the startup reinject sweep skips (mirrors webhook.extraExcluded)")
	operatorCmd.Flags().StringVar(&webhookConfigName, "webhook-config-name", "", "MutatingWebhookConfiguration to patch caBundle (empty = skip)")
	operatorCmd.Flags().StringVar(&webhookServiceName, "webhook-service-name", "", "webhook Service name (defaults to c8s)")
	operatorCmd.Flags().StringVar(&webhookServiceNamespace, "webhook-service-namespace", "", "webhook Service namespace (defaults to --leader-election-namespace)")
	operatorCmd.Flags().Int64Var(&certFSGroup, "cert-fs-group", 65532, "fsGroup applied to injected pods when unset (-1 disables mutation)")
	operatorCmd.Flags().StringVar(&certKeyMode, "cert-key-mode", "0640", "octal mode for injected tls.key")
	operatorCmd.Flags().DurationVar(&certRenewInterval, "get-cert-renew-interval", 6*time.Hour, "renewal interval for injected workload certificates")
	operatorCmd.Flags().Int64Var(&getCertRunAsUser, "get-cert-run-as-user", 65532, "runAsUser for injected get-cert containers")
	operatorCmd.Flags().Int64Var(&getCertRunAsGroup, "get-cert-run-as-group", 65532, "runAsGroup for injected get-cert containers")
	operatorCmd.Flags().BoolVar(&getCertRunAsNonRoot, "get-cert-run-as-non-root", true, "set runAsNonRoot for injected get-cert containers")
	operatorCmd.Flags().StringVar(&secretAgentImage, "secret-agent-image", "", "OpenBao/Vault Agent image injected for pods opting in to secrets injection (empty = secrets injection disabled)")
	operatorCmd.Flags().StringVar(&secretAgentCommand, "secret-agent-command", "bao", "agent binary in --secret-agent-image (bao for OpenBao, vault for HashiCorp Vault)")
	operatorCmd.Flags().StringVar(&secretBrokerURL, "secret-broker-url", "", "default secret-broker base URL the injected agent dials")
	operatorCmd.Flags().StringVar(&luksOpenImage, "luks-open-image", "", "container image the webhook injects to open openbao-gated LUKS volumes for pods with confidential.ai/luks-<name> annotations (empty = LUKS injection disabled). Must expose `c8s luks-open` as its entrypoint.")
	operatorCmd.Flags().BoolVar(&kataEnforce, "kata-enforce", false, "inject a kata runtimeClassName into workload pods that don't request one and enforce kata RuntimeClasses (set by the chart under kata.enabled)")
	operatorCmd.Flags().StringVar(&operatorHardwarePlatform, "hardware-platform", webhook.HardwarePlatformSNP, "CPU TEE the injected confidential kata classes target: sev-snp or tdx (set by the chart to match the RuntimeClasses it renders)")
	operatorCmd.Flags().StringVar(&workloadClaimsHostDir, "workload-claims-host-dir", "", "host directory holding the nri-image-policy broker socket (node-CVM); when set, the webhook mounts it into c8s-cert and injects the get-cert workload-digest claim (docs/ratls.md)")
	rootCmd.AddCommand(operatorCmd)
}
