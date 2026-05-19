//go:build !c8s_node

package main

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/lunal-dev/c8s/internal/controller"
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
		return controller.Run(cmd.Context(), controller.Options{
			MetricsAddr:             metricsAddr,
			HealthAddr:              healthAddr,
			LeaderElection:          leaderElection,
			LeaderElectionID:        "c8s-operator.confidential.ai",
			LeaderElectionNS:        leaderElectionNS,
			DisableStatusMirror:     !statusMirrorEnabled,
			GetCertImage:            getCertImage,
			AssamURL:                assamURL,
			AttestationServiceURL:   attestationServiceURL,
			WebhookConfigName:       webhookConfigName,
			WebhookServiceName:      webhookServiceName,
			WebhookServiceNamespace: webhookServiceNamespace,
			CertFSGroup:             certFSGroup,
			CertKeyMode:             certKeyMode,
			CertRenewInterval:       certRenewInterval,
			GetCertRunAsUser:        getCertRunAsUser,
			GetCertRunAsGroup:       getCertRunAsGroup,
			GetCertRunAsNonRoot:     getCertRunAsNonRoot,
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
	assamURL                string
	attestationServiceURL   string
	webhookConfigName       string
	webhookServiceName      string
	webhookServiceNamespace string
	certFSGroup             int64
	certKeyMode             string
	certRenewInterval       time.Duration
	getCertRunAsUser        int64
	getCertRunAsGroup       int64
	getCertRunAsNonRoot     bool
)

func init() {
	operatorCmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8080", "address for Prometheus metrics")
	operatorCmd.Flags().StringVar(&healthAddr, "health-probe-bind-address", ":8081", "address for health/readyz probes")
	operatorCmd.Flags().BoolVar(&leaderElection, "leader-elect", true, "enable leader election for HA")
	operatorCmd.Flags().StringVar(&leaderElectionNS, "leader-election-namespace", "c8s-system", "namespace holding the leader-election Lease")
	operatorCmd.Flags().BoolVar(&statusMirrorEnabled, "status-mirror-enabled", true, "enable CRD-backed ConfidentialWorkload status mirror controller")
	operatorCmd.Flags().StringVar(&getCertImage, "get-cert-image", "", "image reference the admission webhook injects for get-cert containers (empty = webhook disabled)")
	operatorCmd.Flags().StringVar(&assamURL, "assam-url", "", "assam Service URL the injected get-cert containers POST to")
	operatorCmd.Flags().StringVar(&attestationServiceURL, "attestation-service-url", "", "attestation-service endpoint (empty = no verification)")
	operatorCmd.Flags().StringVar(&webhookConfigName, "webhook-config-name", "", "MutatingWebhookConfiguration to patch caBundle (empty = skip)")
	operatorCmd.Flags().StringVar(&webhookServiceName, "webhook-service-name", "", "webhook Service name (defaults to c8s)")
	operatorCmd.Flags().StringVar(&webhookServiceNamespace, "webhook-service-namespace", "", "webhook Service namespace (defaults to --leader-election-namespace)")
	operatorCmd.Flags().Int64Var(&certFSGroup, "cert-fs-group", 65532, "fsGroup applied to injected pods when unset (-1 disables mutation)")
	operatorCmd.Flags().StringVar(&certKeyMode, "cert-key-mode", "0640", "octal mode for injected tls.key")
	operatorCmd.Flags().DurationVar(&certRenewInterval, "get-cert-renew-interval", 6*time.Hour, "renewal interval for injected workload certificates")
	operatorCmd.Flags().Int64Var(&getCertRunAsUser, "get-cert-run-as-user", 65532, "runAsUser for injected get-cert containers")
	operatorCmd.Flags().Int64Var(&getCertRunAsGroup, "get-cert-run-as-group", 65532, "runAsGroup for injected get-cert containers")
	operatorCmd.Flags().BoolVar(&getCertRunAsNonRoot, "get-cert-run-as-non-root", true, "set runAsNonRoot for injected get-cert containers")
	rootCmd.AddCommand(operatorCmd)
}
