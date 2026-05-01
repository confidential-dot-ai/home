//go:build !c8s_node

package main

import (
	"github.com/spf13/cobra"

	"github.com/lunal-dev/c8s/internal/controller"
)

var operatorCmd = &cobra.Command{
	Use:   "operator",
	Short: "Run the c8s controller-manager and admission webhook",
	Long: `Runs the controller-runtime manager that mirrors per-pod attestation
state into ConfidentialWorkload status. Also hosts the mutating admission
webhook that injects the c8s-init-cert/get-cert init container into pods opted
in via annotation.

Pod-to-pod mTLS is handled by the node-level ratls-mesh DaemonSet, not
by this command.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return controller.Run(cmd.Context(), controller.Options{
			MetricsAddr:                        metricsAddr,
			HealthAddr:                         healthAddr,
			LeaderElection:                     leaderElection,
			LeaderElectionID:                   "c8s-operator.confidential.ai",
			LeaderElectionNS:                   leaderElectionNS,
			DisableStatusMirror:                !statusMirrorEnabled,
			OperatorImage:                      operatorImage,
			AssamURL:                           assamURL,
			AttestationServiceURL:              attestationServiceURL,
			AttestationServiceAPIKeySecretName: attestationServiceAPIKeySecretName,
			AttestationServiceAPIKeySecretKey:  attestationServiceAPIKeySecretKey,
			WebhookConfigName:                  webhookConfigName,
			WebhookServiceName:                 webhookServiceName,
			WebhookServiceNamespace:            webhookServiceNamespace,
			CertFSGroup:                        certFSGroup,
			CertKeyMode:                        certKeyMode,
			InitRunAsUser:                      initRunAsUser,
			InitRunAsGroup:                     initRunAsGroup,
			InitRunAsNonRoot:                   initRunAsNonRoot,
		})
	},
}

var (
	metricsAddr                        string
	healthAddr                         string
	leaderElection                     bool
	leaderElectionNS                   string
	statusMirrorEnabled                bool
	operatorImage                      string
	assamURL                           string
	attestationServiceURL              string
	attestationServiceAPIKeySecretName string
	attestationServiceAPIKeySecretKey  string
	webhookConfigName                  string
	webhookServiceName                 string
	webhookServiceNamespace            string
	certFSGroup                        int64
	certKeyMode                        string
	initRunAsUser                      int64
	initRunAsGroup                     int64
	initRunAsNonRoot                   bool
)

func init() {
	operatorCmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8080", "address for Prometheus metrics")
	operatorCmd.Flags().StringVar(&healthAddr, "health-probe-bind-address", ":8081", "address for health/readyz probes")
	operatorCmd.Flags().BoolVar(&leaderElection, "leader-elect", true, "enable leader election for HA")
	operatorCmd.Flags().StringVar(&leaderElectionNS, "leader-election-namespace", "c8s-system", "namespace holding the leader-election Lease")
	operatorCmd.Flags().BoolVar(&statusMirrorEnabled, "status-mirror-enabled", true, "enable CRD-backed ConfidentialWorkload status mirror controller")
	operatorCmd.Flags().StringVar(&operatorImage, "operator-image", "", "image reference the admission webhook injects for init-container (empty = webhook disabled)")
	operatorCmd.Flags().StringVar(&assamURL, "assam-url", "", "assam Service URL the injected init container POSTs to")
	operatorCmd.Flags().StringVar(&attestationServiceURL, "attestation-service-url", "", "attestation-service endpoint (empty = no verification)")
	operatorCmd.Flags().StringVar(&attestationServiceAPIKeySecretName, "attestation-service-api-key-secret-name", "", "workload-namespace Secret name holding the attestation-service API key (empty = no API key env)")
	operatorCmd.Flags().StringVar(&attestationServiceAPIKeySecretKey, "attestation-service-api-key-secret-key", "apiKey", "Secret key holding the attestation-service API key")
	operatorCmd.Flags().StringVar(&webhookConfigName, "webhook-config-name", "", "MutatingWebhookConfiguration to patch caBundle (empty = skip)")
	operatorCmd.Flags().StringVar(&webhookServiceName, "webhook-service-name", "", "webhook Service name (defaults to c8s)")
	operatorCmd.Flags().StringVar(&webhookServiceNamespace, "webhook-service-namespace", "", "webhook Service namespace (defaults to --leader-election-namespace)")
	operatorCmd.Flags().Int64Var(&certFSGroup, "cert-fs-group", 65532, "fsGroup applied to injected pods when unset (-1 disables mutation)")
	operatorCmd.Flags().StringVar(&certKeyMode, "cert-key-mode", "0640", "octal mode for injected tls.key")
	operatorCmd.Flags().Int64Var(&initRunAsUser, "init-run-as-user", 65532, "runAsUser for the injected init container")
	operatorCmd.Flags().Int64Var(&initRunAsGroup, "init-run-as-group", 65532, "runAsGroup for the injected init container")
	operatorCmd.Flags().BoolVar(&initRunAsNonRoot, "init-run-as-non-root", true, "set runAsNonRoot for the injected init container")
	rootCmd.AddCommand(operatorCmd)
}
