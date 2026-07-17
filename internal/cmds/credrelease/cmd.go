package credrelease

import (
	"time"

	"github.com/spf13/cobra"
)

// NewCmd builds the `cred-release` subcommand: the in-guest service that
// issues an operator a short-lived kube client cert, gated on possession of
// the operator key measured into RTMR[3]. Baked as a systemd unit in the c8s
// node image; not run by hand in normal operation.
func NewCmd() *cobra.Command {
	var cfg Config
	cmd := &cobra.Command{
		Use:   "cred-release",
		Short: "Release a kube operator credential to the attested holder of the RTMR[3]-bound key",
		Long: "cred-release serves an RA-TLS endpoint that issues a short-lived\n" +
			"kube client certificate to a caller who proves possession of the\n" +
			"operator key whose public half was bound into RTMR[3] at launch.\n" +
			"It gives an external operator console-free, non-TOFU cluster-admin\n" +
			"access with no pre-shared secret and no trust in the host. The cert\n" +
			"is signed by the cluster's client CA and the kubeconfig anchors to\n" +
			"the serving CA (RKE2 paths by default; any distribution works via\n" +
			"--client-ca-cert/--client-ca-key/--server-ca-cert — on kubeadm all\n" +
			"three are /etc/kubernetes/pki/ca.crt).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return Run(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.ListenAddr, "listen", ":8443", "HTTPS (RA-TLS) bind address")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", "http://127.0.0.1:8400", "local attestation-api base URL (source of the RA-TLS serving cert's TDX quote)")
	f.StringVar(&cfg.Platform, "platform", "tdx", "TEE platform (RTMR is TDX-only)")
	f.StringVar(&cfg.ClientCACert, "client-ca-cert", defaultClientCACert, "cluster client-CA cert that signs kube client certs (kubeadm: /etc/kubernetes/pki/ca.crt)")
	f.StringVar(&cfg.ClientCAKey, "client-ca-key", defaultClientCAKey, "cluster client-CA key (kubeadm: /etc/kubernetes/pki/ca.key)")
	f.StringVar(&cfg.ServerCACert, "server-ca-cert", defaultServerCACert, "CA that signs the apiserver serving cert; embedded in the released kubeconfig (kubeadm: /etc/kubernetes/pki/ca.crt)")
	f.DurationVar(&cfg.CertTTL, "cert-ttl", 24*time.Hour, "lifetime of issued operator certs")
	f.StringVar(&cfg.CertOrg, "cert-org", "system:masters", "Kubernetes group (cert Subject O) for the issued cert")
	f.StringVar(&cfg.CertCN, "cert-cn", "operator", "Kubernetes user (cert Subject CN) for the issued cert")
	return cmd
}
