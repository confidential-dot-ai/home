package getkubeconfig

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// NewCmd builds the `get-kubeconfig` subcommand: the operator-side client that
// obtains an RKE2 admin kubeconfig from a measured TDX CVM by attesting the
// node, confirming it was launched to trust the operator's key (RTMR[3]), and
// exchanging a CSR for a signed client cert over the cred-release endpoint.
func NewCmd() *cobra.Command {
	var (
		cfg  Config
		node string
	)
	cmd := &cobra.Command{
		Use:   "get-kubeconfig",
		Short: "Attest a c8s CVM and obtain an operator kubeconfig via the RTMR[3]-bound key",
		Long: "get-kubeconfig attests a measured c8s TDX CVM, confirms rtmr[3] proves\n" +
			"the node trusts the operator's key, then exchanges a CSR for a\n" +
			"short-lived RKE2 client cert over the cred-release endpoint and writes\n" +
			"a kubeconfig. Needs attestation-cli on PATH (or $ATTESTATION_CLI).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.OperatorKeyPath == "" || cfg.OutPath == "" {
				return fmt.Errorf("--operator-key and --out are required")
			}
			// --node <host> is a convenience that fills the three URLs with the
			// standard ports; explicit --attest-url/--release-url/--apiserver-url
			// override. At least one of node or the explicit URLs must be set.
			if node != "" {
				if cfg.AttestURL == "" {
					cfg.AttestURL = fmt.Sprintf("http://%s:8400/attest", node)
				}
				if cfg.ReleaseBaseURL == "" {
					cfg.ReleaseBaseURL = fmt.Sprintf("https://%s:8443", node)
				}
				if cfg.APIServerURL == "" {
					cfg.APIServerURL = fmt.Sprintf("https://%s:6443", node)
				}
			}
			if cfg.AttestURL == "" || cfg.ReleaseBaseURL == "" || cfg.APIServerURL == "" {
				return fmt.Errorf("set --node, or all of --attest-url/--release-url/--apiserver-url")
			}
			return Run(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&node, "node", "", "guest host/IP; fills --attest-url/--release-url/--apiserver-url with standard ports (8400/8443/6443)")
	f.StringVar(&cfg.AttestURL, "attest-url", "", "attestation-api /attest URL (overrides --node)")
	f.StringVar(&cfg.ReleaseBaseURL, "release-url", "", "cred-release base URL (overrides --node)")
	f.StringVar(&cfg.APIServerURL, "apiserver-url", "", "apiserver URL for the kubeconfig (overrides --node)")
	f.StringVar(&cfg.OperatorKeyPath, "operator-key", "", "operator ECDSA private key PEM (its public half is bound into RTMR[3]) (required)")
	f.StringVar(&cfg.ContextName, "context", "c8s", "kubeconfig cluster/context/user name")
	f.StringVar(&cfg.TLSServerName, "tls-server-name", "c8s-cvm", "kubeconfig tls-server-name — pins apiserver cert verification to this SAN (the image bakes it into tls-san) instead of the dialed IP. Empty to omit")
	f.StringVar(&cfg.OutPath, "out", "", "output kubeconfig path (required)")
	f.BoolVar(&cfg.InsecureSkipTLSVerify, "insecure-skip-tls-verify", true, "skip :8443 server-cert verification (v1: the attestation gate + CA signature + JWT PoP secure the release; RA-TLS pinning is a follow-up)")
	f.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "per-step network timeout")
	return cmd
}
