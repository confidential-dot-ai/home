// Package requesthandoff implements `c8s cds request-handoff`: the client
// side of the attested mesh-CA handoff (/handoff), runnable standalone as a
// live-cluster rollout-continuity probe.
package requesthandoff

import (
	"os"
	"time"

	"github.com/spf13/cobra"
)

// Exit codes mirror the `verify` subcommand's contract; operators (and the
// future replica pull-on-startup caller) branch on them.
const (
	exitVerified    = 0
	exitUsage       = 1
	exitFailed      = 2 // handoff attempted, but the protocol or verification failed
	exitUnavailable = 3 // /handoff unreachable, disabled (404), or 5xx past the deadline
)

// NewCmd returns the cobra subcommand.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "request-handoff",
		Short: "Pull the mesh CA from a CDS peer via attested handoff",
		Long: `Pull the mesh CA from a CDS peer via attested handoff.

Drives the client side of /handoff end to end: generates an in-memory signer
key, obtains a TEE-bound EAR for it from the peer's /attest-key, pulls the
recipient-encrypted CA material, and verifies the handed-off CA cert is the
live trust root served on GET /ca.

Must run inside an attested TEE with access to the local attestation-api; the
peer admits only launch measurements pinned in its --handoff-measurements.
A non-empty --measurements pin is mandatory even in development; handoff has
no accept-any mode.
The same operator public-key bundle configured on CDS is required: its
canonical hash is bound into both handoff attestations and must match.
Prints a one-line JSON report on stdout. The pulled CA private key never
leaves process memory.

Exit codes: 0 verified · 1 usage · 2 handoff/verification failed · 3 endpoint
unavailable (unreachable / disabled / still bootstrapping past --timeout).`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			os.Exit(run(cmd.Context(), cfg, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&cfg.peerURL, "peer-url", "", "https URL of the CDS peer to pull the mesh CA from")
	f.StringVar(&cfg.attestationApiURL, "attestation-api-url", "", "URL of the attestation-api service")
	f.StringSliceVar(&cfg.measurements, "measurements", nil, "required SHA-384 hex launch measurements the peer may present; pins both its RA-TLS serving cert and its handoff issuer EAR")
	f.StringVar(&cfg.operatorKeys, "operator-keys", "", "PEM bundle of operator EC public keys whose policy hash must match the peer")
	f.StringVar(&cfg.expectedIssuer, "expected-issuer", "cds", "EAR JWT issuer claim required on the peer's handoff EAR")
	f.DurationVar(&cfg.timeout, "timeout", 2*time.Minute, "overall deadline, including retries while the peer's handoff EAR bootstraps")
	f.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")

	_ = cmd.MarkFlagRequired("peer-url")
	_ = cmd.MarkFlagRequired("attestation-api-url")
	_ = cmd.MarkFlagRequired("measurements")
	_ = cmd.MarkFlagRequired("operator-keys")

	return cmd
}
