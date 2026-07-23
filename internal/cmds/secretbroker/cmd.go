// Package secretbroker implements the secret-broker subcommand: the c8s
// "Secrets Manager Proxy" from the whitepaper (§4.3, §5.6.4). It sits inside
// the trust boundary, speaks a subset of the Vault/OpenBao HTTP API so that
// unmodified Vault/OpenBao Agent + CSI tooling can talk to it, authenticates
// the calling workload by its CDS-issued mesh identity, applies a per-secret
// release policy, and brokers the request to a vanilla OpenBao (or HashiCorp
// Vault) instance.
//
// The external store never sees the workload directly — only the broker's
// identity after the CDS identity check and policy pass.
package secretbroker

import (
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultHTTPReadTimeout       = 10 * time.Second
	defaultHTTPReadHeaderTimeout = 5 * time.Second
	defaultHTTPWriteTimeout      = 10 * time.Second
	defaultHTTPIdleTimeout       = 20 * time.Second
	defaultHTTPMaxHeaderBytes    = 1 << 20
)

// NewCmd returns the cobra subcommand.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "secret-broker",
		Short: "Run the attestation-gated secret broker (Vault/OpenBao proxy)",
		Long: "secret-broker fronts a vanilla OpenBao/Vault instance with an " +
			"attestation gate. It speaks a subset of the Vault HTTP API so " +
			"unmodified Vault/OpenBao Agent and CSI tooling work unchanged, " +
			"authenticates the caller by its CDS-issued mesh identity, and " +
			"releases secrets only when the caller's identity matches the " +
			"release policy.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cfg)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&cfg.host, "host", "0.0.0.0", "listen host")
	flags.IntVarP(&cfg.port, "port", "p", 8443, "listen port")
	flags.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")

	// Broker server identity: the injected c8s get-cert sidecar's cert on the
	// shared c8s-certs tmpfs, as for every other component. Stock agents trust
	// it via their configured CA bundle.
	flags.StringVar(&cfg.tlsCert, "tls-cert", "", "PEM server certificate the broker presents to callers (required)")
	flags.StringVar(&cfg.tlsKey, "tls-key", "", "PEM private key for --tls-cert (required)")

	// Caller (workload) verification. CDS is the trust root: callers are
	// verified by X.509 chain to the CDS mesh CA, and identity is read from the
	// CDS-issued leaf (SAN + config-claims).
	flags.StringVar(&cfg.clientCA, "client-ca", "", "override the CA bundle callers' certs must chain to (default: ca.crt beside --tls-cert, the get-cert mesh CA)")
	flags.StringVar(&cfg.attestationApiURL, "attestation-api-url", "", "attestation-api URL used to verify an attested OpenBao (--openbao-attested)")

	// Release policy.
	flags.StringVar(&cfg.policyFile, "policy", "", "path to the JSON release policy (required); deny-by-default")
	flags.DurationVar(&cfg.tokenTTL, "token-ttl", time.Hour, "lifetime of broker-minted caller tokens")

	// Backing OpenBao/Vault.
	flags.StringVar(&cfg.openbaoAddr, "openbao-addr", "", "base URL of the backing OpenBao/Vault, e.g. https://openbao:8200 (required)")
	flags.StringVar(&cfg.openbaoCA, "openbao-ca", "", "PEM CA bundle for the OpenBao TLS endpoint (empty = system roots)")
	flags.BoolVar(&cfg.openbaoAttested, "openbao-attested", true, "require the OpenBao endpoint to present a valid TEE attestation (RA-TLS); set false for an external/managed store")
	flags.StringSliceVar(&cfg.openbaoMeasurements, "openbao-measurements", nil, "SHA-384 hex launch measurements accepted for an attested OpenBao (empty = accept any TEE measurement, UNSAFE)")
	flags.StringVar(&cfg.openbaoToken, "openbao-token", "", "static token the broker uses to authenticate to OpenBao (mutually exclusive with --openbao-approle-*)")
	flags.StringVar(&cfg.openbaoTokenFile, "openbao-token-file", "", "read the static OpenBao token from this file (keeps it out of argv; e.g. a mounted Secret)")
	flags.StringVar(&cfg.openbaoRoleID, "openbao-approle-role-id", "", "AppRole role_id the broker uses to authenticate to OpenBao")
	flags.StringVar(&cfg.openbaoSecretID, "openbao-approle-secret-id", "", "AppRole secret_id the broker uses to authenticate to OpenBao")
	flags.StringVar(&cfg.openbaoSecretIDFile, "openbao-approle-secret-id-file", "", "read the AppRole secret_id from this file (keeps it out of argv)")

	// HTTP server hardening.
	flags.Int64Var(&cfg.maxRequestSize, "max-request-size", 65536, "max request body bytes")
	flags.DurationVar(&cfg.readTimeout, "read-timeout", defaultHTTPReadTimeout, "HTTP server read timeout")
	flags.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", defaultHTTPReadHeaderTimeout, "HTTP server read-header timeout")
	flags.DurationVar(&cfg.writeTimeout, "write-timeout", defaultHTTPWriteTimeout, "HTTP server write timeout")
	flags.DurationVar(&cfg.idleTimeout, "idle-timeout", defaultHTTPIdleTimeout, "HTTP server idle timeout")
	flags.IntVar(&cfg.maxHeaderBytes, "max-header-bytes", defaultHTTPMaxHeaderBytes, "maximum HTTP request header bytes")

	_ = cmd.MarkFlagRequired("tls-cert")
	_ = cmd.MarkFlagRequired("tls-key")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("openbao-addr")

	return cmd
}

type config struct {
	host     string
	port     int
	logLevel string

	tlsCert string
	tlsKey  string

	clientCA          string
	attestationApiURL string

	policyFile string
	tokenTTL   time.Duration

	openbaoAddr         string
	openbaoCA           string
	openbaoAttested     bool
	openbaoMeasurements []string
	openbaoToken        string
	openbaoTokenFile    string
	openbaoRoleID       string
	openbaoSecretID     string
	openbaoSecretIDFile string

	maxRequestSize    int64
	readTimeout       time.Duration
	readHeaderTimeout time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration
	maxHeaderBytes    int
}
