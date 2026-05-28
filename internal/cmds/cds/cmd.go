// Package cds implements the Certificate Distribution Service subcommand:
// the c8s trust root (attestation, EAR issuance, mesh CA, leaf signing,
// handoff).
package cds

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/lunal-dev/c8s/internal/issuer"
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
		Use:   "cds",
		Short: "Run the Certificate Distribution Service (CDS)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cfg)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&cfg.host, "host", "0.0.0.0", "")
	flags.IntVarP(&cfg.port, "port", "p", 8443, "")
	flags.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")

	flags.StringVar(&cfg.attestationSvcURL, "attestation-service-url", "", "URL of the attestation service")
	flags.StringVar(&cfg.caCommonName, "ca-common-name", issuer.DefaultCACommonName, "common name for the in-memory generated mesh CA")
	flags.DurationVar(&cfg.caCertValidity, "ca-cert-validity", 8760*time.Hour, "validity period of the in-memory mesh CA certificate")
	flags.StringSliceVar(&cfg.measurements, "measurements", nil, "SHA-384 hex launch measurements allowed to call /attest (empty = no pinning, UNSAFE)")

	flags.StringVar(&cfg.earIssuerName, "ear-issuer", "cds", "")
	flags.StringVar(&cfg.expectedIssuer, "expected-issuer", "", "EAR JWT issuer claim required on /sign-csr (empty disables)")
	flags.Int64Var(&cfg.jwtClockSkew, "jwt-clock-skew", 30, "EAR JWT exp/nbf/iat clock skew tolerance in seconds")
	flags.DurationVar(&cfg.maxTTL, "max-ttl", 24*time.Hour, "upper bound on /sign-csr leaf TTL")
	flags.DurationVar(&cfg.certTTL, "cert-ttl", 24*time.Hour, "")
	flags.DurationVar(&cfg.challengeTTL, "challenge-ttl", 60*time.Second, "")
	flags.DurationVar(&cfg.requestTimeout, "request-timeout", 5*time.Second, "per-request /attest timeout (0 disables)")
	flags.Int64Var(&cfg.maxRequestSize, "max-request-size", 65536, "max request body bytes on write endpoints")
	flags.DurationVar(&cfg.readTimeout, "read-timeout", defaultHTTPReadTimeout, "HTTP server read timeout")
	flags.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", defaultHTTPReadHeaderTimeout, "HTTP server read-header timeout")
	flags.DurationVar(&cfg.writeTimeout, "write-timeout", defaultHTTPWriteTimeout, "HTTP server write timeout")
	flags.DurationVar(&cfg.idleTimeout, "idle-timeout", defaultHTTPIdleTimeout, "HTTP server idle timeout")
	flags.IntVar(&cfg.maxHeaderBytes, "max-header-bytes", defaultHTTPMaxHeaderBytes, "maximum HTTP request header bytes")

	flags.BoolVar(&cfg.sanValidation, "san-validation", true, "require CSR IP SANs to equal the request source IP (false rejects CSRs carrying IP SANs)")
	flags.StringVar(&cfg.dnsSANPattern, "dns-san-pattern", "", "regex DNS SANs must match in full (empty rejects any DNS SAN)")
	flags.StringVar(&cfg.allowedCNPattern, "allowed-cn-pattern", "", "regex the CSR Subject CN must match in full (empty disables)")
	flags.DurationVar(&cfg.readinessInterval, "readiness-interval", 10*time.Second, "")
	flags.DurationVar(&cfg.minCAValidity, "min-ca-validity", time.Hour, "/readyz fails when the loaded mesh CA has less than this remaining lifetime")
	flags.StringVar(&cfg.whitelistDB, "whitelist-db", "", "Path to the whitelist SQLite database")
	flags.StringSliceVar(&cfg.whitelistWriteMeasurements, "whitelist-write-measurements", nil, "SHA-384 hex launch measurements allowed to mutate the whitelist via a bearer EAR (empty = reject all writes)")
	flags.StringSliceVar(&cfg.handoffMeasurements, "handoff-measurements", nil, "SHA-384 hex launch measurements allowed to pull the mesh CA via /handoff (empty = /handoff disabled)")

	flags.Float64Var(&cfg.rateLimit, "rate-limit", 10, "max requests per second per source IP on attestation endpoints")
	flags.IntVar(&cfg.rateBurst, "rate-burst", 20, "max burst size per source IP")
	flags.IntVar(&cfg.rateLimiterMax, "rate-limiter-max-entries", 10000, "max entries in the per-IP rate limiter")
	flags.DurationVar(&cfg.rateLimiterEvictInterval, "rate-limiter-evict-interval", time.Minute, "interval for per-IP rate limiter eviction sweep")
	flags.DurationVar(&cfg.rateLimiterIdleTimeout, "rate-limiter-idle-timeout", 5*time.Minute, "idle duration before a per-IP rate limiter entry is evicted")

	flags.DurationVar(&cfg.rotationInterval, "token-signer-rotation-interval", 720*time.Hour, "EAR signing key rotation interval (0 disables)")
	flags.DurationVar(&cfg.rotationOverlap, "token-signer-overlap", 25*time.Hour, "how long a retired EAR key stays in JWKS")
	flags.Float64Var(&cfg.rotationJitter, "token-signer-rotation-jitter", 0.1, "")

	flags.StringVar(&cfg.ratlsPlatform, "ratls-platform", "sev-snp", "TEE platform for the RA-TLS serving cert (sev-snp; snp, az-snp, and gcp-snp aliases are normalized). Empty disables TLS — UNSAFE outside tests.")
	flags.DurationVar(&cfg.ratlsCertTTL, "ratls-cert-ttl", 24*time.Hour, "")

	_ = cmd.MarkFlagRequired("attestation-service-url")
	_ = cmd.MarkFlagRequired("whitelist-db")

	return cmd
}

type config struct {
	host                       string
	port                       int
	logLevel                   string
	attestationSvcURL          string
	caCommonName               string
	caCertValidity             time.Duration
	measurements               []string
	earIssuerName              string
	expectedIssuer             string
	jwtClockSkew               int64
	maxTTL                     time.Duration
	certTTL                    time.Duration
	challengeTTL               time.Duration
	requestTimeout             time.Duration
	maxRequestSize             int64
	readTimeout                time.Duration
	readHeaderTimeout          time.Duration
	writeTimeout               time.Duration
	idleTimeout                time.Duration
	maxHeaderBytes             int
	sanValidation              bool
	dnsSANPattern              string
	allowedCNPattern           string
	readinessInterval          time.Duration
	minCAValidity              time.Duration
	whitelistDB                string
	whitelistWriteMeasurements []string
	handoffMeasurements        []string
	rotationInterval           time.Duration
	rotationOverlap            time.Duration
	rotationJitter             float64
	ratlsPlatform              string
	ratlsCertTTL               time.Duration

	rateLimit                float64
	rateBurst                int
	rateLimiterMax           int
	rateLimiterEvictInterval time.Duration
	rateLimiterIdleTimeout   time.Duration
}
