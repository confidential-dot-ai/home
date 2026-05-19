package certissuer

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/lunal-dev/c8s/pkg/ratls"
)

// buildJWKSHTTPClient picks the right transport for the JWKS URL: RA-TLS if
// the scheme is https (the chart-managed CVM path), plain HTTP otherwise
// (legacy/dev paths). Empty measurements with an https URL still succeeds
// but logs a warning — operators in production should pin the value.
func buildJWKSHTTPClient(rawURL, measurementsRaw string, logger *slog.Logger) (*http.Client, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid --jwks-url: %w", err)
	}
	if parsed.Scheme != "https" {
		logger.Warn("JWKS endpoint is plaintext HTTP; an on-path attacker can swap the EAR signing keys cert-issuer trusts. Use https:// with --jwks-assam-measurements set in chart-managed CVM deployments.")
		return &http.Client{Timeout: 10 * time.Second}, nil
	}
	measurements, err := ratls.ParseHexMeasurements(measurementsRaw)
	if err != nil {
		return nil, fmt.Errorf("--jwks-assam-measurements: %w", err)
	}
	if len(measurements) == 0 {
		logger.Warn("--jwks-assam-measurements not set; the JWKS RA-TLS handshake accepts any Assam measurement. Pin the operator-supplied launch digest to close bootstrap MITM.")
	}
	return ratls.NewVerifyingHTTPClient(measurements)
}
