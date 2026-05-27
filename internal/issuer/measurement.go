package issuer

import (
	"fmt"
	"strings"

	"github.com/lunal-dev/c8s/internal/earclaims"
)

// NormalizeMeasurement canonicalizes launch digest strings before allowlist
// comparison. Attestation services may return hex digests in either case.
func NormalizeMeasurement(measurement string) string {
	return strings.ToLower(strings.TrimSpace(measurement))
}

// CheckMeasurement extracts the SNP launch digest from claims.RawEvidence
// and confirms it is in allowed. Returns nil when allowed is empty (opt-in
// pinning); otherwise returns a *TokenValidationError so the caller can map
// the failure reason to a metric label without parsing the error string.
// endpoint is interpolated into the error so the caller doesn't have to.
func CheckMeasurement(claims *EARClaims, allowed map[string]bool, endpoint string) error {
	if len(allowed) == 0 {
		return nil
	}
	measurement, err := earclaims.LaunchDigestFromSubmods(claims.RawEvidence)
	if err != nil {
		return &TokenValidationError{
			Reason: ReasonMeasurementDenied,
			Err:    fmt.Errorf("extract measurement for %s: %w", endpoint, err),
		}
	}
	measurement = NormalizeMeasurement(measurement)
	if !allowed[measurement] {
		return &TokenValidationError{
			Reason: ReasonMeasurementDenied,
			Err:    fmt.Errorf("measurement not allowed for %s", endpoint),
		}
	}
	return nil
}
