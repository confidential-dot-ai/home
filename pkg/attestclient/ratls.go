package attestclient

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// MakeSNPRATLSAttestFunc returns an RA-TLS AttestFunc (matching
// pkg/ratls.ServerConfig.AttestFunc) that asks an attestation service for
// an SEV-SNP report binding the serving key. customData is the hex-encoded
// REPORTDATA the ratls TLS handshake passes in; only the leading SHA-384
// bytes are sent to the service to match the SNP report layout.
func MakeSNPRATLSAttestFunc(client Client, attestationServiceURL string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, customData string) (string, error) {
		reportDataBytes, err := hex.DecodeString(customData)
		if err != nil {
			return "", fmt.Errorf("decode report data hex: %w", err)
		}
		reportDataBytes = reportDataBytes[:sha512.Size384]
		resp, err := client.GenerateEvidenceContext(ctx, attestationServiceURL, reportDataBytes)
		if err != nil {
			return "", fmt.Errorf("attestation service: %w", err)
		}
		return ExtractSNPReport(resp)
	}
}
