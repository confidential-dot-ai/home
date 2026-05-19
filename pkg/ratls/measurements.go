package ratls

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseHexMeasurements parses a comma-separated list of hex-encoded SEV-SNP
// launch digests into the byte form VerifyPolicy.Measurements expects. Empty
// input returns nil; the caller decides whether to warn.
func ParseHexMeasurements(raw string) ([][]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		decoded, err := hex.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid hex measurement %q: %w", p, err)
		}
		if len(decoded) != SNPMeasurementSize {
			return nil, fmt.Errorf("measurement %q is %d bytes, want %d", p, len(decoded), SNPMeasurementSize)
		}
		out = append(out, decoded)
	}
	return out, nil
}
