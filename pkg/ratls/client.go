package ratls

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// NewVerifyingHTTPClient returns an http.Client whose TLS handshake
// verifies the peer's RA-TLS attestation extension against the supplied
// measurement allowlist. Empty measurements falls back to TOFU on the
// attestation extension — UNSAFE outside development; the caller is
// expected to warn.
//
// attestationApiURL is the local attestation-api whose /verify endpoint
// performs all peer evidence verification. Required: every handshake
// verification is delegated to it; there is no in-process fallback.
//
// Connection-pool and timeout knobs: 5s dial, 10s response-header, 30s
// overall, MaxIdleConns=5, MaxConnsPerHost=2.
func NewVerifyingHTTPClient(measurements [][]byte, attestationApiURL string) (*http.Client, error) {
	if attestationApiURL == "" {
		return nil, fmt.Errorf("ratls client config: attestation-api URL is required")
	}
	tlsCfg, _, err := NewClientTLSConfig(&ClientConfig{
		Policy: &VerifyPolicy{Measurements: measurements, AttestationApiURL: attestationApiURL},
	})
	if err != nil {
		return nil, fmt.Errorf("ratls client config: %w", err)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConns:          5,
			MaxConnsPerHost:       2,
			TLSClientConfig:       tlsCfg,
		},
	}, nil
}
