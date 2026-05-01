package ratlsmesh

import (
	"strings"
	"testing"
	"time"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name                  string
		attestationServiceURL string
		outboundPort          int
		inboundPort           int
		certTTL               time.Duration
		wantErr               string // substring match; "" means no error
	}{
		{
			name:                  "valid config",
			attestationServiceURL: "http://localhost:8400",
			outboundPort:          15001,
			inboundPort:           15006,
			certTTL:               24 * time.Hour,
		},
		{
			name:                  "valid https",
			attestationServiceURL: "https://attestation.svc:8400",
			outboundPort:          15001,
			inboundPort:           15006,
			certTTL:               24 * time.Hour,
		},
		{
			name:                  "empty attestation-service-url",
			attestationServiceURL: "",
			outboundPort:          15001,
			inboundPort:           15006,
			certTTL:               24 * time.Hour,
			wantErr:               "--attestation-service-url is required",
		},
		{
			name:                  "invalid url scheme",
			attestationServiceURL: "localhost:8400",
			outboundPort:          15001,
			inboundPort:           15006,
			certTTL:               24 * time.Hour,
			wantErr:               "must start with http:// or https://",
		},
		{
			name:                  "same ports",
			attestationServiceURL: "http://localhost:8400",
			outboundPort:          15001,
			inboundPort:           15001,
			certTTL:               24 * time.Hour,
			wantErr:               "must differ",
		},
		{
			name:                  "cert-ttl too short",
			attestationServiceURL: "http://localhost:8400",
			outboundPort:          15001,
			inboundPort:           15006,
			certTTL:               1 * time.Millisecond,
			wantErr:               "too short",
		},
		{
			name:                  "cert-ttl exactly 1m",
			attestationServiceURL: "http://localhost:8400",
			outboundPort:          15001,
			inboundPort:           15006,
			certTTL:               1 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.attestationServiceURL, tt.outboundPort, tt.inboundPort, tt.certTTL)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
