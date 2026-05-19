package ratlsmesh

import (
	"strings"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/pkg/ratls"
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

func TestRATLSTEEType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ratls.TEEType
		wantErr string
	}{
		{name: "sev snp", input: "sev-snp", want: ratls.TEETypeSEVSNP},
		{name: "empty", wantErr: "--platform is required"},
		{name: "tdx", input: "tdx", wantErr: "TDX platform is not yet implemented"},
		{name: "unknown", input: "sgx", wantErr: "unsupported --platform"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ratlsTEEType(tt.input)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ratlsTEEType() error = %v", err)
				}
				if got != tt.want {
					t.Fatalf("ratlsTEEType() = %v, want %v", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestEffectiveAssamCAURL(t *testing.T) {
	tests := []struct {
		name          string
		certMode      string
		certIssuerURL string
		caURL         string
		want          string
	}{
		{
			name:          "assam mode defaults to cert issuer CA endpoint",
			certMode:      "assam",
			certIssuerURL: "http://cert-issuer:8090",
			want:          "http://cert-issuer:8090/ca",
		},
		{
			name:          "assam mode trims cert issuer URL slash",
			certMode:      "assam",
			certIssuerURL: "http://cert-issuer:8090/",
			want:          "http://cert-issuer:8090/ca",
		},
		{
			name:          "explicit CA URL wins",
			certMode:      "assam",
			certIssuerURL: "http://cert-issuer:8090",
			caURL:         "http://ca.example/mesh.pem",
			want:          "http://ca.example/mesh.pem",
		},
		{
			name:          "self signed keeps empty default",
			certMode:      "self-signed",
			certIssuerURL: "http://cert-issuer:8090",
			want:          "",
		},
		{
			name:     "self signed preserves explicit CA URL",
			certMode: "self-signed",
			caURL:    "http://ca.example/mesh.pem",
			want:     "http://ca.example/mesh.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveAssamCAURL(tt.certMode, tt.certIssuerURL, tt.caURL)
			if got != tt.want {
				t.Fatalf("effectiveAssamCAURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
