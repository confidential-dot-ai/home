package cds

import (
	"context"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

func TestNewCmdDefaultsToSupportedRATLSPlatform(t *testing.T) {
	flag := NewCmd().Flags().Lookup("ratls-platform")
	if flag == nil {
		t.Fatal("missing --ratls-platform flag")
	}
	if flag.DefValue != "sev-snp" {
		t.Fatalf("default --ratls-platform = %q, want sev-snp", flag.DefValue)
	}

	_, _, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:   flag.DefValue,
		AttestFunc: func(context.Context, string) (string, error) { return "", nil },
	})
	if err != nil {
		t.Fatalf("default --ratls-platform is not accepted by ratls: %v", err)
	}
}
