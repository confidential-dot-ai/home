package requesthandoff

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

func testCA(t *testing.T, cn string) *issuer.CA {
	t.Helper()
	ca, err := issuer.NewCAWithCurve(cn, time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestServedCAMatch(t *testing.T) {
	ca := testCA(t, "match-ca")
	other := testCA(t, "other-ca")

	if !servedCAMatch([]*x509.Certificate{other.Cert, ca.Cert}, ca.Cert) {
		t.Fatal("servedCAMatch = false for a bundle containing the CA")
	}
	if servedCAMatch([]*x509.Certificate{other.Cert}, ca.Cert) {
		t.Fatal("servedCAMatch = true for a bundle without the CA")
	}
}

func TestExitCodeFor(t *testing.T) {
	cases := []struct {
		name string
		err  error
		exit int
	}{
		{"handoff 404 (disabled, retryable-ish)", &issuer.HandoffStatusError{Status: http.StatusNotFound}, exitUnavailable},
		{"handoff 403 (denied)", &issuer.HandoffStatusError{Status: http.StatusForbidden}, exitFailed},
		{"handoff 503 (bootstrapping)", &issuer.HandoffStatusError{Status: http.StatusServiceUnavailable}, exitUnavailable},
		{"handoff 429 (throttled)", &issuer.HandoffStatusError{Status: http.StatusTooManyRequests}, exitUnavailable},
		{"attest-key 401", fmt.Errorf("attest-key: %w", &attestclient.StatusError{Status: http.StatusUnauthorized}), exitFailed},
		{"attest-key 500", fmt.Errorf("attest-key: %w", &attestclient.StatusError{Status: http.StatusInternalServerError}), exitUnavailable},
		{"deadline", context.DeadlineExceeded, exitUnavailable},
		{"protocol", errors.New("issuer handoff signature verification failed"), exitFailed},
	}
	for _, tc := range cases {
		if got := exitCodeFor(tc.err); got != tc.exit {
			t.Errorf("%s: exitCodeFor = %d, want %d", tc.name, got, tc.exit)
		}
	}
}

func TestNewCmdDefaults(t *testing.T) {
	cmd := NewCmd()
	for flag, want := range map[string]string{
		"expected-issuer": "cds",
		"timeout":         "2m0s",
		"log-level":       "info",
	} {
		f := cmd.Flags().Lookup(flag)
		if f == nil {
			t.Fatalf("flag --%s not registered", flag)
		}
		if f.DefValue != want {
			t.Errorf("--%s default = %q, want %q", flag, f.DefValue, want)
		}
	}
	for _, flag := range []string{"peer-url", "attestation-api-url", "measurements", "operator-keys"} {
		f := cmd.Flags().Lookup(flag)
		if f == nil {
			t.Fatalf("flag --%s not registered", flag)
		}
		if f.Annotations[cobra.BashCompOneRequiredFlag] == nil {
			t.Errorf("--%s is not marked required", flag)
		}
	}
}
