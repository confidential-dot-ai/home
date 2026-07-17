package requesthandoff

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
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

func TestReportForVerdict(t *testing.T) {
	ca := testCA(t, "handed-off-ca")
	other := testCA(t, "other-ca")
	digest, err := types.ParseDigest("sha256:" + strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	material := &issuer.HandoffMaterial{
		CACert:           ca.Cert,
		CAKey:            ca.Key,
		Bundle:           []*x509.Certificate{ca.Cert},
		AllowlistVersion: "7",
		Allowlist:        map[types.Digest]string{digest: "registry.example/dynamic:latest"},
	}

	rep, code := reportFor(material, []*x509.Certificate{other.Cert, ca.Cert})
	if !rep.ServedCAMatch || code != exitVerified {
		t.Fatalf("match: ServedCAMatch=%t code=%d, want true/%d", rep.ServedCAMatch, code, exitVerified)
	}
	if want := certutil.CertFingerprint(ca.Cert.Raw); rep.CACertFingerprintSHA256 != want {
		t.Fatalf("fingerprint = %s, want %s", rep.CACertFingerprintSHA256, want)
	}
	if rep.BundleCertCount != 1 {
		t.Fatalf("BundleCertCount = %d, want 1", rep.BundleCertCount)
	}
	if rep.AllowlistVersion != "7" || rep.AllowlistDigestCount != 1 {
		t.Fatalf("allowlist report = version %q count %d, want 7/1", rep.AllowlistVersion, rep.AllowlistDigestCount)
	}
	encoded, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"bundle_cert_count":1`)) {
		t.Fatalf("report JSON = %s, want bundle_cert_count", encoded)
	}
	if bytes.Contains(encoded, []byte(`"bundle_certs"`)) {
		t.Fatalf("report JSON retains ambiguous bundle_certs field: %s", encoded)
	}
	if !bytes.Contains(encoded, []byte(`"allowlist_version":"7"`)) || !bytes.Contains(encoded, []byte(`"allowlist_digest_count":1`)) {
		t.Fatalf("report JSON = %s, want allowlist snapshot summary", encoded)
	}

	rep, code = reportFor(material, []*x509.Certificate{other.Cert})
	if rep.ServedCAMatch || code != exitFailed {
		t.Fatalf("mismatch: ServedCAMatch=%t code=%d, want false/%d", rep.ServedCAMatch, code, exitFailed)
	}
}

func TestFetchServedCAStatusErrorIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rolling", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchServedCA(context.Background(), srv.Client(), srv.URL)
	var statusErr *issuer.HandoffStatusError
	if !errors.As(err, &statusErr) || statusErr.Status != http.StatusServiceUnavailable {
		t.Fatalf("fetchServedCA error = %v, want 503 *issuer.HandoffStatusError", err)
	}
	if got := exitCodeFor(err); got != exitUnavailable {
		t.Fatalf("exitCodeFor = %d, want %d (a 5xx from /ca is availability, not a verdict)", got, exitUnavailable)
	}
}

func TestRunRejectsNonPositiveTimeout(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), config{}, &out, &errOut); code != exitUsage {
		t.Fatalf("run with zero timeout = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "--timeout") {
		t.Fatalf("stderr %q does not mention --timeout", errOut.String())
	}
}

func TestErrorfStripsControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	errorf(&buf, "%s", "a\x1b[31mred\nb\tc")
	if got, want := buf.String(), "error: a[31mredbc\n"; got != want {
		t.Fatalf("errorf output = %q, want %q", got, want)
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
