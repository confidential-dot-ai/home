package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// fakeAttestKeyClient mints an EAR bound to the pubkey PullHandoff generated,
// standing in for the network /attest-key flow.
type fakeAttestKeyClient struct {
	t           *testing.T
	tokenKey    *ecdsa.PrivateKey
	measurement string
}

func (f *fakeAttestKeyClient) AttestKeyWithOperatorKeysHash(_ context.Context, _ string, pubKeyDER []byte, operatorKeysHash string) (string, error) {
	f.t.Helper()
	now := time.Now().Unix()
	return signJWT(f.t, f.tokenKey, map[string]any{
		earclaims.IssuedAt:         now,
		earclaims.ExpiresAt:        now + 3600,
		earclaims.TEEPublicKey:     base64.RawURLEncoding.EncodeToString(pubKeyDER),
		earclaims.OperatorKeysHash: operatorKeysHash,
		earclaims.Submods: map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.LaunchDigest: f.measurement,
			},
		},
	}), nil
}

func pullTestHandoffServer(t *testing.T, tokenKey *ecdsa.PrivateKey, allowed map[string]bool) (*httptest.Server, *CA) {
	t.Helper()
	ca, err := NewCAWithCurve("Pull Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	activeHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         testKeyProvider{pub: &tokenKey.PublicKey},
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)
	return srv, ca
}

func TestPullHandoffTransfersCA(t *testing.T) {
	tokenKey := handoffTestKey(t)
	allowed := map[string]bool{"allowed_measurement": true}
	srv, ca := pullTestHandoffServer(t, tokenKey, allowed)

	deps := HandoffClientDeps{
		KeyProvider:         testKeyProvider{pub: &tokenKey.PublicKey},
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
	}
	attest := &fakeAttestKeyClient{t: t, tokenKey: tokenKey, measurement: "allowed_measurement"}
	material, err := PullHandoff(context.Background(), PullConfig{
		Deps:              deps,
		Attest:            attest,
		PeerURL:           srv.URL,
		AttestationApiURL: "http://unused",
		HTTPClient:        srv.Client(),
	})
	if err != nil {
		t.Fatalf("PullHandoff: %v", err)
	}
	if got, want := certutil.CertFingerprint(material.CACert.Raw), certutil.CertFingerprint(ca.Cert.Raw); got != want {
		t.Fatalf("pulled CA fingerprint = %s, want %s", got, want)
	}
	if !material.CAKey.PublicKey.Equal(&ca.Key.PublicKey) {
		t.Fatal("pulled CA key does not match active key")
	}
}

// countingHandoffProxy fronts srv, invoking reject for the first n /handoff
// calls (to simulate transient failures) and proxying the rest. It reports
// how many /handoff calls it saw.
func countingHandoffProxy(t *testing.T, srv *httptest.Server, reject func(w http.ResponseWriter) bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/handoff" {
			calls.Add(1)
			if reject(w) {
				return
			}
		}
		resp, err := srv.Client().Post(srv.URL+r.URL.Path, r.Header.Get("Content-Type"), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(front.Close)
	return front, &calls
}

func TestPullHandoffRetriesTransientThenSucceeds(t *testing.T) {
	tokenKey := handoffTestKey(t)
	allowed := map[string]bool{"allowed_measurement": true}
	srv, _ := pullTestHandoffServer(t, tokenKey, allowed)

	// First two /handoff calls 503 (peer bootstrapping); then proxy through.
	var seen atomic.Int32
	front, calls := countingHandoffProxy(t, srv, func(w http.ResponseWriter) bool {
		if seen.Add(1) <= 2 {
			http.Error(w, "bootstrapping", http.StatusServiceUnavailable)
			return true
		}
		return false
	})

	deps := HandoffClientDeps{
		KeyProvider:         testKeyProvider{pub: &tokenKey.PublicKey},
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
	}
	attest := &fakeAttestKeyClient{t: t, tokenKey: tokenKey, measurement: "allowed_measurement"}
	material, err := PullHandoff(context.Background(), PullConfig{
		Deps:              deps,
		Attest:            attest,
		PeerURL:           front.URL,
		AttestationApiURL: "http://unused",
		HTTPClient:        front.Client(),
		RetryInterval:     time.Millisecond,
	})
	if err != nil {
		t.Fatalf("PullHandoff: %v", err)
	}
	if material == nil || material.CACert == nil {
		t.Fatal("PullHandoff returned no material after retries")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("handoff endpoint calls = %d, want 3 (two 503s + success)", got)
	}
}

func TestPullHandoffFailsFastOnDefinitiveVerdict(t *testing.T) {
	tokenKey := handoffTestKey(t)
	// Server allows only a measurement the requester does not have: 403.
	srv, _ := pullTestHandoffServer(t, tokenKey, map[string]bool{"other_measurement": true})
	// Proxy that never injects, only counts, so a retry would show as >1 call.
	front, calls := countingHandoffProxy(t, srv, func(http.ResponseWriter) bool { return false })

	deps := HandoffClientDeps{
		KeyProvider:         testKeyProvider{pub: &tokenKey.PublicKey},
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
	}
	attest := &fakeAttestKeyClient{t: t, tokenKey: tokenKey, measurement: "allowed_measurement"}
	_, err := PullHandoff(context.Background(), PullConfig{
		Deps:              deps,
		Attest:            attest,
		PeerURL:           front.URL,
		AttestationApiURL: "http://unused",
		HTTPClient:        front.Client(),
		RetryInterval:     time.Millisecond,
	})
	var statusErr *HandoffStatusError
	if !errors.As(err, &statusErr) || statusErr.Status != http.StatusForbidden {
		t.Fatalf("PullHandoff error = %v, want 403 *HandoffStatusError", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("handoff endpoint calls = %d; a 403 must fail fast, not retry", got)
	}
}

func TestClassifyPullError(t *testing.T) {
	certErr := &url.Error{Op: "Get", URL: "https://peer", Err: &tls.CertificateVerificationError{Err: errors.New("measurement not allowed")}}
	cases := []struct {
		name string
		err  error
		want PullOutcome
	}{
		{"nil", nil, PullOK},
		{"handoff 503", &HandoffStatusError{Status: http.StatusServiceUnavailable}, PullTransient},
		{"handoff 429", &HandoffStatusError{Status: http.StatusTooManyRequests}, PullTransient},
		{"handoff 403", &HandoffStatusError{Status: http.StatusForbidden}, PullFatal},
		{"handoff 404", &HandoffStatusError{Status: http.StatusNotFound}, PullDisabled},
		{"attest-key 500 wrapped", fmt.Errorf("attest-key: %w", &attestclient.StatusError{Status: http.StatusInternalServerError}), PullTransient},
		{"attest-key 401 wrapped", fmt.Errorf("attest-key: %w", &attestclient.StatusError{Status: http.StatusUnauthorized}), PullFatal},
		{"attestation-api APIError 500", fmt.Errorf("attest-key: %w", &attestationclient.APIError{Status: http.StatusInternalServerError}), PullTransient},
		{"attestation-api 429", fmt.Errorf("attest-key: %w", &attestationclient.APIError{Status: http.StatusTooManyRequests}), PullTransient},
		{"attestation-api unexpected 502", fmt.Errorf("attest-key: %w", &attestationclient.UnexpectedError{Status: http.StatusBadGateway}), PullTransient},
		{"ratls denial", certErr, PullDenied},
		{"transport error", &url.Error{Op: "Post", URL: "https://peer", Err: errors.New("connection refused")}, PullTransient},
		{"deadline", context.DeadlineExceeded, PullTransient},
		{"other", errors.New("marshal failed"), PullFatal},
	}
	for _, tc := range cases {
		if got := ClassifyPullError(tc.err); got != tc.want {
			t.Errorf("%s: ClassifyPullError = %d, want %d", tc.name, got, tc.want)
		}
	}
}
