package allowlist_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/readiness"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/earsigner"
	"github.com/confidential-dot-ai/c8s/pkg/jwks"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/golang-jwt/jwt/v5"
)

const (
	digestA       = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	digestMissing = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	testIssuer    = "cds"
	measurementA  = "allowed-launch-digest"
)

// authHeader issues an EAR bound to body via the pbh claim and returns it as
// a Bearer header value. Callers MUST pass the exact bytes the server will
// receive — any difference (whitespace, key ordering) breaks verification.
func authHeader(t *testing.T, issuer ear.Issuer, measurement string, body []byte) string {
	t.Helper()
	token, err := issuer.IssueForRequestBody(json.RawMessage(`{"test":"evidence"}`), measurement, body)
	if err != nil {
		t.Fatalf("issue EAR: %v", err)
	}
	return "Bearer " + token
}

func signedEAR(t *testing.T, keyPEM []byte, claims jwt.MapClaims) string {
	t.Helper()
	key, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse EAR key: %v", err)
	}
	kid, err := jwks.Thumbprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("thumbprint EAR key: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign EAR: %v", err)
	}
	return signed
}

// keyProviderFor builds the production KeyProvider (an earsigner.Rotator) from
// a key PEM so tests verify tokens through the same kid-resolving path CDS uses.
func keyProviderFor(t *testing.T, keyPEM []byte) issuer.KeyProvider {
	t.Helper()
	rotator, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: time.Hour, Overlap: time.Hour, Logger: slog.Default(),
	}, keyPEM, func(*ecdsa.PrivateKey, string) {})
	if err != nil {
		t.Fatalf("new rotator: %v", err)
	}
	return rotator
}

func testAllowlistApp(t *testing.T) (http.Handler, *readiness.Checker, ear.Issuer) {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}

	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("generate EAR key: %v", err)
	}
	issuer, err := ear.NewIssuer(keyPEM, testIssuer, 5*time.Minute)
	if err != nil {
		t.Fatalf("new EAR issuer: %v", err)
	}

	asClient := attestationclient.NewClient("http://localhost:0")
	checker := readiness.NewChecker(asClient, 10*time.Second)

	wh := allowlist.Handler{
		Store: &store,
		WriteAuthorizer: allowlist.EARWriteAuthorizer{
			KeyProvider:         keyProviderFor(t, keyPEM),
			ExpectedIssuer:      testIssuer,
			AllowedMeasurements: map[string]bool{measurementA: true},
		}.Authorize,
	}

	return allowlistTestRouter(wh, checker.Ready), &checker, issuer
}

// allowlistTestRouter mounts only the routes the allowlist tests exercise, so
// these unit tests don't depend on the full server router.
func allowlistTestRouter(wh allowlist.Handler, ready attestation.ReadinessFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", attestation.HandleReadyz(ready))
	mux.HandleFunc("GET /allowlist", wh.HandleList)
	mux.HandleFunc("POST /allowlist", wh.HandleAdd)
	mux.HandleFunc("DELETE /allowlist", wh.HandleDelete)
	return mux
}

func TestHealthzReturnsOK(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
}

func TestReadyzReturnsUnavailableInitially(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want 503", resp.StatusCode)
	}
}

func TestAllowlistListEmpty(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/allowlist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var version string
	if err := json.Unmarshal(raw["version"], &version); err != nil {
		t.Fatalf("unmarshal version: %v", err)
	}
	if version != "1" {
		t.Fatalf("version = %q, want 1", version)
	}

	var digests map[string]string
	if err := json.Unmarshal(raw["digests"], &digests); err != nil {
		t.Fatalf("unmarshal digests: %v", err)
	}
	if len(digests) != 0 {
		t.Fatalf("expected empty digests, got %d entries", len(digests))
	}
}

func TestAllowlistAddRequiresAuth(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digest":"%s","image":"test-image"}`, digestA)
	resp, err := http.Post(srv.URL+"/allowlist", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func TestAllowlistAddRejectsUnauthorizedMeasurement(t *testing.T) {
	app, _, issuer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digest":"%s","image":"test-image"}`, digestA)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, issuer, "other-launch-digest", []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func TestAllowlistWriteAuthorizerRejectsMissingExpiration(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("generate EAR key: %v", err)
	}

	token := signedEAR(t, keyPEM, jwt.MapClaims{
		earclaims.Issuer:   testIssuer,
		earclaims.IssuedAt: time.Now().Unix(),
		earclaims.Submods: map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.LaunchDigest: measurementA,
			},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/allowlist", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err = (allowlist.EARWriteAuthorizer{
		KeyProvider:         keyProviderFor(t, keyPEM),
		ExpectedIssuer:      testIssuer,
		AllowedMeasurements: map[string]bool{measurementA: true},
	}).Authorize(req, nil)
	if err == nil {
		t.Fatal("expected missing expiration to be rejected")
	}
}

func TestAllowlistWriteAuthorizerRejectsExpiredToken(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("generate EAR key: %v", err)
	}

	token := signedEAR(t, keyPEM, jwt.MapClaims{
		earclaims.Issuer:    testIssuer,
		earclaims.IssuedAt:  time.Now().Add(-10 * time.Minute).Unix(),
		earclaims.ExpiresAt: time.Now().Add(-5 * time.Minute).Unix(),
		earclaims.Submods: map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.LaunchDigest: measurementA,
			},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/allowlist", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	err = (allowlist.EARWriteAuthorizer{
		KeyProvider:         keyProviderFor(t, keyPEM),
		ExpectedIssuer:      testIssuer,
		AllowedMeasurements: map[string]bool{measurementA: true},
	}).Authorize(req, nil)
	if err == nil {
		t.Fatal("expected expired EAR to be rejected")
	}
}

// TestAllowlistWriteAuthorizerAcceptsRetiringKey is the rotation-window
// regression guard: an EAR signed by the previous (now retiring) key must still
// authorize writes. The old hand-rolled authorizer resolved only the active
// key, so a token minted moments before a rotation failed. Routing through the
// rotator's kid-based KeyProvider fixes it.
func TestAllowlistWriteAuthorizerAcceptsRetiringKey(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("generate EAR key: %v", err)
	}
	// The issuer signs with the initial key's kid; after one rotation that kid
	// is retiring, not active.
	iss, err := ear.NewIssuer(keyPEM, testIssuer, 5*time.Minute)
	if err != nil {
		t.Fatalf("new EAR issuer: %v", err)
	}

	swapped := make(chan struct{}, 1)
	rotator, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: time.Millisecond,
		Overlap:  time.Hour, // keep the retiring key resolvable
		Logger:   slog.Default(),
	}, keyPEM, func(*ecdsa.PrivateKey, string) {
		select {
		case swapped <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("new rotator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rotator.Run(ctx)
	select {
	case <-swapped:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for key rotation")
	}
	cancel()

	body := []byte(`{"digest":"` + digestA + `","image":"retiring"}`)
	token, err := iss.IssueForRequestBody(json.RawMessage(`{"test":"evidence"}`), measurementA, body)
	if err != nil {
		t.Fatalf("issue EAR: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/allowlist", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	if err := (allowlist.EARWriteAuthorizer{
		KeyProvider:         rotator,
		ExpectedIssuer:      testIssuer,
		AllowedMeasurements: map[string]bool{measurementA: true},
	}).Authorize(req, body); err != nil {
		t.Fatalf("EAR signed by retiring key must still authorize: %v", err)
	}
}

func addDigest(t *testing.T, srvURL string, issuer ear.Issuer, digest, image string) {
	t.Helper()
	body := fmt.Sprintf(`{"digest":"%s","image":"%s"}`, digest, image)
	req, err := http.NewRequest(http.MethodPost, srvURL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, issuer, measurementA, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("add digest got status %d, want 204", resp.StatusCode)
	}
}

func TestAllowlistAddAndListRoundtrip(t *testing.T) {
	app, _, issuer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	addDigest(t, srv.URL, issuer, digestA, "test-image")

	resp, err := http.Get(srv.URL + "/allowlist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	var result types.AllowlistListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	expectedDigest, _ := types.ParseDigest(digestA)
	img, ok := result.Digests[expectedDigest]
	if !ok {
		t.Fatal("digest not found in allowlist")
	}
	if img != "test-image" {
		t.Fatalf("image = %q, want test-image", img)
	}

	// version should have been incremented from "1" to "2"
	if result.Version != "2" {
		t.Fatalf("version = %q, want 2", result.Version)
	}
}

func TestAllowlistDeleteExistingReturnsNoContent(t *testing.T) {
	app, _, issuer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	addDigest(t, srv.URL, issuer, digestA, "test-image")

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestA)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, issuer, measurementA, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("got status %d, want 204", resp.StatusCode)
	}

	// verify empty
	listResp, err := http.Get(srv.URL + "/allowlist")
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	defer listResp.Body.Close()

	var result types.AllowlistListResponse
	if err := json.NewDecoder(listResp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result.Digests) != 0 {
		t.Fatalf("expected empty digests, got %d", len(result.Digests))
	}
}

func TestAllowlistDeleteNonexistentReturnsNotFound(t *testing.T) {
	app, _, issuer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestMissing)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, issuer, measurementA, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got status %d, want 404", resp.StatusCode)
	}
}

func TestAllowlistDeleteRequiresAuth(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestA)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// no auth header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func TestAllowlistAddRejectsInvalidDigest(t *testing.T) {
	app, _, issuer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := `{"digest":"sha256:abc","image":"test-image"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, issuer, measurementA, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("got status %d, want 422", resp.StatusCode)
	}
}

// TestAllowlistAddRejectsReplayWithDifferentBody is the H2 regression test:
// a captured EAR for one body MUST NOT authorize a different body within the
// EAR's TTL.
func TestAllowlistAddRejectsReplayWithDifferentBody(t *testing.T) {
	app, _, issuer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	// Token is bound to the legitimate digestA body.
	originalBody := fmt.Sprintf(`{"digest":"%s","image":"trusted-image"}`, digestA)
	header := authHeader(t, issuer, measurementA, []byte(originalBody))

	// Attacker replays the same token but ships a different digest.
	attackerBody := fmt.Sprintf(`{"digest":"%s","image":"attacker-image"}`, digestMissing)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist", strings.NewReader(attackerBody))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", header)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("captured token authorized a different body: got status %d, want 401", resp.StatusCode)
	}
}

// TestAllowlistAddRejectsTokenWithoutBodyHash confirms that the body-binding
// claim is REQUIRED — a token issued without `pbh` (e.g. by older callers
// that didn't use IssueForRequestBody) is rejected, not silently accepted.
func TestAllowlistAddRejectsTokenWithoutBodyHash(t *testing.T) {
	app, _, issuer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	// IssueWithLaunchDigest produces a token without the pbh claim.
	token, err := issuer.IssueWithLaunchDigest(json.RawMessage(`{"test":"evidence"}`), measurementA)
	if err != nil {
		t.Fatalf("issue EAR: %v", err)
	}

	body := fmt.Sprintf(`{"digest":"%s","image":"test-image"}`, digestA)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token without pbh claim was accepted: got status %d, want 401", resp.StatusCode)
	}
}

// TestAllowlistAddRejectsBodyOverConfiguredCap confirms the per-Handler cap
// is honoured: an over-cap body returns 413 *before* the auth check runs
// (so the handler doesn't burn CPU hashing megabytes a malicious caller
// supplied).
func TestAllowlistAddRejectsBodyOverConfiguredCap(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("generate EAR key: %v", err)
	}
	issuer, err := ear.NewIssuer(keyPEM, testIssuer, 5*time.Minute)
	if err != nil {
		t.Fatalf("new EAR issuer: %v", err)
	}
	asClient := attestationclient.NewClient("http://localhost:0")
	checker := readiness.NewChecker(asClient, 10*time.Second)
	wh := allowlist.Handler{
		Store: &store,
		WriteAuthorizer: allowlist.EARWriteAuthorizer{
			KeyProvider:         keyProviderFor(t, keyPEM),
			ExpectedIssuer:      testIssuer,
			AllowedMeasurements: map[string]bool{measurementA: true},
		}.Authorize,
		MaxWriteBodyBytes: 64,
	}
	srv := httptest.NewServer(allowlistTestRouter(wh, checker.Ready))
	defer srv.Close()

	body := strings.Repeat("x", 1024)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, issuer, measurementA, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap body got status %d, want 413", resp.StatusCode)
	}
}

func TestAllowlistListEmitsETag(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/allowlist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != `W/"1"` {
		t.Fatalf("ETag = %q, want W/\"1\"", got)
	}
}

func TestAllowlistListMatchingIfNoneMatchReturns304(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/allowlist", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("If-None-Match", `W/"1"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != `W/"1"` {
		t.Fatalf("ETag = %q, want W/\"1\"", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("304 body should be empty, got %d bytes", len(body))
	}
}

func TestAllowlistListStaleIfNoneMatchReturns200WithNewETag(t *testing.T) {
	app, _, issuer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	addDigest(t, srv.URL, issuer, digestA, "test-image")

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/allowlist", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("If-None-Match", `W/"1"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != `W/"2"` {
		t.Fatalf("ETag = %q, want W/\"2\"", got)
	}
}
