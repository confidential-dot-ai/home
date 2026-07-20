package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/time/rate"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- CertKeyProvider ---

func TestNewCertKeyProvider(t *testing.T) {
	ca, err := issuer.NewCA("kp", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	p, err := issuer.NewCertKeyProvider(ca.Cert)
	if err != nil {
		t.Fatalf("NewCertKeyProvider: %v", err)
	}
	// kid is ignored for the cert-pinned provider.
	got, err := p.PublicKey("anything")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !got.Equal(ca.Key.Public()) {
		t.Error("returned public key does not match CA key")
	}
}

func TestNewCertKeyProviderRejectsNonECDSA(t *testing.T) {
	// A leaf cert built around a non-ECDSA key is overkill; instead craft a
	// cert whose PublicKey is replaced with a non-ECDSA type.
	ca, err := issuer.NewCA("kp", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	bad := *ca.Cert
	bad.PublicKey = "not-a-key"
	if _, err := issuer.NewCertKeyProvider(&bad); err == nil {
		t.Fatal("expected error for non-ECDSA cert public key")
	}
}

// --- JWKSKeyProvider ---

func jwksServer(t *testing.T, kid string, pub *ecdsa.PublicKey) *httptest.Server {
	t.Helper()
	key, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	if kid != "" {
		if err := key.Set(jwk.KeyIDKey, kid); err != nil {
			t.Fatalf("set kid: %v", err)
		}
	}
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		t.Fatalf("add key: %v", err)
	}
	buf, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal set: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf)
	}))
}

func TestJWKSKeyProviderResolvesKid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := jwksServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	p, err := issuer.NewJWKSKeyProvider(context.Background(), srv.URL, time.Minute, srv.Client(), discardLogger())
	if err != nil {
		t.Fatalf("NewJWKSKeyProvider: %v", err)
	}
	got, err := p.PublicKey("kid-1")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !got.Equal(&key.PublicKey) {
		t.Error("resolved key does not match server key")
	}
}

func TestJWKSKeyProviderRejectsEmptyKid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := jwksServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	p, err := issuer.NewJWKSKeyProvider(context.Background(), srv.URL, time.Minute, srv.Client(), discardLogger())
	if err != nil {
		t.Fatalf("NewJWKSKeyProvider: %v", err)
	}
	if _, err := p.PublicKey(""); err == nil {
		t.Fatal("expected empty kid to be rejected")
	}
}

func TestJWKSKeyProviderKidMiss(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := jwksServer(t, "kid-1", &key.PublicKey)
	defer srv.Close()

	p, err := issuer.NewJWKSKeyProvider(context.Background(), srv.URL, time.Minute, srv.Client(), discardLogger())
	if err != nil {
		t.Fatalf("NewJWKSKeyProvider: %v", err)
	}
	// First miss triggers a force-refresh which still won't find the kid.
	if _, err := p.PublicKey("missing-kid"); err == nil {
		t.Fatal("expected kid miss to error")
	}
	// Second miss within a second is refresh rate-limited.
	if _, err := p.PublicKey("missing-kid"); err == nil {
		t.Fatal("expected rate-limited kid miss to error")
	}
}

func TestNewJWKSKeyProviderInitialFetchFailureDoesNotError(t *testing.T) {
	// A server that 500s: initial fetch fails but constructor still succeeds
	// (it logs a warning and retries lazily).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p, err := issuer.NewJWKSKeyProvider(context.Background(), srv.URL, time.Minute, srv.Client(), discardLogger())
	if err != nil {
		t.Fatalf("NewJWKSKeyProvider should tolerate initial fetch failure: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

// --- NodeTracker ---

func TestNodeTrackerTrackAndUpdateMetrics(t *testing.T) {
	nt := issuer.NewNodeTracker(time.Hour)
	nt.Track("10.0.0.1", time.Now().Add(2*time.Hour))
	nt.Track("10.0.0.2", time.Now().Add(3*time.Hour))
	// Should not panic and should retain fresh entries.
	nt.UpdateMetrics()

	// Empty tracker path.
	empty := issuer.NewNodeTracker(time.Hour)
	empty.UpdateMetrics()
}

func TestNodeTrackerRunUpdaterStopsOnCancel(t *testing.T) {
	nt := issuer.NewNodeTracker(time.Hour)
	nt.Track("10.0.0.1", time.Now().Add(time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		nt.RunUpdater(ctx, time.Millisecond)
		close(done)
	}()
	// Let it tick at least once, then cancel.
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunUpdater did not return after cancel")
	}
}

// --- RateLimitMiddleware ---

func TestRateLimitMiddlewareAllowsThenRejects(t *testing.T) {
	// burst=1, rate=0 -> first request allowed, second rejected.
	rl, err := issuer.NewIPRateLimiter(rate.Limit(0), 1, 10)
	if err != nil {
		t.Fatalf("NewIPRateLimiter: %v", err)
	}
	var served int
	h := issuer.RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	h.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first request: code = %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, req)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: code = %d, want 429", second.Code)
	}
	if served != 1 {
		t.Fatalf("handler served %d times, want 1", served)
	}
}

func TestRateLimitMiddlewareHandlesPortlessRemoteAddr(t *testing.T) {
	rl, err := issuer.NewIPRateLimiter(rate.Limit(100), 10, 10)
	if err != nil {
		t.Fatalf("NewIPRateLimiter: %v", err)
	}
	h := issuer.RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "/run/cds.sock" // no host:port
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestIPRateLimiterEvictionLoopStopsOnCancel(t *testing.T) {
	rl, err := issuer.NewIPRateLimiter(rate.Limit(100), 10, 10)
	if err != nil {
		t.Fatalf("NewIPRateLimiter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rl.EvictionLoop(ctx, time.Millisecond, time.Millisecond)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("EvictionLoop did not return after cancel")
	}
}

// --- CARotator ---

func TestNewCARotatorValidatesDeps(t *testing.T) {
	if _, err := issuer.NewCARotator(issuer.CARotatorDeps{}); err == nil {
		t.Error("missing Snapshot: expected error")
	}
	if _, err := issuer.NewCARotator(issuer.CARotatorDeps{
		Snapshot: func() (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, bool) {
			return nil, nil, nil, false
		},
	}); err == nil {
		t.Error("missing CommitRotation: expected error")
	}
}

func TestCARotatorRotateCANoBundle(t *testing.T) {
	cr, err := issuer.NewCARotator(issuer.CARotatorDeps{
		Snapshot: func() (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, bool) {
			return nil, nil, nil, false
		},
		CommitRotation: func(*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) string {
			return ""
		},
	})
	if err != nil {
		t.Fatalf("NewCARotator: %v", err)
	}
	if _, _, err := cr.RotateCA(); !errors.Is(err, issuer.ErrNoCertificateBundle) {
		t.Fatalf("RotateCA err = %v, want ErrNoCertificateBundle", err)
	}
}

func TestCARotatorRotateCACommits(t *testing.T) {
	ca, err := issuer.NewCA("parent", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	var committed bool
	var newCertSeen *x509.Certificate
	cr, err := issuer.NewCARotator(issuer.CARotatorDeps{
		CACertValidity: time.Hour,
		CACommonName:   "rotated ca",
		Snapshot: func() (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, bool) {
			return ca.Cert, ca.Key, ca.Cert, true
		},
		CommitRotation: func(newCert *x509.Certificate, _ *ecdsa.PrivateKey, _ *x509.Certificate, parent *x509.Certificate) string {
			committed = true
			newCertSeen = newCert
			if !parent.Equal(ca.Cert) {
				t.Error("parent passed to CommitRotation is not the snapshot CA")
			}
			return "fp-123"
		},
	})
	if err != nil {
		t.Fatalf("NewCARotator: %v", err)
	}
	newCert, fp, err := cr.RotateCA()
	if err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	if !committed {
		t.Error("CommitRotation was not invoked")
	}
	if fp != "fp-123" {
		t.Errorf("fingerprint = %q, want fp-123", fp)
	}
	if newCert.Subject.CommonName != "rotated ca" {
		t.Errorf("new CA CN = %q, want rotated ca", newCert.Subject.CommonName)
	}
	if newCertSeen == nil || !newCertSeen.Equal(newCert) {
		t.Error("CommitRotation received a different cert than returned")
	}
	// New CA must chain to the parent.
	if err := newCert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("rotated CA not signed by parent: %v", err)
	}
}

func TestCARotatorRunNoopOnNonPositiveInterval(t *testing.T) {
	cr, err := issuer.NewCARotator(issuer.CARotatorDeps{
		Snapshot: func() (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, bool) {
			return nil, nil, nil, false
		},
		CommitRotation: func(*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) string {
			return ""
		},
	})
	if err != nil {
		t.Fatalf("NewCARotator: %v", err)
	}
	// interval <= 0 returns immediately.
	cr.Run(context.Background(), 0)
}

// --- EARClaims getters ---

func TestEARClaimsGetters(t *testing.T) {
	c := issuer.EARClaims{Issuer: "cds"}
	if sub, err := c.GetSubject(); err != nil || sub != "" {
		t.Errorf("GetSubject() = %q, %v; want \"\", nil", sub, err)
	}
	aud, err := c.GetAudience()
	if err != nil {
		t.Fatalf("GetAudience: %v", err)
	}
	if len(aud) != 0 {
		t.Errorf("GetAudience() = %v, want empty", aud)
	}
	iss, err := c.GetIssuer()
	if err != nil || iss != "cds" {
		t.Errorf("GetIssuer() = %q, %v; want cds, nil", iss, err)
	}
}

func TestEARClaimsUnmarshalInvalidJSON(t *testing.T) {
	var c issuer.EARClaims
	if err := json.Unmarshal([]byte("not json"), &c); err == nil {
		t.Fatal("expected error unmarshaling invalid JSON into EARClaims")
	}
}

// --- ValidateEARToken further paths ---

func TestValidateEARTokenRequiresProvider(t *testing.T) {
	_, err := issuer.ValidateEARToken("x.y.z", nil, "cds")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonInvalidSignature {
		t.Errorf("reason = %q, want invalid_signature", ve.Reason)
	}
}

func TestValidateEARTokenMalformedToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, err = issuer.ValidateEARToken("garbage", testKeyProvider{pub: &key.PublicKey}, "cds")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonMalformed {
		t.Errorf("reason = %q, want malformed", ve.Reason)
	}
}

func TestValidateEARTokenExpired(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	past := time.Now().Add(-time.Hour).Unix()
	claims := validEARClaims(past)
	claims[earclaims.ExpiresAt] = past + 1 // already expired (beyond skew)
	token := signEARJWT(t, key, claims)

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonExpired {
		t.Errorf("reason = %q, want expired", ve.Reason)
	}
}

func TestValidateEARTokenWrongIssuer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().Unix()
	claims := validEARClaims(now)
	claims[earclaims.Issuer] = "someone-else"
	token := signEARJWT(t, key, claims)

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonInvalidIssuer {
		t.Errorf("reason = %q, want invalid_issuer", ve.Reason)
	}
}

func TestValidateEARTokenWrongSigningKey(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	now := time.Now().Unix()
	token := signEARJWT(t, signingKey, validEARClaims(now))

	// Provider returns a different key, so the signature does not verify.
	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &otherKey.PublicKey}, "cds")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonInvalidSignature {
		t.Errorf("reason = %q, want invalid_signature", ve.Reason)
	}
}

func TestValidateEARTokenProviderError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().Unix()
	token := signEARJWT(t, key, validEARClaims(now))

	_, err = issuer.ValidateEARToken(token, erroringKeyProvider{}, "cds")
	if err == nil {
		t.Fatal("expected error when provider cannot resolve key")
	}
}

type erroringKeyProvider struct{}

func (erroringKeyProvider) PublicKey(string) (*ecdsa.PublicKey, error) {
	return nil, errors.New("no key")
}

// --- VerifyKeyBinding success + error paths ---

func TestVerifyKeyBindingSuccess(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	claims := &issuer.EARClaims{TEEPubKey: base64.RawURLEncoding.EncodeToString(pubDER)}
	if err := issuer.VerifyKeyBinding(csr, claims); err != nil {
		t.Fatalf("VerifyKeyBinding: %v", err)
	}
}

func TestVerifyKeyBindingMissingClaim(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := issuer.VerifyKeyBinding(csr, &issuer.EARClaims{}); err == nil {
		t.Fatal("expected error for missing TEEPubKey claim")
	}
}

func TestVerifyKeyBindingBadBase64(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := issuer.VerifyKeyBinding(csr, &issuer.EARClaims{TEEPubKey: "!!!not-base64!!!"}); err == nil {
		t.Fatal("expected error for non-base64 TEEPubKey")
	}
}

func TestVerifyKeyBindingDifferentKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	// A different key of identical DER length -> bytes.Equal fails.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	otherDER, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatalf("marshal other: %v", err)
	}
	err = issuer.VerifyKeyBinding(csr, &issuer.EARClaims{TEEPubKey: base64.RawURLEncoding.EncodeToString(otherDER)})
	if err == nil || !strings.Contains(err.Error(), "does not match TEE-attested key") {
		t.Fatalf("err = %v, want mismatch", err)
	}
}

// --- CheckMeasurement error paths ---

func TestCheckMeasurementEmptyAllowlistPasses(t *testing.T) {
	claims := &issuer.EARClaims{}
	if err := issuer.CheckMeasurement(claims, nil, "ep"); err != nil {
		t.Fatalf("empty allowlist should pass: %v", err)
	}
}

func TestCheckMeasurementNotAllowed(t *testing.T) {
	rawEvidence, err := json.Marshal(map[string]any{
		earclaims.SubmodAttester: map[string]any{
			earclaims.LaunchDigest: "abc123",
		},
	})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	claims := &issuer.EARClaims{RawEvidence: rawEvidence}
	err = issuer.CheckMeasurement(claims, map[string]bool{"deadbeef": true}, "sign-csr")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonMeasurementDenied {
		t.Errorf("reason = %q, want measurement_denied", ve.Reason)
	}
}

func TestCheckMeasurementExtractFailure(t *testing.T) {
	// RawEvidence without a launch digest -> extraction fails.
	claims := &issuer.EARClaims{RawEvidence: json.RawMessage(`{}`)}
	err := issuer.CheckMeasurement(claims, map[string]bool{"x": true}, "sign-csr")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonMeasurementDenied {
		t.Errorf("reason = %q, want measurement_denied", ve.Reason)
	}
}

func TestNormalizeMeasurement(t *testing.T) {
	if got := issuer.NormalizeMeasurement("  DEADbeef \n"); got != "deadbeef" {
		t.Errorf("NormalizeMeasurement = %q, want deadbeef", got)
	}
}

// --- ValidateCAKeyPair ---

func TestValidateCAKeyPair(t *testing.T) {
	ca, err := issuer.NewCA("handoff ca", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	other, err := issuer.NewCA("other ca", time.Hour)
	if err != nil {
		t.Fatalf("NewCA other: %v", err)
	}

	if err := issuer.ValidateCAKeyPair(ca.Cert, ca.Key); err != nil {
		t.Fatalf("valid CA keypair: unexpected error %v", err)
	}
	if err := issuer.ValidateCAKeyPair(nil, ca.Key); err == nil {
		t.Error("nil cert: expected error")
	}
	if err := issuer.ValidateCAKeyPair(ca.Cert, nil); err == nil {
		t.Error("nil key: expected error")
	}
	if err := issuer.ValidateCAKeyPair(ca.Cert, other.Key); err == nil {
		t.Error("mismatched key: expected error")
	}

	expired := *ca.Cert
	expired.NotBefore = time.Now().Add(-2 * time.Hour)
	expired.NotAfter = time.Now().Add(-time.Hour)
	if err := issuer.ValidateCAKeyPair(&expired, ca.Key); err == nil {
		t.Error("expired cert: expected error")
	}

	notCA := *ca.Cert
	notCA.IsCA = false
	if err := issuer.ValidateCAKeyPair(&notCA, ca.Key); err == nil {
		t.Error("non-CA cert: expected error")
	}

	noCertSign := *ca.Cert
	noCertSign.KeyUsage = x509.KeyUsageDigitalSignature
	if err := issuer.ValidateCAKeyPair(&noCertSign, ca.Key); err == nil {
		t.Error("cert without cert-sign usage: expected error")
	}
}

// --- TokenValidationError Error/Unwrap ---

func TestTokenValidationErrorErrorAndUnwrap(t *testing.T) {
	inner := errors.New("inner failure")
	e := &issuer.TokenValidationError{Reason: issuer.ReasonExpired, Err: inner}
	if e.Error() != "inner failure" {
		t.Errorf("Error() = %q, want inner failure", e.Error())
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap should expose the wrapped error")
	}
}
