package cds

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/earsigner"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const testOperatorKeysHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestCompilePattern(t *testing.T) {
	t.Run("empty returns nil", func(t *testing.T) {
		re, err := compilePattern("--x", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if re != nil {
			t.Fatalf("empty pattern should yield nil regexp, got %v", re)
		}
	})

	t.Run("valid compiles", func(t *testing.T) {
		re, err := compilePattern("--x", `^a.*z$`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if re == nil || !re.MatchString("abz") {
			t.Fatalf("expected compiled pattern matching abz, got %v", re)
		}
	})

	t.Run("invalid returns error", func(t *testing.T) {
		if _, err := compilePattern("--x", "("); err == nil {
			t.Fatal("expected error for invalid regex, got nil")
		}
	})
}

func TestCompilePatterns(t *testing.T) {
	t.Run("nil input yields nil slice", func(t *testing.T) {
		got, err := compilePatterns("--x", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil slice, got %v", got)
		}
	})

	t.Run("empties are skipped", func(t *testing.T) {
		got, err := compilePatterns("--x", []string{"", `^a$`, ""})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 compiled pattern (empties skipped), got %d", len(got))
		}
	})

	t.Run("propagates compile error", func(t *testing.T) {
		if _, err := compilePatterns("--x", []string{"["}); err == nil {
			t.Fatal("expected error for invalid regex in list, got nil")
		}
	})
}

func TestBuildHandoffHandler_DisabledWhenNoMeasurements(t *testing.T) {
	cfg := config{} // handoffMeasurements empty
	hh, err := buildHandoffHandler(
		context.Background(),
		cfg,
		nil,          // mesh unused on the disabled path
		nil,          // allowlist store unused on the disabled path
		"",           // operator policy unused on the disabled path
		nil,          // keyProvider unused
		ear.Issuer{}, // earIssuer unused on the disabled path
		attestationclient.NewClient(""),
	)
	if err != nil {
		t.Fatalf("unexpected error on disabled handoff: %v", err)
	}
	if hh != nil {
		t.Fatalf("expected nil handler when --handoff-measurements unset, got %v", hh)
	}
}

func TestBuildHandoffHandler_EnabledReturnsHandler(t *testing.T) {
	// Cancel the context up front so the background refresh/expiry goroutines
	// the enabled path spawns return immediately instead of leaking.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("ear key: %v", err)
	}
	earIss, err := ear.NewIssuer(keyPEM, "cds", time.Hour)
	if err != nil {
		t.Fatalf("ear issuer: %v", err)
	}
	rotator, err := earsigner.NewRotator(earsigner.RotatorConfig{}, keyPEM, earIss.SwapKey)
	if err != nil {
		t.Fatalf("rotator: %v", err)
	}
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := config{
		handoffMeasurements: []string{"deadbeef"},
		earIssuerName:       "cds",
	}
	hh, err := buildHandoffHandler(ctx, cfg, ca, &store, testOperatorKeysHash, rotator, earIss, attestationclient.NewClient(""))
	if err != nil {
		t.Fatalf("buildHandoffHandler: %v", err)
	}
	if hh == nil {
		t.Fatal("expected a non-nil handoff handler when measurements are set")
	}
}

func TestNormalizeHTTPServerConfig_FillsZeroDefaults(t *testing.T) {
	got := normalizeHTTPServerConfig(config{})
	if got.readTimeout != defaultHTTPReadTimeout {
		t.Errorf("readTimeout = %v, want %v", got.readTimeout, defaultHTTPReadTimeout)
	}
	if got.readHeaderTimeout != defaultHTTPReadHeaderTimeout {
		t.Errorf("readHeaderTimeout = %v, want %v", got.readHeaderTimeout, defaultHTTPReadHeaderTimeout)
	}
	if got.writeTimeout != defaultHTTPWriteTimeout {
		t.Errorf("writeTimeout = %v, want %v", got.writeTimeout, defaultHTTPWriteTimeout)
	}
	if got.idleTimeout != defaultHTTPIdleTimeout {
		t.Errorf("idleTimeout = %v, want %v", got.idleTimeout, defaultHTTPIdleTimeout)
	}
	if got.maxHeaderBytes != defaultHTTPMaxHeaderBytes {
		t.Errorf("maxHeaderBytes = %d, want %d", got.maxHeaderBytes, defaultHTTPMaxHeaderBytes)
	}
}

func TestNormalizeHTTPServerConfig_PreservesNonZero(t *testing.T) {
	in := config{
		readTimeout:       time.Second,
		readHeaderTimeout: 2 * time.Second,
		writeTimeout:      3 * time.Second,
		idleTimeout:       4 * time.Second,
		maxHeaderBytes:    99,
	}
	got := normalizeHTTPServerConfig(in)
	if got.readTimeout != in.readTimeout ||
		got.readHeaderTimeout != in.readHeaderTimeout ||
		got.writeTimeout != in.writeTimeout ||
		got.idleTimeout != in.idleTimeout ||
		got.maxHeaderBytes != in.maxHeaderBytes {
		t.Fatalf("normalizeHTTPServerConfig altered non-zero config: got %+v, want %+v", got, in)
	}
}

// caChainPEM has three branches: prefer CAChainPEM, fall back to CA.Cert, or
// return nil. The existing attest tests only exercise the first.
func TestAttestHandler_caChainPEM(t *testing.T) {
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}

	t.Run("prefers explicit CAChainPEM", func(t *testing.T) {
		h := AttestHandler{CAChainPEM: []byte("explicit"), CA: ca}
		if got := string(h.caChainPEM()); got != "explicit" {
			t.Fatalf("got %q, want explicit", got)
		}
	})

	t.Run("derives from CA cert when chain empty", func(t *testing.T) {
		h := AttestHandler{CA: ca}
		want := certutil.EncodeCertPEM(ca.Cert.Raw)
		if !bytes.Equal(h.caChainPEM(), want) {
			t.Fatal("derived chain does not match CA cert PEM")
		}
	})

	t.Run("nil when no chain and no CA", func(t *testing.T) {
		h := AttestHandler{}
		if got := h.caChainPEM(); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("nil when CA has nil cert", func(t *testing.T) {
		h := AttestHandler{CA: &issuer.CA{}}
		if got := h.caChainPEM(); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})
}

// Exercise the decode and challenge error paths the existing suite skips.
func TestAttest_RejectsUnknownJSONFields(t *testing.T) {
	mock := newMockAttestationApi(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)

	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader([]byte(`{"unknown":true}`)))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d, want 422; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsMalformedChallengeEncoding(t *testing.T) {
	mock := newMockAttestationApi(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	csrPEM, _ := generateCSR(t)

	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: "!!!not-base64!!!",
		Evidence:  types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		CSR:       csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsValidBase64UnknownChallenge(t *testing.T) {
	mock := newMockAttestationApi(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	csrPEM, _ := generateCSR(t)

	// Valid base64 but never issued, so Consume returns false.
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: "AAAAAAAAAAAAAAAAAAAAAA==",
		Evidence:  types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		CSR:       csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_MissingEARField(t *testing.T) {
	h, _, _ := newTestSignCSRHandler(t)
	csr, _ := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	w := postSignCSR(t, h, "", csr.Raw, time.Hour)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("missing 'ear'")) {
		t.Errorf("body should mention missing ear; got %s", w.Body.String())
	}
}

func TestSignCSR_MissingCSRField(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	earTok := signEAR(t, earKey, earClaimsLite{
		Issuer:   "cds",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(time.Minute).Unix(),
	})
	// Body with an EAR but a nil CSR DER.
	body := []byte(`{"ear":"` + earTok + `","csr":"","ttl":"1h"}`)
	req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSignCSR(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("missing 'csr'")) {
		t.Errorf("body should mention missing csr; got %s", w.Body.String())
	}
}

func TestSignCSR_InvalidTTLMessage(t *testing.T) {
	h, _, _ := newTestSignCSRHandler(t)
	body := []byte(`{"ear":"x","csr":"x","ttl":12345}`)
	req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSignCSR(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestNewRouter_PanicsOnZeroMaxRequestSize(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for zero MaxRequestSize")
		}
	}()
	newRouter(dependencies{RateLimiter: newTestRateLimiter(t), MaxRequestSize: 0})
}

func TestNewRouter_PanicsOnNilRateLimiter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil RateLimiter")
		}
	}()
	newRouter(dependencies{RateLimiter: nil, MaxRequestSize: 1})
}

// When a HandoffHandler is wired, /handoff is mounted and reachable (a malformed
// body proves the route exists rather than 404/405).
func TestRouter_HandoffMountedWhenConfigured(t *testing.T) {
	r := newStubRouterWithHandoff(t)
	req := httptest.NewRequest(http.MethodPost, "/handoff", bytes.NewReader([]byte(`{}`)))
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed {
		t.Fatalf("/handoff should be mounted: got %d", w.Code)
	}
}

func newStubRouterWithHandoff(t *testing.T) http.Handler {
	t.Helper()
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("ear key: %v", err)
	}
	earIss, err := ear.NewIssuer(keyPEM, "cds", time.Hour)
	if err != nil {
		t.Fatalf("ear issuer: %v", err)
	}
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	cs := attestation.NewChallengeStore(time.Minute)

	rotator, err := earsigner.NewRotator(earsigner.RotatorConfig{}, keyPEM, earIss.SwapKey)
	if err != nil {
		t.Fatalf("rotator: %v", err)
	}
	boot, err := issuer.NewLocalHandoffBootstrap(attestationclient.NewClient(""), earIss, testOperatorKeysHash)
	if err != nil {
		t.Fatalf("handoff bootstrap: %v", err)
	}
	hh, err := issuer.NewHandoffHandler(issuer.HandoffDeps{
		KeyProvider:         rotator,
		ExpectedIssuer:      "cds",
		AllowedMeasurements: map[string]bool{"deadbeef": true},
		OperatorKeysHash:    testOperatorKeysHash,
		Signer:              boot.Signer(),
		EARSource:           boot.EARSource(),
		Snapshot: func() (issuer.CASnapshot, bool) {
			version, digests, err := store.ListAll()
			if err != nil {
				return issuer.CASnapshot{}, false
			}
			return issuer.CASnapshot{Cert: ca.Cert, Key: ca.Key, AllowlistVersion: version, Allowlist: digests}, true
		},
	})
	if err != nil {
		t.Fatalf("handoff handler: %v", err)
	}

	deps := dependencies{
		AttestHandler:    AttestHandler{Challenges: &cs, CA: ca, CertTTL: time.Hour},
		AllowlistHandler: allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }},
		HandoffHandler:   hh,
		ReadyFn:          func() bool { return true },
		EarIssuer:        earIss,
		CACertPEM:        certutil.EncodeCertPEM(ca.Cert.Raw),
		RateLimiter:      newTestRateLimiter(t),
		MaxRequestSize:   65536,
	}
	return newRouter(deps)
}
