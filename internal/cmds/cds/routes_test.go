package cds

import (
	"bytes"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/earsigner"
	"golang.org/x/time/rate"
)

func newStubRouter(t *testing.T) http.Handler {
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
	deps := dependencies{
		AttestHandler:    AttestHandler{Challenges: &cs, CA: ca, CertTTL: time.Hour},
		AllowlistHandler: allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }},
		ReadyFn:          func() bool { return true },
		EarIssuer:        earIss,
		CACertPEM:        certutil.EncodeCertPEM(ca.Cert.Raw),
		RateLimiter:      newTestRateLimiter(t),
		MaxRequestSize:   65536,
	}
	return newRouter(deps)
}

func TestRouter_RateLimitsAttestationEndpoints(t *testing.T) {
	keyPEM, _ := earsigner.Generate()
	earIss, _ := ear.NewIssuer(keyPEM, "cds", time.Hour)
	store, _ := allowlist.OpenInMemory()
	t.Cleanup(func() { _ = store.Close() })
	ca, _ := issuer.NewCA("test ca", time.Hour)
	cs := attestation.NewChallengeStore(time.Minute)
	// Burst of 1, so the second request from the same source IP is rejected.
	rl, err := issuer.NewIPRateLimiter(rate.Limit(1), 1, 100)
	if err != nil {
		t.Fatalf("rate limiter: %v", err)
	}
	deps := dependencies{
		AttestHandler:    AttestHandler{Challenges: &cs, CA: ca, CertTTL: time.Hour},
		AllowlistHandler: allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }},
		ReadyFn:          func() bool { return true },
		EarIssuer:        earIss,
		CACertPEM:        certutil.EncodeCertPEM(ca.Cert.Raw),
		RateLimiter:      rl,
		MaxRequestSize:   65536,
	}
	r := newRouter(deps)

	do := func() int {
		req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader([]byte(`{}`)))
		req.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if got := do(); got == http.StatusTooManyRequests {
		t.Fatalf("first request rate-limited unexpectedly: %d", got)
	}
	if got := do(); got != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", got)
	}
}

func newTestRateLimiter(t *testing.T) *issuer.IPRateLimiter {
	t.Helper()
	rl, err := issuer.NewIPRateLimiter(rate.Limit(1000), 1000, 1000)
	if err != nil {
		t.Fatalf("rate limiter: %v", err)
	}
	return rl
}

func TestRouter_RoutesMountedWithExpectedMethods(t *testing.T) {
	cases := []struct {
		method, path string
		wantStatus   int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/readyz", http.StatusOK},
		{http.MethodGet, "/.well-known/jwks.json", http.StatusOK},
		{http.MethodGet, "/metrics", http.StatusOK},
		{http.MethodGet, "/ca", http.StatusOK},
		{http.MethodGet, "/allowlist", http.StatusOK},
		{http.MethodGet, "/does-not-exist", http.StatusNotFound},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
	}

	r := newStubRouter(t)
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Errorf("status: got %d, want %d; body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

func TestRouter_HandoffMountedOnlyWhenConfigured(t *testing.T) {
	// Stub router is built without a HandoffHandler, so /handoff is absent.
	r := newStubRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/handoff", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("/handoff without --handoff-measurements: got %d, want 404", w.Code)
	}
}

func TestRouter_AttestKeyMounted(t *testing.T) {
	// /attest-key is always mounted; an empty body is rejected as a bad request,
	// proving the route exists (a missing route would 404, a wrong method 405).
	r := newStubRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/attest-key", bytes.NewReader([]byte(`{}`)))
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed {
		t.Fatalf("/attest-key not mounted: got %d", w.Code)
	}
}

func TestRouter_AttestRejectsOversizedBody(t *testing.T) {
	keyPEM, _ := earsigner.Generate()
	earIss, _ := ear.NewIssuer(keyPEM, "cds", time.Hour)
	store, _ := allowlist.OpenInMemory()
	t.Cleanup(func() { _ = store.Close() })
	ca, _ := issuer.NewCA("test ca", time.Hour)
	cs := attestation.NewChallengeStore(time.Minute)
	deps := dependencies{
		AttestHandler:    AttestHandler{Challenges: &cs, CA: ca, CertTTL: time.Hour},
		AllowlistHandler: allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }},
		ReadyFn:          func() bool { return true },
		EarIssuer:        earIss,
		CACertPEM:        certutil.EncodeCertPEM(ca.Cert.Raw),
		RateLimiter:      newTestRateLimiter(t),
		MaxRequestSize:   16,
	}
	r := newRouter(deps)

	body := make([]byte, 1024)
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("oversized body should be rejected; got %d", w.Code)
	}
}

func TestRouter_CAEndpointReturnsLoadedCert(t *testing.T) {
	r := newStubRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/ca", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("content-type: got %q", ct)
	}
	if _, err := certutil.ParseCertificatePEM(w.Body.Bytes()); err != nil {
		t.Errorf("body is not a parseable cert: %v", err)
	}
}

func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	defaultSrv := newHTTPServer(":0", http.NewServeMux(), config{})
	if defaultSrv.ReadTimeout != defaultHTTPReadTimeout {
		t.Errorf("default ReadTimeout = %v, want %v", defaultSrv.ReadTimeout, defaultHTTPReadTimeout)
	}
	if defaultSrv.ReadHeaderTimeout != defaultHTTPReadHeaderTimeout {
		t.Errorf("default ReadHeaderTimeout = %v, want %v", defaultSrv.ReadHeaderTimeout, defaultHTTPReadHeaderTimeout)
	}
	if defaultSrv.WriteTimeout != defaultHTTPWriteTimeout {
		t.Errorf("default WriteTimeout = %v, want %v", defaultSrv.WriteTimeout, defaultHTTPWriteTimeout)
	}
	if defaultSrv.IdleTimeout != defaultHTTPIdleTimeout {
		t.Errorf("default IdleTimeout = %v, want %v", defaultSrv.IdleTimeout, defaultHTTPIdleTimeout)
	}
	if defaultSrv.MaxHeaderBytes != defaultHTTPMaxHeaderBytes {
		t.Errorf("default MaxHeaderBytes = %d, want %d", defaultSrv.MaxHeaderBytes, defaultHTTPMaxHeaderBytes)
	}

	cfg := config{
		readTimeout:       time.Second,
		readHeaderTimeout: 2 * time.Second,
		writeTimeout:      3 * time.Second,
		idleTimeout:       4 * time.Second,
		maxHeaderBytes:    4096,
	}
	srv := newHTTPServer(":0", http.NewServeMux(), cfg)

	if srv.ReadTimeout != cfg.readTimeout {
		t.Errorf("ReadTimeout = %v, want %v", srv.ReadTimeout, cfg.readTimeout)
	}
	if srv.ReadHeaderTimeout != cfg.readHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, cfg.readHeaderTimeout)
	}
	if srv.WriteTimeout != cfg.writeTimeout {
		t.Errorf("WriteTimeout = %v, want %v", srv.WriteTimeout, cfg.writeTimeout)
	}
	if srv.IdleTimeout != cfg.idleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, cfg.idleTimeout)
	}
	if srv.MaxHeaderBytes != cfg.maxHeaderBytes {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, cfg.maxHeaderBytes)
	}
}

func TestValidateConfigRejectsUnsafeValues(t *testing.T) {
	valid := config{
		maxHeaderBytes:    1,
		maxTTL:            time.Hour,
		maxRequestSize:    1,
		readinessInterval: time.Second,
	}
	if err := validateConfig(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*config)
	}{
		{name: "negative read timeout", edit: func(c *config) { c.readTimeout = -time.Second }},
		{name: "negative read header timeout", edit: func(c *config) { c.readHeaderTimeout = -time.Second }},
		{name: "negative write timeout", edit: func(c *config) { c.writeTimeout = -time.Second }},
		{name: "negative idle timeout", edit: func(c *config) { c.idleTimeout = -time.Second }},
		{name: "negative max header bytes", edit: func(c *config) { c.maxHeaderBytes = -1 }},
		{name: "zero max ttl", edit: func(c *config) { c.maxTTL = 0 }},
		{name: "negative max ttl", edit: func(c *config) { c.maxTTL = -time.Hour }},
		{name: "zero max request size", edit: func(c *config) { c.maxRequestSize = 0 }},
		{name: "negative max request size", edit: func(c *config) { c.maxRequestSize = -1 }},
		{name: "zero readiness interval", edit: func(c *config) { c.readinessInterval = 0 }},
		{name: "negative readiness interval", edit: func(c *config) { c.readinessInterval = -time.Second }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.edit(&cfg)
			if err := validateConfig(cfg); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestReadinessFn(t *testing.T) {
	healthyService := func() bool { return true }
	unhealthyService := func() bool { return false }

	freshCA := &x509.Certificate{NotAfter: time.Now().Add(48 * time.Hour)}
	expiringCA := &x509.Certificate{NotAfter: time.Now().Add(30 * time.Minute)}
	expiredCA := &x509.Certificate{NotAfter: time.Now().Add(-time.Hour)}

	tests := []struct {
		name      string
		svc       func() bool
		ca        *x509.Certificate
		minWindow time.Duration
		want      bool
	}{
		{"all good", healthyService, freshCA, time.Hour, true},
		{"attestation-api down", unhealthyService, freshCA, time.Hour, false},
		{"CA expiring inside window", healthyService, expiringCA, time.Hour, false},
		{"CA already expired", healthyService, expiredCA, time.Hour, false},
		{"nil CA", healthyService, nil, time.Hour, false},
		{"zero window disables CA check", healthyService, expiringCA, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fn := readinessFn(tc.svc, tc.ca, tc.minWindow)
			if got := fn(); got != tc.want {
				t.Errorf("readinessFn() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseMeasurementAllowlist(t *testing.T) {
	cases := []struct {
		name    string
		input   []string
		wantLen int
	}{
		{"empty", nil, 0},
		{"whitespace only", []string{"  ", ""}, 0},
		{"normalises case and trim", []string{"DEAD", " beef ", "dead"}, 2},
		{"three distinct", []string{"a", "b", "c"}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMeasurementAllowlist(tc.input)
			if len(got) != tc.wantLen {
				t.Errorf("len: got %d, want %d (map=%v)", len(got), tc.wantLen, got)
			}
		})
	}
}
