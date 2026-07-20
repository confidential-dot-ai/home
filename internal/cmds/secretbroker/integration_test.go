package secretbroker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// genCert mints a real self-signed leaf with the given CN/SAN, so the broker's
// ca-mode identity extraction and the token↔cert binding (which hash the cert's
// DER) are exercised against genuine certificates rather than zero-value structs.
func genCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func withClientCert(req *http.Request, cert *x509.Certificate) *http.Request {
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	return req
}

// openbaoStub is a minimal stand-in for a real OpenBao KV v2 backend. It checks
// the static store token and serves one secret, so the integration test
// exercises the broker's full login→authorize→proxy path without TEE hardware.
// (The bundled demo.sh runs the same path against a real OpenBao binary.)
func openbaoStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "stub-token" {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		if r.URL.Path != "/v1/secret/data/api/db" {
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Two fields, so field-scoped grants are observably filtered.
		_, _ = w.Write([]byte(`{"data":{"data":{"password":"s3cr3t","api_key":"k-9"},"metadata":{"version":1}}}`))
	}))
}

func newTestBroker(t *testing.T, storeAddr string) http.Handler {
	return newTestBrokerWithPolicy(t, storeAddr, &Policy{Rules: []Rule{
		{WorkloadID: "api", Allow: []string{"secret/data/api/*"}},
	}})
}

func newTestBrokerWithPolicy(t *testing.T, storeAddr string, policy *Policy) http.Handler {
	t.Helper()
	store, err := newVaultClient(config{
		openbaoAddr:     storeAddr,
		openbaoAttested: false,
		openbaoToken:    "stub-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	b := &broker{
		verifier: &peerVerifier{mode: peerVerifyCA},
		policy:   policy,
		tokens:   newTokenStore(time.Hour),
		store:    store,
		tokenTTL: time.Hour,
	}
	return newRouter(b, 65536)
}

func loginWith(t *testing.T, router http.Handler, cert *x509.Certificate) (string, int) {
	t.Helper()
	// PUT is what the stock Vault/OpenBao Agent uses for auth logins.
	req := withClientCert(httptest.NewRequest(http.MethodPut, "/v1/auth/cert/login", nil), cert)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return "", rec.Code
	}
	var resp authResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	return resp.Auth.ClientToken, rec.Code
}

func readWith(router http.Handler, cert *x509.Certificate, token, path string) *httptest.ResponseRecorder {
	req := withClientCert(httptest.NewRequest(http.MethodGet, "/v1/"+path, nil), cert)
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestEndToEndKVRead(t *testing.T) {
	stub := openbaoStub(t)
	defer stub.Close()
	router := newTestBroker(t, stub.URL)
	api := genCert(t, "api")

	token, code := loginWith(t, router, api)
	if code != http.StatusOK || token == "" {
		t.Fatalf("login failed: code=%d", code)
	}

	rec := readWith(router, api, token, "secret/data/api/db")
	if rec.Code != http.StatusOK {
		t.Fatalf("read failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp kvResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode read response: %v", err)
	}
	if got := resp.Data.Data["password"]; got != "s3cr3t" {
		t.Fatalf("secret not proxied through: got %v", resp.Data.Data)
	}
	// Path granted without a field scope → the whole item passes through.
	if _, ok := resp.Data.Data["api_key"]; !ok {
		t.Fatalf("unscoped grant should return all fields, got %v", resp.Data.Data)
	}
}

// A field-scoped grant ("…#password") must return only that field — the rest
// of the KV item never crosses the wire (N6).
func TestKVReadFieldScoped(t *testing.T) {
	stub := openbaoStub(t)
	defer stub.Close()
	router := newTestBrokerWithPolicy(t, stub.URL, &Policy{Rules: []Rule{
		{WorkloadID: "api", Allow: []string{"secret/data/api/*#password"}},
	}})
	api := genCert(t, "api")

	token, code := loginWith(t, router, api)
	if code != http.StatusOK || token == "" {
		t.Fatalf("login failed: code=%d", code)
	}
	rec := readWith(router, api, token, "secret/data/api/db")
	if rec.Code != http.StatusOK {
		t.Fatalf("read failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp kvResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode read response: %v", err)
	}
	if got := resp.Data.Data["password"]; got != "s3cr3t" {
		t.Fatalf("granted field missing: got %v", resp.Data.Data)
	}
	if _, ok := resp.Data.Data["api_key"]; ok {
		t.Fatalf("field-scoped grant leaked ungranted field: got %v", resp.Data.Data)
	}
	// Metadata is non-secret and still passes through.
	if resp.Data.Metadata["version"] == nil {
		t.Fatalf("metadata should pass through, got %v", resp.Data.Metadata)
	}
}

func TestLoginDeniedForUnknownWorkload(t *testing.T) {
	stub := openbaoStub(t)
	defer stub.Close()
	router := newTestBroker(t, stub.URL)

	if _, code := loginWith(t, router, genCert(t, "evil")); code != http.StatusForbidden {
		t.Fatalf("expected 403 for unmatched workload, got %d", code)
	}
}

func TestReadDeniedOutsideGrant(t *testing.T) {
	stub := openbaoStub(t)
	defer stub.Close()
	router := newTestBroker(t, stub.URL)
	api := genCert(t, "api")

	token, _ := loginWith(t, router, api)
	// Token is scoped to secret/data/api/*; a different path must be refused by
	// the broker before it ever touches the store.
	rec := readWith(router, api, token, "secret/data/other/db")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for ungranted path, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReadDeniedWithoutToken(t *testing.T) {
	stub := openbaoStub(t)
	defer stub.Close()
	router := newTestBroker(t, stub.URL)
	api := genCert(t, "api")

	if rec := readWith(router, api, "", "secret/data/api/db"); rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without token, got %d", rec.Code)
	}
	if rec := readWith(router, api, "c8sb.bogus", "secret/data/api/db"); rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with bogus token, got %d", rec.Code)
	}
}

// TestTokenBoundToClientCert proves a token minted for one client cert cannot be
// replayed on a different cert — even one with the same workload id — closing
// cross-workload token theft between two otherwise-valid mesh identities.
func TestTokenBoundToClientCert(t *testing.T) {
	stub := openbaoStub(t)
	defer stub.Close()
	router := newTestBroker(t, stub.URL)

	certA := genCert(t, "api")
	certB := genCert(t, "api") // same workload id, different key/DER

	token, code := loginWith(t, router, certA)
	if code != http.StatusOK {
		t.Fatalf("login failed: %d", code)
	}
	// Same cert: allowed.
	if rec := readWith(router, certA, token, "secret/data/api/db"); rec.Code != http.StatusOK {
		t.Fatalf("read on minting cert should succeed, got %d", rec.Code)
	}
	// Different cert presenting the stolen token: denied.
	if rec := readWith(router, certB, token, "secret/data/api/db"); rec.Code != http.StatusForbidden {
		t.Fatalf("stolen token on different cert must be denied, got %d", rec.Code)
	}
}

func TestLoginAcceptsPostAndPut(t *testing.T) {
	stub := openbaoStub(t)
	defer stub.Close()
	router := newTestBroker(t, stub.URL)

	for _, method := range []string{http.MethodPost, http.MethodPut} {
		req := withClientCert(httptest.NewRequest(method, "/v1/auth/cert/login", nil), genCert(t, "api"))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("login via %s failed: %d", method, rec.Code)
		}
	}
}

func TestLoginResponseShape(t *testing.T) {
	stub := openbaoStub(t)
	defer stub.Close()
	router := newTestBroker(t, stub.URL)

	req := withClientCert(httptest.NewRequest(http.MethodPost, "/v1/auth/cert/login", nil), genCert(t, "api"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// The stock Agent needs auth.client_token and auth.lease_duration present.
	if !strings.Contains(rec.Body.String(), `"client_token"`) ||
		!strings.Contains(rec.Body.String(), `"lease_duration"`) {
		t.Fatalf("login response missing required fields: %s", rec.Body.String())
	}
}
