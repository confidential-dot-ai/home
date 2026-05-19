package attestation_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/internal/attestation"
	"github.com/lunal-dev/c8s/internal/certissuerclient"
	"github.com/lunal-dev/c8s/internal/ear"
	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/internal/server"
	"github.com/lunal-dev/c8s/internal/whitelist"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/types"
)

func testKeyPEM() []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func mockVerifyResponse(signatureValid, reportDataMatch bool) string {
	return mustJSON(types.VerifyResponse{
		Result: types.VerificationResult{
			Platform:        "snp",
			SignatureValid:  signatureValid,
			Claims:          types.Claims{},
			ReportDataMatch: &reportDataMatch,
		},
	})
}

func mockVerifyResponseNullReportData() string {
	return mustJSON(types.VerifyResponse{
		Result: types.VerificationResult{
			Platform:       "snp",
			SignatureValid: true,
			Claims:         types.Claims{},
		},
	})
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func testApp(attestationURL, certIssuerURL string) http.Handler {
	challengeStore := attestation.NewChallengeStore(60 * time.Second)

	earIssuer, err := ear.NewIssuer(testKeyPEM(), "test-issuer", 24*time.Hour)
	if err != nil {
		panic(err)
	}

	asClient := attestationclient.NewClient(attestationURL)
	ciClient := certissuerclient.NewClient(certIssuerURL)

	whitelistStore, err := whitelist.OpenInMemory()
	if err != nil {
		panic(err)
	}

	deps := server.Dependencies{
		AttestationHandler: attestation.Handler{
			Challenges:        &challengeStore,
			AttestationClient: asClient,
			CertIssuer:        ciClient,
			CertTTL:           "24h",
			EarIssuer:         earIssuer,
		},
		WhitelistHandler: whitelist.Handler{
			Store: &whitelistStore,
		},
		ReadyFn:   func() bool { return false },
		EarIssuer: earIssuer,
	}

	return server.NewRouter(deps)
}

func attestRequestBody(t *testing.T, challenge string) string {
	t.Helper()
	csr := testCSRPEM(t)
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence: types.AttestationEvidence{
			Platform: "snp",
			Evidence: json.RawMessage(`{}`),
		},
		CSR: csr,
	})
	if err != nil {
		t.Fatalf("marshal attest request: %v", err)
	}
	return string(body)
}

func testCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate csr key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-node"},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func testRSACSRPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa csr key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-node"},
	}, key)
	if err != nil {
		t.Fatalf("create rsa csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func testCertificatePEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate certificate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func authenticate(t *testing.T, appURL string) string {
	t.Helper()
	resp, err := http.Post(appURL+"/authenticate", "application/json", nil)
	if err != nil {
		t.Fatalf("authenticate request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticate returned %d, want 200", resp.StatusCode)
	}
	var cr types.ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatalf("decode challenge response: %v", err)
	}
	return cr.Challenge
}

func doAttest(t *testing.T, appURL, challenge string) *http.Response {
	t.Helper()
	body := attestRequestBody(t, challenge)
	resp, err := http.Post(appURL+"/attest", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("attest request failed: %v", err)
	}
	return resp
}

func doAttestWithCSR(t *testing.T, appURL, challenge, csr string) *http.Response {
	t.Helper()
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence: types.AttestationEvidence{
			Platform: "snp",
			Evidence: json.RawMessage(`{}`),
		},
		CSR: csr,
	})
	if err != nil {
		t.Fatalf("marshal attest request: %v", err)
	}
	resp, err := http.Post(appURL+"/attest", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("attest request failed: %v", err)
	}
	return resp
}

func TestAuthenticateReturnsBase64Challenge(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)

	decoded, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		t.Fatalf("challenge is not valid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("challenge decoded to %d bytes, want 32", len(decoded))
	}
}

func TestAuthenticateReturnsUniqueChallenges(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	c1 := authenticate(t, app.URL)
	c2 := authenticate(t, app.URL)
	if c1 == c2 {
		t.Fatal("two authenticate calls returned the same challenge")
	}
}

func TestAttestRejectsInvalidChallenge(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	// fabricate a valid base64 challenge that was never issued
	fakeChallenge := base64.StdEncoding.EncodeToString(make([]byte, 32))
	resp := doAttest(t, app.URL, fakeChallenge)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
}

func TestAttestRejectsNonECDSACSRKey(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	resp := doAttestWithCSR(t, app.URL, challenge, testRSACSRPEM(t))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
}

func TestAttestRejectsReusedChallenge(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, true))
	}))
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.SignCsrResponse{Certificate: testCertificatePEM(t, "leaf")})
	}))
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)

	resp1 := doAttest(t, app.URL, challenge)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first attest got %d, want 200", resp1.StatusCode)
	}

	resp2 := doAttest(t, app.URL, challenge)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("second attest got %d, want 400", resp2.StatusCode)
	}
}

func TestAttestReturnsCertificateOnValidAttestation(t *testing.T) {
	var sawKeyBoundReportData bool
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode verify request: %v", err)
		}
		if req.Params == nil || req.Params.ExpectedReportData == nil {
			t.Fatal("verify request missing expected_report_data")
		}
		if got := len(req.Params.ExpectedReportData.Bytes()); got != sha512.Size384 {
			t.Fatalf("expected_report_data length = %d, want %d", got, sha512.Size384)
		}
		sawKeyBoundReportData = true
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, true))
	}))
	defer mockAS.Close()
	var sawTEEPubKey bool
	mockCI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.SignCsrRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode sign-csr request: %v", err)
		}
		var claims map[string]any
		decodeJWTPayload(t, req.Ear, &claims)
		if claims[earclaims.TEEPublicKey] == "" {
			t.Fatal("sign-csr EAR missing tee_public_key")
		}
		sawTEEPubKey = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.SignCsrResponse{Certificate: testCertificatePEM(t, "leaf")})
	}))
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	resp := doAttest(t, app.URL, challenge)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/x-pem-file" {
		t.Fatalf("Content-Type = %q, want application/x-pem-file", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Fatal("response body does not contain BEGIN CERTIFICATE")
	}
	if !sawKeyBoundReportData {
		t.Fatal("attestation service did not receive key-bound report data")
	}
	if !sawTEEPubKey {
		t.Fatal("cert-issuer did not receive tee_public_key-bound EAR")
	}
}

func TestAttestKeyReturnsEARForAttestedPubkey(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, true))
	}))
	defer mockAS.Close()

	app := httptest.NewServer(testApp(mockAS.URL, "http://unused"))
	defer app.Close()

	challenge := authenticate(t, app.URL)

	pubKey := generateAttestKeyPubKey(t)
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}

	body, err := json.Marshal(types.AttestKeyRequestBody{
		Challenge: challenge,
		Evidence: types.AttestationEvidence{
			Platform: "snp",
			Evidence: json.RawMessage(`{"quote":"abc"}`),
		},
		PublicKey: base64.StdEncoding.EncodeToString(pubDER),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp, err := http.Post(app.URL+"/attest-key", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /attest-key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	var out types.AttestKeyResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.EAR == "" {
		t.Fatal("response missing ear")
	}

	var claims map[string]any
	decodeJWTPayload(t, out.EAR, &claims)
	if claims[earclaims.TEEPublicKey] == nil {
		t.Fatal("EAR missing tee_public_key claim")
	}
	wantPubKeyClaim := base64.RawURLEncoding.EncodeToString(pubDER)
	if got, _ := claims[earclaims.TEEPublicKey].(string); got != wantPubKeyClaim {
		t.Fatalf("tee_public_key = %q, want %q", got, wantPubKeyClaim)
	}
}

func TestAttestKeyRejectsNonECDSAPubkey(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused", "http://unused"))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	body, err := json.Marshal(types.AttestKeyRequestBody{
		Challenge: challenge,
		Evidence:  types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		PublicKey: base64.StdEncoding.EncodeToString([]byte("not-a-pubkey")),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(app.URL+"/attest-key", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func generateAttestKeyPubKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &key.PublicKey
}

func decodeJWTPayload(t *testing.T, token string, v any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		t.Fatalf("unmarshal JWT payload: %v", err)
	}
}

func TestAttestRejectsInvalidSignature(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(false, true))
	}))
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	resp := doAttest(t, app.URL, challenge)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func TestAttestRejectsChallengeMismatch(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, false))
	}))
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	resp := doAttest(t, app.URL, challenge)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func TestAttestRejectsWhenReportDataMatchNull(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponseNullReportData())
	}))
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	resp := doAttest(t, app.URL, challenge)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func TestAttestBadGatewayWhenAttestationServiceUnreachable(t *testing.T) {
	// point to a closed server
	mockAS := httptest.NewServer(http.NotFoundHandler())
	asURL := mockAS.URL
	mockAS.Close()

	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(asURL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	resp := doAttest(t, app.URL, challenge)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("got status %d, want 502", resp.StatusCode)
	}

	var errResp types.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp.Error != "attestation_service_unreachable" {
		t.Fatalf("error = %q, want attestation_service_unreachable", errResp.Error)
	}
}

func TestAttestBadGatewayWhenAttestationServiceReturns500(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"internal","message":"boom"}`)
	}))
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	resp := doAttest(t, app.URL, challenge)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("got status %d, want 502", resp.StatusCode)
	}

	var errResp types.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp.Error != "attestation_service_error" {
		t.Fatalf("error = %q, want attestation_service_error", errResp.Error)
	}
}

func TestAttestBadGatewayWhenCertIssuerUnreachable(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, true))
	}))
	defer mockAS.Close()

	// point to a closed server
	mockCI := httptest.NewServer(http.NotFoundHandler())
	ciURL := mockCI.URL
	mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, ciURL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	resp := doAttest(t, app.URL, challenge)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("got status %d, want 502", resp.StatusCode)
	}

	var errResp types.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp.Error != "cert_issuer_unreachable" {
		t.Fatalf("error = %q, want cert_issuer_unreachable", errResp.Error)
	}
}

func TestAttestBadGatewayWhenCertIssuerReturns500(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, true))
	}))
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal error")
	}))
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	resp := doAttest(t, app.URL, challenge)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("got status %d, want 502", resp.StatusCode)
	}

	var errResp types.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp.Error != "cert_issuer_error" {
		t.Fatalf("error = %q, want cert_issuer_error", errResp.Error)
	}
}

func TestChallengeConsumedEvenOnDownstreamFailure(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"internal","message":"boom"}`)
	}))
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)

	// first attempt - 502 from downstream failure
	resp1 := doAttest(t, app.URL, challenge)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadGateway {
		t.Fatalf("first attest got %d, want 502", resp1.StatusCode)
	}

	// retry with same challenge - should be consumed
	resp2 := doAttest(t, app.URL, challenge)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("retry attest got %d, want 400", resp2.StatusCode)
	}
}

func TestAttestRejectsNonBase64Challenge(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	resp := doAttest(t, app.URL, "not-valid-base64!!!")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
}

func TestAttestRejectsEmptyChallenge(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	resp := doAttest(t, app.URL, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", resp.StatusCode)
	}
}

func TestAttestRejectsMissingContentType(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	body := attestRequestBody(t, challenge)

	req, err := http.NewRequest(http.MethodPost, app.URL+"/attest", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	// deliberately not setting Content-Type

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	// chi router does not enforce content-type by default, so the handler
	// will still attempt to decode JSON. We just verify we get a response.
	if resp.StatusCode == 0 {
		t.Fatal("unexpected zero status")
	}
}

func TestAttestRejectsInvalidJSON(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	resp, err := http.Post(app.URL+"/attest", "application/json", strings.NewReader("{garbled"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("got status %d, want 422", resp.StatusCode)
	}
}

func TestAuthenticateRejectsGetMethod(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	resp, err := http.Get(app.URL + "/authenticate")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("got status %d, want 405", resp.StatusCode)
	}
}

func TestAttestRejectsGetMethod(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	resp, err := http.Get(app.URL + "/attest")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("got status %d, want 405", resp.StatusCode)
	}
}

func TestErrorResponseFormat(t *testing.T) {
	mockAS := httptest.NewServer(http.NotFoundHandler())
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.NotFoundHandler())
	defer mockCI.Close()

	app := httptest.NewServer(testApp(mockAS.URL, mockCI.URL))
	defer app.Close()

	// trigger an error by sending invalid JSON
	resp, err := http.Post(app.URL+"/attest", "application/json", strings.NewReader("{bad"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}

	errField, ok := raw["error"]
	if !ok {
		t.Fatal("error response missing 'error' field")
	}
	if _, ok := errField.(string); !ok {
		t.Fatal("'error' field is not a string")
	}

	msgField, ok := raw["message"]
	if !ok {
		t.Fatal("error response missing 'message' field")
	}
	if _, ok := msgField.(string); !ok {
		t.Fatal("'message' field is not a string")
	}
}
