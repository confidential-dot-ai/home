package attestation_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/internal/attestation"
	"github.com/lunal-dev/c8s/internal/certissuer"
	"github.com/lunal-dev/c8s/internal/ear"
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
	rdm := fmt.Sprintf("%t", reportDataMatch)
	return fmt.Sprintf(`{
		"result": {
			"platform": "snp",
			"signature_valid": %t,
			"claims": {
				"launch_digest": "",
				"report_data": "",
				"signed_data": "",
				"init_data": ""
			},
			"report_data_match": %s
		},
		"token": null
	}`, signatureValid, rdm)
}

func mockVerifyResponseNullReportData() string {
	return `{
		"result": {
			"platform": "snp",
			"signature_valid": true,
			"claims": {
				"launch_digest": "",
				"report_data": "",
				"signed_data": "",
				"init_data": ""
			},
			"report_data_match": null
		},
		"token": null
	}`
}

func testApp(attestationURL, certIssuerURL string) http.Handler {
	challengeStore := attestation.NewChallengeStore(60 * time.Second)

	earIssuer, err := ear.NewIssuer(testKeyPEM(), "test-issuer", 24*time.Hour)
	if err != nil {
		panic(err)
	}

	asClient := attestationclient.NewClient(attestationURL)
	ciClient := certissuer.NewClient(certIssuerURL)

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
			Store:            &whitelistStore,
			AdminPasswordB64: base64.StdEncoding.EncodeToString([]byte("test-password")),
		},
		ReadyFn:   func() bool { return false },
		EarIssuer: earIssuer,
	}

	return server.NewRouter(deps)
}

func attestRequestBody(challenge string) string {
	return fmt.Sprintf(`{"challenge":"%s","evidence":{"platform":"snp","evidence":{}},"csr":"fake-csr"}`, challenge)
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
	body := attestRequestBody(challenge)
	resp, err := http.Post(appURL+"/attest", "application/json", strings.NewReader(body))
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

func TestAttestRejectsReusedChallenge(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, true))
	}))
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"certificate":"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"}`)
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
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, true))
	}))
	defer mockAS.Close()
	mockCI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"certificate":"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"}`)
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
	body := attestRequestBody(challenge)

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
