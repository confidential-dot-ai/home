package attestation_test

import (
	"crypto"
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

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
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

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// testApp mounts the attestation routes /authenticate and /attest-key. CSR
// signing happens in-process in cds, so these handlers carry no signer
// dependency.
func testApp(attestationURL string) http.Handler {
	return testAppWithOperatorPolicy(attestationURL, "")
}

func testAppWithOperatorPolicy(attestationURL, operatorKeysHash string) http.Handler {
	challengeStore := attestation.NewChallengeStore(60 * time.Second)

	earIssuer, err := ear.NewIssuer(testKeyPEM(), "test-issuer", 24*time.Hour)
	if err != nil {
		panic(err)
	}

	h := attestation.Handler{
		Challenges:        &challengeStore,
		AttestationClient: attestationclient.NewClient(attestationURL),
		EarIssuer:         earIssuer,
		OperatorKeysHash:  operatorKeysHash,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /authenticate", attestation.HandleAuthenticate(h.Challenges))
	mux.HandleFunc("POST /attest-key", h.HandleAttestKey)
	return mux
}

func authenticate(t *testing.T, appURL string) string {
	t.Helper()
	resp, err := http.Post(appURL+"/authenticate", "application/json", nil)
	if err != nil {
		t.Fatalf("authenticate request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticate status = %d, want 200", resp.StatusCode)
	}
	var out types.ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	return out.Challenge
}

func TestAuthenticateReturnsBase64Challenge(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
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
	app := httptest.NewServer(testApp("http://unused"))
	defer app.Close()

	c1 := authenticate(t, app.URL)
	c2 := authenticate(t, app.URL)
	if c1 == c2 {
		t.Fatal("two authenticate calls returned the same challenge")
	}
}

func TestAuthenticateRejectsGetMethod(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
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

func TestAttestKeyReturnsEARForAttestedPubkey(t *testing.T) {
	const operatorKeysHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, true))
	}))
	defer mockAS.Close()

	app := httptest.NewServer(testAppWithOperatorPolicy(mockAS.URL, operatorKeysHash))
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
		PublicKey:        base64.StdEncoding.EncodeToString(pubDER),
		OperatorKeysHash: operatorKeysHash,
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
	if got, _ := claims[earclaims.OperatorKeysHash].(string); got != operatorKeysHash {
		t.Fatalf("operator_keys_hash = %q, want %q", got, operatorKeysHash)
	}
}

func TestAttestKeyRejectsMismatchedOperatorPolicy(t *testing.T) {
	const requiredHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	app := httptest.NewServer(testAppWithOperatorPolicy("http://unused", requiredHash))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	pubDER, err := x509.MarshalPKIXPublicKey(generateAttestKeyPubKey(t))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(types.AttestKeyRequestBody{
		Challenge:        challenge,
		Evidence:         types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		PublicKey:        base64.StdEncoding.EncodeToString(pubDER),
		OperatorKeysHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(app.URL+"/attest-key", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAttestKeyRejectsNonECDSAPubkey(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
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
