package attestclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// unreachableURL points at a port nothing is listening on, to exercise
// transport-error paths deterministically without real network access.
const unreachableURL = "http://127.0.0.1:1"

func TestStatusErrorError(t *testing.T) {
	err := &StatusError{Status: 503, Body: "unavailable"}
	got := err.Error()
	if !strings.Contains(got, "503") || !strings.Contains(got, "unavailable") {
		t.Fatalf("Error() = %q, want status and body", got)
	}
}

type ctxKey struct{}

func TestContextOrBackgroundNil(t *testing.T) {
	var nilCtx context.Context
	if contextOrBackground(nilCtx) == nil {
		t.Fatal("contextOrBackground(nil) returned nil")
	}
	ctx := context.WithValue(context.Background(), ctxKey{}, 1)
	if contextOrBackground(ctx) != ctx {
		t.Fatal("contextOrBackground should return the passed-in context unchanged")
	}
}

func TestAuthenticateNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	_, err := c.Authenticate()
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected StatusError, got %T: %v", err, err)
	}
	if statusErr.Status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", statusErr.Status)
	}
	if statusErr.Body != "boom" {
		t.Fatalf("body = %q, want boom", statusErr.Body)
	}
}

func TestAuthenticateMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	if _, err := c.Authenticate(); err == nil {
		t.Fatal("expected decode error for malformed JSON")
	}
}

func TestAuthenticateTransportError(t *testing.T) {
	c := NewClient(unreachableURL)
	_, err := c.AuthenticateContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("error = %v, want request failed", err)
	}
}

func TestAttestSuccess(t *testing.T) {
	const certPEM = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			t.Fatalf("path = %s, want /attest", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content-type = %q, want application/json", ct)
		}
		var req attestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if req.Challenge != "chal" || req.CSR != "csr" {
			t.Fatalf("unexpected request: %+v", req)
		}
		_, _ = w.Write([]byte(certPEM))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	got, err := c.Attest(attestRequest{Challenge: "chal", CSR: "csr"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if got != certPEM {
		t.Fatalf("cert = %q, want %q", got, certPEM)
	}
}

func TestAttestNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad csr"))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	_, err := c.Attest(attestRequest{})
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected StatusError, got %T: %v", err, err)
	}
	if statusErr.Status != http.StatusBadRequest || statusErr.Body != "bad csr" {
		t.Fatalf("statusErr = %+v", statusErr)
	}
}

func TestAttestTransportError(t *testing.T) {
	c := NewClient(unreachableURL)
	_, err := c.Attest(attestRequest{})
	if err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("error = %v, want request failed", err)
	}
}

func TestHealthzNotReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	ok, err := c.Healthz()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected healthz false for 503")
	}
}

func TestHealthzTransportError(t *testing.T) {
	c := NewClient(unreachableURL)
	if _, err := c.Healthz(); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestReadyzNotReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	ok, err := c.Readyz()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected readyz false for 503")
	}
}

func TestReadyzTransportError(t *testing.T) {
	c := NewClient(unreachableURL)
	if _, err := c.Readyz(); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestGenerateEvidenceSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			t.Fatalf("path = %s, want /attest", r.URL.Path)
		}
		var req types.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if string(req.ReportData.Bytes()) != "report-data" {
			t.Fatalf("report data = %q", req.ReportData.Bytes())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"platform":"snp","evidence":{"q":1}}`))
	}))
	defer srv.Close()

	// httpClient is shared by GenerateEvidence's inner attestationclient.
	c := NewClientWithHTTP("http://cds.invalid", srv.Client())
	resp, err := c.GenerateEvidence(srv.URL, []byte("report-data"))
	if err != nil {
		t.Fatalf("GenerateEvidence: %v", err)
	}
	if resp.Platform != "snp" {
		t.Fatalf("platform = %q, want snp", resp.Platform)
	}
}

func TestGenerateEvidenceError(t *testing.T) {
	c := NewClient("http://cds.invalid")
	if _, err := c.GenerateEvidence(unreachableURL, []byte("x")); err == nil {
		t.Fatal("expected error from unreachable attestation-api")
	}
}

// fullFlowServers wires up a CDS mux and an attestation-api server that
// together satisfy ObtainCertificate / AttestKey. The cds handler for
// /attest and /attest-key is supplied by the caller.
func fullFlowServers(t *testing.T, challenge string, cdsHandler http.Handler) (cdsURL, apiURL string) {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"platform":"snp","evidence":{"q":1}}`))
	}))
	t.Cleanup(api.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: challenge})
	})
	mux.Handle("/attest", cdsHandler)
	mux.Handle("/attest-key", cdsHandler)
	cds := httptest.NewServer(mux)
	t.Cleanup(cds.Close)

	return cds.URL, api.URL
}

func TestObtainCertificateSuccess(t *testing.T) {
	const challenge = "dGVzdC1jaGFsbGVuZ2U="
	const certPEM = "-----BEGIN CERTIFICATE-----\nflow\n-----END CERTIFICATE-----\n"
	csrPEM := testCSRPEM(t)

	cdsURL, apiURL := fullFlowServers(t, challenge, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(certPEM))
	}))

	c := NewClient(cdsURL)
	got, err := c.ObtainCertificate(apiURL, csrPEM)
	if err != nil {
		t.Fatalf("ObtainCertificate: %v", err)
	}
	if got != certPEM {
		t.Fatalf("cert = %q, want %q", got, certPEM)
	}
}

func TestObtainCertificateWithContextError(t *testing.T) {
	// CDS returns a non-base64 challenge so the flow fails at decode.
	cdsURL, apiURL := fullFlowServers(t, "!!!not-base64!!!", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("attest should not be reached")
	}))

	c := NewClient(cdsURL)
	_, err := c.ObtainCertificateWithContext(context.Background(), apiURL, testCSRPEM(t))
	if err == nil || !strings.Contains(err.Error(), "invalid base64 in challenge") {
		t.Fatalf("error = %v, want invalid base64", err)
	}
}

func TestObtainCertificateAuthenticateError(t *testing.T) {
	c := NewClient(unreachableURL)
	_, err := c.ObtainCertificate(unreachableURL, testCSRPEM(t))
	if err == nil || !strings.Contains(err.Error(), "authenticate") {
		t.Fatalf("error = %v, want authenticate failure", err)
	}
}

func TestObtainCertificateBadCSR(t *testing.T) {
	const challenge = "dGVzdC1jaGFsbGVuZ2U="
	cdsURL, apiURL := fullFlowServers(t, challenge, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("attest should not be reached with a bad CSR")
	}))

	c := NewClient(cdsURL)
	_, err := c.ObtainCertificateWithEvidence(apiURL, "not a pem csr")
	if err == nil || !strings.Contains(err.Error(), "PEM-encoded certificate request") {
		t.Fatalf("error = %v, want CSR PEM error", err)
	}
}

// badControlCharURL contains an ASCII control character, which makes
// http.NewRequestWithContext fail at request construction (before any
// transport activity), exercising that error branch.
const badControlCharURL = "http://\x7f.example"

func TestAuthenticateBadRequestURL(t *testing.T) {
	c := NewClient(badControlCharURL)
	if _, err := c.AuthenticateContext(context.Background()); err == nil {
		t.Fatal("expected NewRequest error for control char in URL")
	}
}

func TestAttestBadRequestURL(t *testing.T) {
	c := NewClient(badControlCharURL)
	if _, err := c.Attest(attestRequest{}); err == nil {
		t.Fatal("expected NewRequest error for control char in URL")
	}
}

func TestReportDataForCSRBadPEM(t *testing.T) {
	if _, err := reportDataForCSR("garbage", nil); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
	// Wrong PEM type.
	wrongType := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if _, err := reportDataForCSR(wrongType, nil); err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}

func testPubKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return der
}

func TestAttestKeySuccess(t *testing.T) {
	const challenge = "dGVzdC1jaGFsbGVuZ2U="
	const ear = "header.payload.sig"
	const operatorKeysHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pubDER := testPubKeyDER(t)

	cdsURL, apiURL := fullFlowServers(t, challenge, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest-key" {
			t.Fatalf("path = %s, want /attest-key", r.URL.Path)
		}
		var body types.AttestKeyRequestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Challenge != challenge {
			t.Fatalf("challenge = %q", body.Challenge)
		}
		if body.PublicKey != base64.StdEncoding.EncodeToString(pubDER) {
			t.Fatal("public key not round-tripped")
		}
		if body.OperatorKeysHash != operatorKeysHash {
			t.Fatalf("operator_keys_hash = %q, want %q", body.OperatorKeysHash, operatorKeysHash)
		}
		if body.Evidence.Platform != "snp" {
			t.Fatalf("platform = %q, want snp", body.Evidence.Platform)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.AttestKeyResponseBody{EAR: ear})
	}))

	c := NewClient(cdsURL)
	got, err := c.AttestKeyWithOperatorKeysHash(context.Background(), apiURL, pubDER, operatorKeysHash)
	if err != nil {
		t.Fatalf("AttestKey: %v", err)
	}
	if got != ear {
		t.Fatalf("ear = %q, want %q", got, ear)
	}
}

func TestAttestKeyMissingEAR(t *testing.T) {
	const challenge = "dGVzdC1jaGFsbGVuZ2U="
	cdsURL, apiURL := fullFlowServers(t, challenge, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))

	c := NewClient(cdsURL)
	_, err := c.AttestKey(context.Background(), apiURL, testPubKeyDER(t))
	if err == nil || !strings.Contains(err.Error(), "missing ear") {
		t.Fatalf("error = %v, want missing ear", err)
	}
}

func TestAttestKeyNon2xx(t *testing.T) {
	const challenge = "dGVzdC1jaGFsbGVuZ2U="
	cdsURL, apiURL := fullFlowServers(t, challenge, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied"))
	}))

	c := NewClient(cdsURL)
	_, err := c.AttestKey(context.Background(), apiURL, testPubKeyDER(t))
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected StatusError, got %T: %v", err, err)
	}
	if statusErr.Status != http.StatusForbidden || statusErr.Body != "denied" {
		t.Fatalf("statusErr = %+v", statusErr)
	}
}

func TestAttestKeyBadPubKey(t *testing.T) {
	const challenge = "dGVzdC1jaGFsbGVuZ2U="
	cdsURL, apiURL := fullFlowServers(t, challenge, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("attest-key should not be reached with an invalid public key")
	}))

	c := NewClient(cdsURL)
	_, err := c.AttestKey(context.Background(), apiURL, []byte("not-pkix-der"))
	if err == nil || !strings.Contains(err.Error(), "parse public key") {
		t.Fatalf("error = %v, want parse public key", err)
	}
}

func TestAttestKeyBadChallenge(t *testing.T) {
	cdsURL, apiURL := fullFlowServers(t, "!!!bad!!!", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("attest-key should not be reached")
	}))

	c := NewClient(cdsURL)
	_, err := c.AttestKey(context.Background(), apiURL, testPubKeyDER(t))
	if err == nil || !strings.Contains(err.Error(), "invalid base64 in challenge") {
		t.Fatalf("error = %v, want invalid base64", err)
	}
}

func TestAttestKeyAuthenticateError(t *testing.T) {
	c := NewClient(unreachableURL)
	_, err := c.AttestKey(context.Background(), unreachableURL, testPubKeyDER(t))
	if err == nil || !strings.Contains(err.Error(), "authenticate") {
		t.Fatalf("error = %v, want authenticate failure", err)
	}
}

func TestMakeSNPRATLSAttestFuncSuccess(t *testing.T) {
	// attestation-api returns bare-metal SNP evidence; the AttestFunc should
	// extract the raw SNP report.
	report := make([]byte, 1184)
	report[0] = 0x02
	evidence := map[string]string{"attestation_report": base64.StdEncoding.EncodeToString(report)}
	evidenceJSON, _ := json.Marshal(evidence)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.AttestResponse{Platform: "snp", Evidence: evidenceJSON})
	}))
	defer api.Close()

	c := NewClientWithHTTP("http://cds.invalid", api.Client())
	fn := MakeSNPRATLSAttestFunc(c, api.URL)

	// customData must be hex-encoded and at least sha512.Size384 (48) bytes.
	customData := strings.Repeat("ab", 48)
	out, err := fn(context.Background(), customData)
	if err != nil {
		t.Fatalf("AttestFunc: %v", err)
	}
	if len(out) != 1184 {
		t.Fatalf("report len = %d, want 1184", len(out))
	}
}

func TestMakeSNPRATLSAttestFuncBadHex(t *testing.T) {
	c := NewClient("http://cds.invalid")
	fn := MakeSNPRATLSAttestFunc(c, "http://api.invalid")
	_, err := fn(context.Background(), "not-hex")
	if err == nil || !strings.Contains(err.Error(), "decode report data hex") {
		t.Fatalf("error = %v, want decode hex error", err)
	}
}

func TestMakeSNPRATLSAttestFuncAPIError(t *testing.T) {
	c := NewClient("http://cds.invalid")
	fn := MakeSNPRATLSAttestFunc(c, unreachableURL)
	customData := strings.Repeat("cd", 48)
	_, err := fn(context.Background(), customData)
	if err == nil || !strings.Contains(err.Error(), "attestation-api") {
		t.Fatalf("error = %v, want attestation-api error", err)
	}
}
