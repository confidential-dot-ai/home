package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestClassifyVerifyError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "signature invalid",
			err:        fmt.Errorf("wrap: %w", attestationclient.ErrSignatureInvalid),
			wantStatus: http.StatusUnauthorized,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "report data mismatch",
			err:        fmt.Errorf("wrap: %w", attestationclient.ErrReportDataMismatch),
			wantStatus: http.StatusUnauthorized,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "api 4xx is client fault",
			err:        &attestationclient.APIError{Status: http.StatusBadRequest},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "transport failure is unreachable",
			err:        errors.New("dial tcp: connection refused"),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, code, msg := classifyVerifyError(tc.err)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if msg == "" {
				t.Error("message empty")
			}
		})
	}
}

// A CSR whose public key is not ECDSA must be rejected before verification.
func TestAttest_RejectsNonECDSACSR(t *testing.T) {
	mock := newMockAttestationApi(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	challenge := issueChallenge(t, h)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa-node"},
	}, rsaKey)
	if err != nil {
		t.Fatalf("create rsa csr: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsMalformedWorkloadClaimsEncoding(t *testing.T) {
	mock := newMockAttestationApi(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	csrPEM, _ := generateCSR(t)

	body, err := json.Marshal(types.AttestRequestBody{
		Challenge:      issueChallenge(t, h),
		Evidence:       types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		CSR:            csrPEM,
		WorkloadClaims: "!!!not-base64!!!",
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
	if !strings.Contains(w.Body.String(), "workload_claims") {
		t.Errorf("body should mention workload_claims; got %s", w.Body.String())
	}
}

// A CSR whose RA-TLS attestation extension does not parse must be rejected at
// issuance when workload claims are presented.
func TestAttest_WorkloadClaims_RejectsGarbageRATLSExtension(t *testing.T) {
	mock := newMockAttestationApi(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.AllowlistStore = fakeStore{wlDigestA: true}

	csrPEM, _ := generateCSRWithRATLSExtension(t, []byte("garbage-extension"))
	digests := []string{wlDigestA}
	w := postAttestClaimsWithCSR(t, h, issueChallenge(t, h), csrPEM, claimsDERFor(t, nil, digests), nil, digests)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "does not parse") {
		t.Errorf("body should mention parse failure; got %s", w.Body.String())
	}
}

func generateCSRWithRATLSExtension(t *testing.T, extValue []byte) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "test-node"},
		ExtraExtensions: []pkix.Extension{{Id: ratls.OIDRATLSAttestation, Value: extValue}},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

// An unloaded CA makes in-process signing fail after all validation passed.
// Also exercises the RequestTimeout>0 wrapping.
func TestAttest_SignFailureReturns500(t *testing.T) {
	mock := newMockAttestationApi(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.CA = &issuer.CA{} // no cert/key loaded: SignCSR fails
	h.RequestTimeout = time.Second
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), types.ErrorCodeSignFailed) {
		t.Errorf("body should mention %s; got %s", types.ErrorCodeSignFailed, w.Body.String())
	}
}

// errStore fails every allowlist lookup, forcing the fail-closed branch.
type errStore struct{}

func (errStore) Contains(types.Digest) (bool, error) {
	return false, errors.New("store unavailable")
}

func TestVerifyWorkloadClaims_FailsClosedOnStoreError(t *testing.T) {
	h := AttestHandler{AllowlistStore: errStore{}}
	digests := []string{wlDigestA}
	err := h.verifyWorkloadClaims(claimsDERFor(t, nil, digests), nil, digests)
	if err == nil {
		t.Fatal("expected error when the allowlist store fails")
	}
	if !strings.Contains(err.Error(), "check allowlist") {
		t.Errorf("error = %q, want it to mention check allowlist", err)
	}
}

func TestSignCSR_RejectsNonPEMCSRField(t *testing.T) {
	h, _, _ := newTestSignCSRHandler(t)
	body := []byte(`{"ear":"x","csr":"bm90LXBlbQ==","ttl":"1h"}`)
	req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSignCSR(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid CSR") {
		t.Errorf("body should say invalid CSR; got %s", w.Body.String())
	}
}

func TestSignCSR_RejectsPEMWithGarbageDER(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:   "cds",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(time.Minute).Unix(),
	})
	w := postSignCSR(t, h, ear, []byte("not-a-real-csr-der"), time.Hour)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid CSR") {
		t.Errorf("body should say invalid CSR; got %s", w.Body.String())
	}
}

func TestSignCSR_RejectsTamperedCSRSignature(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	csr, _ := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	tampered := make([]byte, len(csr.Raw))
	copy(tampered, csr.Raw)
	tampered[len(tampered)-1] ^= 0xFF

	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:   "cds",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(time.Minute).Unix(),
	})
	w := postSignCSR(t, h, ear, tampered, time.Hour)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "signature invalid") {
		t.Errorf("body should say signature invalid; got %s", w.Body.String())
	}
}

func TestSignCSR_SANValidationBindsSourceIP(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	h.SANValidation = true
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// cancelKeyProvider cancels the request context when the EAR key is fetched,
// so the handler's post-validation ctx.Err() check fires.
type cancelKeyProvider struct {
	pub    *ecdsa.PublicKey
	cancel context.CancelFunc
}

func (p cancelKeyProvider) PublicKey(string) (*ecdsa.PublicKey, error) {
	p.cancel()
	return p.pub, nil
}

func TestSignCSR_TimeoutBeforeSigningReturns504(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.KeyProvider = cancelKeyProvider{pub: &earKey.PublicKey, cancel: cancel}

	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	body, err := json.Marshal(map[string]any{"ear": ear, "csr": string(csrPEM), "ttl": "1h"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.HandleSignCSR(w, req)
	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("status: got %d, want 504; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_SignFailureReturns500(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	h.CA = &issuer.CA{} // no cert/key loaded: SignCSR fails
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

// failWriter accepts headers but fails the body write, exercising the encode
// error logging branch.
type failWriter struct {
	header http.Header
	status int
}

func (f *failWriter) Header() http.Header {
	if f.header == nil {
		f.header = make(http.Header)
	}
	return f.header
}

func (f *failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func (f *failWriter) WriteHeader(status int) { f.status = status }

func TestSignCSR_ResponseEncodeFailureIsLoggedNotFatal(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	body, err := json.Marshal(map[string]any{"ear": ear, "csr": string(csrPEM), "ttl": "1h"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body))
	w := &failWriter{}
	h.HandleSignCSR(w, req) // must not panic on encode failure
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json (handler reached the response stage)", ct)
	}
}

// Seeding into a closed store must fail closed.
func TestSeedStore_FailsClosedOnStoreError(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	_ = store.Close()

	path := writeSeed(t, `{"version":"1","digests":{"`+digestA+`":"ghcr.io/x/cds:v1"}}`)
	if _, err := seedStore(&store, path); err == nil {
		t.Fatal("seedStore succeeded on a closed store; want fail-closed error")
	}
}
