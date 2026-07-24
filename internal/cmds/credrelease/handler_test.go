package credrelease

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// TestHandlerReleasesServerCA drives POST /release-credential end to end and
// checks the wire response: CAPEM is the serving-CA PEM verbatim and the
// issued cert chains to the client CA.
func TestHandlerReleasesServerCA(t *testing.T) {
	opKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opKeyPEM, err := certutil.MarshalECKeyPEM(opKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(opKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&opKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	ca := testCA(t)
	serverCA, err := issuer.NewCA("server-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca.pem = certutil.EncodeCertPEM(serverCA.Cert.Raw)

	h, err := NewHandler(pubPEM, ca, "system:masters", "operator", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ignored-by-signer"},
	}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, err := json.Marshal(releaseRequest{CSRPEM: string(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}
	authz, err := signer.Authorization(http.MethodPost, "/release-credential", body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/release-credential", bytes.NewReader(body))
	req.Header.Set("Authorization", authz)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}

	var resp releaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.CAPEM != string(ca.pem) {
		t.Error("released CA is not the serving-CA PEM")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := parseLeaf(t, []byte(resp.CertPEM)).Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("released cert does not chain to the client CA: %v", err)
	}
}

// newOperatorAuth generates a fresh operator keypair, returning a token signer
// (the operator side) and the PKIX public-key PEM (the measured side).
func newOperatorAuth(t *testing.T) (*operatorauth.Signer, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

// csrPEMFromKey builds a PEM CERTIFICATE REQUEST self-signed by key.
func csrPEMFromKey(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ignored-by-signer"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestNewHandlerRejectsBadPubkey: the measured key must be an ECDSA PKIX PEM.
func TestNewHandlerRejectsBadPubkey(t *testing.T) {
	if _, err := NewHandler([]byte("not a key"), testCA(t), "system:masters", "operator", time.Hour); err == nil {
		t.Error("expected error for non-PEM operator pubkey")
	}
}

// errReader fails mid-body, driving the read-body error branch.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// TestServeHTTPErrorPaths drives every refusal branch of the handler: routing,
// method, authorization, body decoding, CSR validation, and signing.
func TestServeHTTPErrorPaths(t *testing.T) {
	signer, pubPEM := newOperatorAuth(t)
	h, err := NewHandler(pubPEM, testCA(t), "system:masters", "operator", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// authorized wraps a body with a valid operatorauth token for POST
	// /release-credential, so the test reaches the branch after AUTHORIZE.
	authorized := func(body []byte) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/release-credential", bytes.NewReader(body))
		authz, err := signer.Authorization(http.MethodPost, "/release-credential", body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", authz)
		return req
	}
	mustJSON := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tamperedCSR := csrPEMFromKey(t, ecKey)
	// Flip the final signature byte: still parses, fails CheckSignature at
	// sign time — the 500 branch.
	der := decodeOnePEM(t, tamperedCSR, "CERTIFICATE REQUEST")
	der[len(der)-1] ^= 0xFF
	tamperedCSR = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	tests := []struct {
		name       string
		req        *http.Request
		wantStatus int
		wantBody   string
	}{
		{
			name:       "unknown path",
			req:        httptest.NewRequest(http.MethodPost, "/other", nil),
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "wrong method",
			req:        httptest.NewRequest(http.MethodGet, "/release-credential", nil),
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "body read error",
			req:        httptest.NewRequest(http.MethodPost, "/release-credential", errReader{}),
			wantStatus: http.StatusBadRequest,
			wantBody:   "read body",
		},
		{
			name:       "missing authorization",
			req:        httptest.NewRequest(http.MethodPost, "/release-credential", bytes.NewReader([]byte("{}"))),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "authorized but not JSON",
			req:        authorized([]byte("{not json")),
			wantStatus: http.StatusBadRequest,
			wantBody:   "bad request",
		},
		{
			name:       "CSR not PEM",
			req:        authorized(mustJSON(releaseRequest{CSRPEM: "garbage"})),
			wantStatus: http.StatusBadRequest,
			wantBody:   "bad CSR",
		},
		{
			name: "CSR PEM with garbage DER",
			req: authorized(mustJSON(releaseRequest{CSRPEM: string(pem.EncodeToMemory(
				&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("junk")}))})),
			wantStatus: http.StatusBadRequest,
			wantBody:   "bad CSR",
		},
		{
			name:       "CSR with RSA key",
			req:        authorized(mustJSON(releaseRequest{CSRPEM: string(csrPEMFromKey(t, rsaKey))})),
			wantStatus: http.StatusBadRequest,
			wantBody:   "want ECDSA",
		},
		{
			name:       "CSR with tampered self-signature",
			req:        authorized(mustJSON(releaseRequest{CSRPEM: string(tamperedCSR)})),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "sign",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantBody != "" && !bytes.Contains(rec.Body.Bytes(), []byte(tc.wantBody)) {
				t.Errorf("body %q does not contain %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}
