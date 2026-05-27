package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/issuerapi"
)

type staticKeyProvider struct{ pub *ecdsa.PublicKey }

func (s staticKeyProvider) PublicKey(string) (*ecdsa.PublicKey, error) { return s.pub, nil }

func newTestSignCSRHandler(t *testing.T) (SignCSRHandler, *ecdsa.PrivateKey, *issuer.CA) {
	t.Helper()
	ca, err := issuer.NewCA("test ca", 2*issuer.MaxLeafTTL)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	earKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ear key: %v", err)
	}
	return SignCSRHandler{
		CA:             ca,
		CAChainPEM:     certutil.EncodeCertPEM(ca.Cert.Raw),
		MaxTTL:         time.Hour,
		KeyProvider:    staticKeyProvider{pub: &earKey.PublicKey},
		ExpectedIssuer: "cds",
		RequestTimeout: time.Second,
	}, earKey, ca
}

type earClaimsLite struct {
	Issuer    string         `json:"iss"`
	IssuedAt  int64          `json:"iat"`
	NotBefore int64          `json:"nbf,omitempty"`
	Expiry    int64          `json:"exp"`
	TEEPubKey string         `json:"tee_public_key,omitempty"`
	Submods   map[string]any `json:"submods,omitempty"`
}

func signEAR(t *testing.T, key *ecdsa.PrivateKey, claims earClaimsLite) string {
	t.Helper()
	tokenClaims := jwt.MapClaims{
		earclaims.Issuer:    claims.Issuer,
		earclaims.IssuedAt:  claims.IssuedAt,
		earclaims.ExpiresAt: claims.Expiry,
	}
	if claims.NotBefore != 0 {
		tokenClaims[earclaims.NotBefore] = claims.NotBefore
	}
	if claims.TEEPubKey != "" {
		tokenClaims[earclaims.TEEPublicKey] = claims.TEEPubKey
	}
	if claims.Submods != nil {
		tokenClaims[earclaims.Submods] = claims.Submods
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, tokenClaims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

func teePubKeyB64(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal csr pubkey: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func csrFor(t *testing.T, subject pkix.Name, dns []string) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen csr key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject, DNSNames: dns}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	return csr, key
}

func postSignCSR(t *testing.T, h SignCSRHandler, ear string, csrDER []byte, ttl time.Duration) *httptest.ResponseRecorder {
	t.Helper()
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, err := json.Marshal(issuerapi.SignCSRRequest{
		EAR: ear,
		CSR: issuerapi.MustPEMData(csrPEM),
		TTL: issuerapi.Duration{Duration: ttl},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSignCSR(w, req)
	return w
}

func TestSignCSR_HappyPath(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(5 * time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp issuerapi.SignCSRResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	leaf, err := certutil.ParseCertificatePEM(resp.Certificate.Bytes())
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if err := leaf.CheckSignatureFrom(h.CA.Cert); err != nil {
		t.Fatalf("leaf not signed by handler CA: %v", err)
	}
}

func TestSignCSR_RejectsUnknownFields(t *testing.T) {
	h, _, _ := newTestSignCSRHandler(t)
	body := []byte(`{"ear":"","csr":"","ttl":"1h","extra":"unknown"}`)
	req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSignCSR(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_RejectsWrongIssuer(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "not-cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_RejectsExpiredToken(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Add(-time.Hour).Unix(),
		Expiry:    time.Now().Add(-10 * time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_RejectsFutureNotBefore(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Add(2 * time.Minute).Unix(),
		Expiry:    time.Now().Add(5 * time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_RejectsMissingExp(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
		// no Expiry
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_RejectsSignedByWrongKey(t *testing.T) {
	h, _, _ := newTestSignCSRHandler(t)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, wrongKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_RejectsKeyBindingMismatch(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, otherKey),
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "key_binding") {
		t.Errorf("body should mention key_binding; got %s", w.Body.String())
	}
}

func TestSignCSR_EnforcesMeasurementAllowlist(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	approved := "approved-digest"
	h.Measurements = map[string]bool{strings.ToLower(approved): true}
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)

	digest := sha256.Sum256([]byte("evidence"))
	_ = digest
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
		Submods: map[string]any{
			"cpu0": map[string]any{
				"ear.veraison.annotated-evidence": map[string]any{
					"snp": map[string]any{"measurement": "unapproved-digest"},
				},
			},
		},
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_MeasurementAllowlistCaseInsensitive(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	h.Measurements = map[string]bool{"deadbeef": true}
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
		Submods: map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.LaunchDigest: "DEADBEEF",
			},
		},
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusOK {
		t.Fatalf("uppercase digest with lowercase allowlist: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_EnforcesDNSSANPolicy(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	h.Policy.DNSSANPattern = regexp.MustCompile(`^allowed\.svc$`)
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, []string{"forbidden.svc"})
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})

	w := postSignCSR(t, h, ear, csr.Raw, time.Hour)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestSignCSR_CapsTTL(t *testing.T) {
	h, earKey, _ := newTestSignCSRHandler(t)
	h.MaxTTL = 30 * time.Minute
	csr, csrKey := csrFor(t, pkix.Name{CommonName: "test-node"}, nil)
	ear := signEAR(t, earKey, earClaimsLite{
		Issuer:    "cds",
		IssuedAt:  time.Now().Unix(),
		Expiry:    time.Now().Add(time.Minute).Unix(),
		TEEPubKey: teePubKeyB64(t, csrKey),
	})

	w := postSignCSR(t, h, ear, csr.Raw, 24*time.Hour)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp issuerapi.SignCSRResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	leaf, err := certutil.ParseCertificatePEM(resp.Certificate.Bytes())
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	got := leaf.NotAfter.Sub(leaf.NotBefore)
	if got > h.MaxTTL+time.Minute {
		t.Errorf("TTL not capped: got %v, want <= %v", got, h.MaxTTL)
	}
}
