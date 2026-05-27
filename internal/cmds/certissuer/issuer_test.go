package certissuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/issuerapi"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/resources"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/time/rate"
)

// newSignCSRRequest builds a signCSRRequest from raw string values,
// matching the old constructor style for test convenience.
func newSignCSRRequest(ear, csrPEM, ttl string) signCSRRequest {
	req := signCSRRequest{EAR: ear}
	if csrPEM != "" {
		req.CSR = issuerapi.MustPEMData([]byte(csrPEM))
	}
	if ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil {
			panic("bad TTL in test: " + err.Error())
		}
		req.TTL = issuerapi.Duration{Duration: d}
	}
	return req
}

// testIssuer creates an Issuer with a fresh CA keypair and token-signer keypair.
func testIssuer(t *testing.T) (*Issuer, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate CA keypair (P-384 as in plan).
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCert := selfSignedCA(t, caKey, "Test Mesh CA")

	// Generate token-signer keypair (P-256, matching KBS).
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenCert := selfSignedLeaf(t, tokenKey, "KBS Token Signer")

	iss := &Issuer{
		keyProvider:   mustCertKeyProvider(t, tokenCert),
		MaxTTL:        24 * time.Hour,
		MinCAValidity: time.Hour,
		Logger:        slog.Default(),
		tracker:       newNodeTracker(24 * time.Hour),
	}
	iss.bundle.Store(&certBundle{
		caCert:          caCert,
		caKey:           caKey,
		tokenSignerCert: tokenCert,
	})

	return iss, tokenKey
}

func mustCertKeyProvider(t *testing.T, cert *x509.Certificate) *issuer.CertKeyProvider {
	t.Helper()
	p, err := issuer.NewCertKeyProvider(cert)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func selfSignedCA(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func selfSignedLeaf(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func validTestEARClaims(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims)+3)
	for k, v := range claims {
		out[k] = v
	}
	if _, ok := out[earclaims.EATProfile]; !ok {
		out[earclaims.EATProfile] = earclaims.EARProfileTag
	}
	if _, ok := out[earclaims.EARVerifierID]; !ok {
		out[earclaims.EARVerifierID] = map[string]any{
			earclaims.Developer: "test",
			earclaims.Build:     "test",
		}
	}
	if !hasNonEmptyObjectClaim(out[earclaims.Submods]) {
		out[earclaims.Submods] = map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.EARStatus: 2,
			},
		}
	}
	return out
}

func hasNonEmptyObjectClaim(v any) bool {
	switch typed := v.(type) {
	case map[string]any:
		return len(typed) > 0
	case map[string]string:
		return len(typed) > 0
	case map[string]json.RawMessage:
		return len(typed) > 0
	default:
		return false
	}
}

// signJWT creates an ES256 JWT signed by the given key, adding mandatory EAR
// shape fields unless the caller provided them.
func signJWT(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	claims = validTestEARClaims(claims)
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload

	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}

	// Encode as r||s (each 32 bytes for P-256).
	keySize := 32
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func teePubKeyB64(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func generateCSR(t *testing.T, key *ecdsa.PrivateKey, cn string, ips ...net.IP) string {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func generateCSRWithDNS(t *testing.T, key *ecdsa.PrivateKey, cn string, dnsNames []string, ips ...net.IP) string {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func generateCSRWithSubject(t *testing.T, key *ecdsa.PrivateKey, subject pkix.Name, ips ...net.IP) string {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:     subject,
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func generateCSRWithExtraExtension(t *testing.T, key *ecdsa.PrivateKey, cn string, ext pkix.Extension, ips ...net.IP) string {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		IPAddresses:     ips,
		ExtraExtensions: []pkix.Extension{ext},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func TestHandleSignCSR(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	iss.SANValidation = true

	// Generate a key for the CSR.
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := generateCSR(t, csrKey, "ratls-mesh-10.0.0.1", net.ParseIP("10.0.0.1"))

	now := time.Now()
	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     now.Unix(),
		earclaims.ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "12h"))

	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	var signResp signCSRResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		t.Fatal(err)
	}

	if signResp.Certificate.DER() == nil {
		t.Fatal("empty certificate in response")
	}
	if signResp.CACertificate.DER() == nil {
		t.Fatal("empty CA certificate in response")
	}

	// Parse the issued cert and verify it.
	issuedCert, err := x509.ParseCertificate(signResp.Certificate.DER())
	if err != nil {
		t.Fatal(err)
	}

	// Check subject — O, OU should be stripped.
	if issuedCert.Subject.CommonName != "ratls-mesh-10.0.0.1" {
		t.Errorf("CN = %q, want %q", issuedCert.Subject.CommonName, "ratls-mesh-10.0.0.1")
	}
	if len(issuedCert.Subject.Organization) != 0 {
		t.Errorf("Organization should be stripped, got %v", issuedCert.Subject.Organization)
	}

	// Check IP SAN.
	if len(issuedCert.IPAddresses) == 0 || !issuedCert.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("IP SAN = %v, want [10.0.0.1]", issuedCert.IPAddresses)
	}

	// Check ExtKeyUsage.
	if len(issuedCert.ExtKeyUsage) != 2 {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth, ClientAuth]", issuedCert.ExtKeyUsage)
	}

	// Verify the certificate chains to the CA.
	caPool := x509.NewCertPool()
	caPool.AddCert(iss.getBundle().caCert)
	if _, err := issuedCert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("certificate does not chain to CA: %v", err)
	}
}

func TestHandleSignCSR_SubjectStripped(t *testing.T) {
	iss, tokenKey := testIssuer(t)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// CSR with O, OU set — should be stripped from issued cert.
	csr := generateCSRWithSubject(t, csrKey, pkix.Name{
		CommonName:         "test-node",
		Organization:       []string{"Evil Corp"},
		OrganizationalUnit: []string{"Pwn Unit"},
		Country:            []string{"XX"},
	})

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "1h"))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusOK {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("expected 200, got %d: %s", w.Code, respBody)
	}

	var resp signCSRResponse
	json.NewDecoder(w.Result().Body).Decode(&resp)
	cert, _ := x509.ParseCertificate(resp.Certificate.DER())

	if cert.Subject.CommonName != "test-node" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "test-node")
	}
	if len(cert.Subject.Organization) != 0 {
		t.Errorf("Organization should be stripped, got %v", cert.Subject.Organization)
	}
	if len(cert.Subject.OrganizationalUnit) != 0 {
		t.Errorf("OU should be stripped, got %v", cert.Subject.OrganizationalUnit)
	}
	if len(cert.Subject.Country) != 0 {
		t.Errorf("Country should be stripped, got %v", cert.Subject.Country)
	}
}

func TestHandleSignCSR_ExpiredToken(t *testing.T) {
	iss, tokenKey := testIssuer(t)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSR(t, csrKey, "test-node")

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:    "kbs",
		earclaims.IssuedAt:  time.Now().Add(-10 * time.Minute).Unix(),
		earclaims.ExpiresAt: time.Now().Add(-5 * time.Minute).Unix(), // expired
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, ""))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d", w.Code)
	}
}

func TestHandleSignCSR_InvalidSignature(t *testing.T) {
	iss, _ := testIssuer(t)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSR(t, csrKey, "test-node")

	// Sign with a different key than the token-signer cert.
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ear := signJWT(t, wrongKey, map[string]any{
		earclaims.Issuer:    "kbs",
		earclaims.IssuedAt:  time.Now().Unix(),
		earclaims.ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, ""))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid signature, got %d", w.Code)
	}
}

func TestHandleSignCSR_TTLCapped(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	iss.MaxTTL = 1 * time.Hour

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSR(t, csrKey, "test-node")

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "48h"))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusOK {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("expected 200, got %d: %s", w.Code, respBody)
	}

	var resp signCSRResponse
	json.NewDecoder(w.Result().Body).Decode(&resp)

	cert, _ := x509.ParseCertificate(resp.Certificate.DER())

	actualTTL := cert.NotAfter.Sub(cert.NotBefore)
	if actualTTL > 1*time.Hour+time.Minute { // small tolerance
		t.Errorf("TTL = %v, expected capped to ~1h", actualTTL)
	}
}

func TestSignCSRWithBundleUsesCapturedSigner(t *testing.T) {
	iss, _ := testIssuer(t)
	captured := iss.getBundle()
	replacement, _ := testIssuer(t)
	iss.bundle.Store(replacement.getBundle())

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrPEM := generateCSR(t, csrKey, "test-node")
	csr, err := x509.ParseCertificateRequest(issuerapi.MustPEMData([]byte(csrPEM)).DER())
	if err != nil {
		t.Fatal(err)
	}
	claims := &issuer.EARClaims{RawEvidence: json.RawMessage(`{"test":true}`)}

	certPEM, _, err := iss.signCSRWithBundle(captured, csr, claims, time.Hour)
	if err != nil {
		t.Fatalf("signCSRWithBundle failed: %v", err)
	}
	cert, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(captured.caCert); err != nil {
		t.Fatalf("leaf was not signed by captured CA: %v", err)
	}
	if err := cert.CheckSignatureFrom(replacement.getBundle().caCert); err == nil {
		t.Fatal("leaf unexpectedly verifies against replacement CA")
	}
}

func TestHandleCA(t *testing.T) {
	iss, _ := testIssuer(t)

	req := httptest.NewRequest("GET", "/ca", nil)
	w := httptest.NewRecorder()
	iss.HandleCA(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	block, _ := pem.Decode([]byte(body))
	if block == nil {
		t.Fatal("no PEM block in response")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "Test Mesh CA" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "Test Mesh CA")
	}
}

func TestHandlePublicCA_Public(t *testing.T) {
	iss, _ := testIssuer(t)
	bm := issuer.NewBundleManager(iss.MaxTTL, "", "default/mesh/ca-bundle", slog.Default())
	bm.SetInitial(iss.getBundle().caCert)

	req := httptest.NewRequest("GET", "/ca", nil)
	w := httptest.NewRecorder()
	handlePublicCA(bm)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if block, _ := pem.Decode(w.Body.Bytes()); block == nil {
		t.Fatal("no PEM block in public CA response")
	}
}

func TestCapTTL(t *testing.T) {
	maxTTL := 24 * time.Hour

	tests := []struct {
		input time.Duration
		want  time.Duration
	}{
		{0, 24 * time.Hour}, // zero → max
		{12 * time.Hour, 12 * time.Hour},
		{48 * time.Hour, 24 * time.Hour}, // capped
		{30 * time.Minute, 30 * time.Minute},
		{-1 * time.Hour, 24 * time.Hour}, // negative → max
	}

	for _, tt := range tests {
		got := capTTL(tt.input, maxTTL)
		if got != tt.want {
			t.Errorf("capTTL(%v) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestLiveEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/live", nil)
	w := httptest.NewRecorder()
	handleLive(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// signJWT384 creates an ES384 JWT signed by the given P-384 key, adding
// mandatory EAR shape fields unless the caller provided them.
func signJWT384(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES384","typ":"JWT"}`))
	claims = validTestEARClaims(claims)
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload

	h := sha512.Sum384([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}

	keySize := 48 // P-384
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestHandleSignCSR_ES384(t *testing.T) {
	// Generate a P-384 token-signer key.
	tokenKey384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenCert384 := selfSignedLeaf(t, tokenKey384, "KBS Token Signer P384")

	// Generate CA keypair (P-384).
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCert := selfSignedCA(t, caKey, "Test Mesh CA")

	iss := &Issuer{
		keyProvider:   mustCertKeyProvider(t, tokenCert384),
		MaxTTL:        24 * time.Hour,
		MinCAValidity: time.Hour,
		SANValidation: true,
		Logger:        slog.Default(),
		tracker:       newNodeTracker(24 * time.Hour),
	}
	iss.bundle.Store(&certBundle{
		caCert:          caCert,
		caKey:           caKey,
		tokenSignerCert: tokenCert384,
	})

	// Generate a P-256 key for the CSR.
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := generateCSR(t, csrKey, "ratls-mesh-10.0.0.2", net.ParseIP("10.0.0.2"))

	now := time.Now()
	ear := signJWT384(t, tokenKey384, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     now.Unix(),
		earclaims.ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence-384",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "12h"))

	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	req.RemoteAddr = "10.0.0.2:12345"
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	var signResp signCSRResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		t.Fatal(err)
	}

	if signResp.Certificate.DER() == nil {
		t.Fatal("empty certificate in response")
	}

	// Parse the issued cert and verify it chains to the CA.
	issuedCert, err := x509.ParseCertificate(signResp.Certificate.DER())
	if err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(iss.getBundle().caCert)
	if _, err := issuedCert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("certificate does not chain to CA: %v", err)
	}

	if len(issuedCert.IPAddresses) == 0 || !issuedCert.IPAddresses[0].Equal(net.ParseIP("10.0.0.2")) {
		t.Errorf("IP SAN = %v, want [10.0.0.2]", issuedCert.IPAddresses)
	}
}

func TestHandleSignCSR_KeyBindingMismatch(t *testing.T) {
	iss, tokenKey := testIssuer(t)

	// Generate two different P-256 keys.
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	differentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	csr := generateCSR(t, csrKey, "ratls-mesh-10.0.0.3", net.ParseIP("10.0.0.3"))

	// Marshal differentKey's public key as DER PKIX and base64url-encode it.
	diffPubDER, err := x509.MarshalPKIXPublicKey(&differentKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	teePubKey := base64.RawURLEncoding.EncodeToString(diffPubDER)

	now := time.Now()
	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     now.Unix(),
		earclaims.ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKey,
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, ""))

	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusForbidden {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Errorf("expected 403 for key binding mismatch, got %d: %s", w.Code, respBody)
	}

	// Verify error message is sanitized.
	respBody := strings.TrimSpace(w.Body.String())
	if respBody != "forbidden: certificate request denied" {
		t.Errorf("error message should be sanitized, got %q", respBody)
	}
}

func TestHandleSignCSR_AttestationDigestExtension(t *testing.T) {
	iss, tokenKey := testIssuer(t)

	// Generate a key for the CSR.
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := generateCSR(t, csrKey, "ratls-mesh-10.0.0.4")

	// Use a JSON object for submods, matching real KBS EAR token format.
	rawEvidence := map[string]any{"cpu0": map[string]any{"status": "ok"}}
	now := time.Now()
	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     now.Unix(),
		earclaims.ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		earclaims.Submods:      rawEvidence,
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "12h"))

	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	var signResp signCSRResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		t.Fatal(err)
	}

	// Parse the issued certificate.
	issuedCert, err := x509.ParseCertificate(signResp.Certificate.DER())
	if err != nil {
		t.Fatal(err)
	}

	// Find the attestation digest extension.
	var attDigestExt *pkix.Extension
	for i := range issuedCert.Extensions {
		if issuedCert.Extensions[i].Id.Equal(certutil.OIDAttestationDigest) {
			attDigestExt = &issuedCert.Extensions[i]
			break
		}
	}
	if attDigestExt == nil {
		t.Fatal("attestation digest extension not found in issued certificate")
	}

	// Unmarshal the extension value (ASN.1 OCTET STRING wrapping the digest).
	var gotDigest []byte
	if _, err := asn1.Unmarshal(attDigestExt.Value, &gotDigest); err != nil {
		t.Fatalf("failed to unmarshal attestation digest extension: %v", err)
	}

	// The expected value is SHA-256 of the raw JSON evidence bytes.
	rawEvidenceJSON, _ := json.Marshal(rawEvidence)
	expectedDigest := sha256.Sum256(rawEvidenceJSON)
	if len(gotDigest) != len(expectedDigest) {
		t.Fatalf("attestation digest length = %d, want %d", len(gotDigest), len(expectedDigest))
	}
	for i := range gotDigest {
		if gotDigest[i] != expectedDigest[i] {
			t.Fatalf("attestation digest mismatch at byte %d: got %x, want %x", i, gotDigest, expectedDigest)
		}
	}
}

func TestHandleSignCSR_CopiesRATLSExtension(t *testing.T) {
	iss, tokenKey := testIssuer(t)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantExt := pkix.Extension{
		Id:       ratls.OIDRATLSAttestation,
		Critical: true,
		Value:    []byte{0x30, 0x03, 0x02, 0x01, 0x01},
	}
	csr := generateCSRWithExtraExtension(t, csrKey, "ratls-mesh-10.0.0.4", wantExt)

	now := time.Now()
	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     now.Unix(),
		earclaims.ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		earclaims.Submods:      map[string]any{"cpu0": map[string]any{"status": "ok"}},
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "12h"))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}
	var signResp signCSRResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		t.Fatal(err)
	}
	issuedCert, err := x509.ParseCertificate(signResp.Certificate.DER())
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range issuedCert.Extensions {
		if ext.Id.Equal(ratls.OIDRATLSAttestation) {
			if ext.Critical {
				t.Fatal("issued RA-TLS extension should not be critical")
			}
			if !bytes.Equal(ext.Value, wantExt.Value) {
				t.Fatalf("issued RA-TLS extension value = %x, want %x", ext.Value, wantExt.Value)
			}
			return
		}
	}
	t.Fatal("issued certificate missing RA-TLS extension")
}

func TestHandleSignCSR_RejectsMissingTEEPublicKey(t *testing.T) {
	iss, tokenKey := testIssuer(t)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSR(t, csrKey, "test-node")

	// Chart-managed Assam EAR tokens must bind the CSR key to the attested TEE.
	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:    "kbs",
		earclaims.IssuedAt:  time.Now().Unix(),
		earclaims.ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:   "test-evidence",
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, ""))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing tee_public_key, got %d", w.Code)
	}
}

func TestHandleSignCSR_FutureIAT(t *testing.T) {
	iss, tokenKey := testIssuer(t)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSR(t, csrKey, "test-node")

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Add(10 * time.Minute).Unix(), // future
		earclaims.ExpiresAt:    time.Now().Add(15 * time.Minute).Unix(),
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, ""))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for future iat, got %d", w.Code)
	}
}

func TestSignCSR_ReturnsSerial(t *testing.T) {
	iss, tokenKey := testIssuer(t)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrPEM := generateCSR(t, csrKey, "test-node", net.ParseIP("10.0.0.5"))

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("no PEM block in CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})
	claims, err := issuer.ValidateEARToken(ear, mustCertKeyProvider(t, iss.getBundle().tokenSignerCert), "")
	if err != nil {
		t.Fatal(err)
	}

	certPEM, serial, err := iss.signCSR(csr, claims, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if serial == nil || serial.Sign() <= 0 {
		t.Fatal("expected positive serial number")
	}
	if len(certPEM) == 0 {
		t.Fatal("expected non-empty certificate PEM")
	}
}

func TestMetricsIncremented(t *testing.T) {
	iss, tokenKey := testIssuer(t)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSR(t, csrKey, "test-node")

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "1h"))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusOK {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("expected 200, got %d: %s", w.Code, respBody)
	}

	// Verify that certificatesIssuedTotal was incremented.
	if got := testutil.ToFloat64(certificatesIssuedTotal); got < 1 {
		t.Errorf("certificatesIssuedTotal = %v, want >= 1", got)
	}

	// Verify active requests is back to 0.
	if got := testutil.ToFloat64(activeRequests); got != 0 {
		t.Errorf("activeRequests = %v, want 0", got)
	}
}

func TestRateLimiting(t *testing.T) {
	iss, tokenKey := testIssuer(t)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSR(t, csrKey, "test-node")

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "1h"))

	// Create a very tight rate limiter: 1 req/s, burst 1.
	rl := newIPRateLimiter(rate.Limit(1), 1, 10000)
	handler := rateLimitMiddleware(rl, http.HandlerFunc(iss.HandleSignCSR))

	// First request should succeed.
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("first request: expected 200, got %d: %s", w.Code, respBody)
	}

	// Second immediate request should be rate limited.
	req2 := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	req2.RemoteAddr = "10.0.0.1:12346"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}
}

func TestTokenValidationError_Typed(t *testing.T) {
	iss, _ := testIssuer(t)

	// Completely garbage JWT.
	_, err := issuer.ValidateEARToken("not.a.jwt", mustCertKeyProvider(t, iss.getBundle().tokenSignerCert), "")
	if err == nil {
		t.Fatal("expected error for garbage JWT")
	}

	var tve *issuer.TokenValidationError
	if !errors.As(err, &tve) {
		t.Fatalf("expected tokenValidationError, got %T: %v", err, err)
	}
	if tve.Reason != issuer.ReasonMalformed && tve.Reason != issuer.ReasonInvalidSignature {
		t.Errorf("unexpected reason %q", tve.Reason)
	}
}

func TestValidateEARTokenRequiresExpiry(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	token := signJWT(t, tokenKey, map[string]any{
		earclaims.IssuedAt: time.Now().Unix(),
	})

	_, err := issuer.ValidateEARToken(token, mustCertKeyProvider(t, iss.getBundle().tokenSignerCert), "")
	if err == nil {
		t.Fatal("expected missing expiry error")
	}
	var tve *issuer.TokenValidationError
	if !errors.As(err, &tve) {
		t.Fatalf("expected tokenValidationError, got %T: %v", err, err)
	}
	if tve.Reason != issuer.ReasonMalformed {
		t.Errorf("unexpected reason %q", tve.Reason)
	}
}

// === New tests for Phase 1-4 ===

func TestHandleSignCSR_DNSSANRejected(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	iss.SANValidation = true
	// No DNSSANPattern set — all DNS SANs should be rejected.

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSRWithDNS(t, csrKey, "test-node", []string{"kubernetes.default.svc.cluster.local"}, net.ParseIP("10.0.0.1"))

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "1h"))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusForbidden {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Errorf("expected 403 for DNS SAN with no pattern, got %d: %s", w.Code, respBody)
	}
}

func TestHandleSignCSR_DNSSANRejectedWhenSourceIPValidationDisabled(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	iss.SANValidation = false
	// No DNSSANPattern set -- all DNS SANs should still be rejected.

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSRWithDNS(t, csrKey, "test-node", []string{"kubernetes.default.svc.cluster.local"}, net.ParseIP("10.0.0.99"))

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "1h"))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusForbidden {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Errorf("expected 403 for DNS SAN with source-IP validation disabled, got %d: %s", w.Code, respBody)
	}
}

func TestHandleSignCSR_ValidDNSSAN(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	iss.SANValidation = true
	iss.DNSSANPattern = regexp.MustCompile(`^ratls-mesh-[\d]+\.local$`)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSRWithDNS(t, csrKey, "ratls-mesh-1", []string{"ratls-mesh-1.local"}, net.ParseIP("10.0.0.1"))

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "1h"))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusOK {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Errorf("expected 200 for valid DNS SAN, got %d: %s", w.Code, respBody)
	}
}

func TestHandleSignCSR_InvalidCN(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	iss.SANValidation = true
	iss.AllowedCNPattern = regexp.MustCompile(`^ratls-mesh-`)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSR(t, csrKey, "evil-impersonator", net.ParseIP("10.0.0.1"))

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "1h"))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusForbidden {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Errorf("expected 403 for invalid CN, got %d: %s", w.Code, respBody)
	}
}

func TestHandleSignCSR_InvalidCNRejectedWhenSourceIPValidationDisabled(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	iss.SANValidation = false
	iss.AllowedCNPattern = regexp.MustCompile(`^ratls-mesh-`)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSR(t, csrKey, "evil-impersonator", net.ParseIP("10.0.0.99"))

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "1h"))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusForbidden {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Errorf("expected 403 for invalid CN with source-IP validation disabled, got %d: %s", w.Code, respBody)
	}
}

func TestHandleSignCSR_WrongIssuer(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	iss.ExpectedIssuer = "expected-kbs-instance"

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := generateCSR(t, csrKey, "test-node")

	ear := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "different-kbs-instance",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})

	body, _ := json.Marshal(newSignCSRRequest(ear, csr, "1h"))
	req := httptest.NewRequest("POST", "/sign-csr", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	iss.HandleSignCSR(w, req)

	if w.Code != http.StatusUnauthorized {
		respBody, _ := io.ReadAll(w.Result().Body)
		t.Errorf("expected 401 for wrong issuer, got %d: %s", w.Code, respBody)
	}
}

func TestRateLimiterEviction(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(10), 20, 10000)

	// Add some entries.
	rl.getLimiter("10.0.0.1")
	rl.getLimiter("10.0.0.2")
	rl.getLimiter("10.0.0.3")

	rl.mu.Lock()
	if len(rl.limiters) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(rl.limiters))
	}

	// Set lastSeen to 10 minutes ago for two entries.
	oldTime := time.Now().Add(-10 * time.Minute)
	rl.limiters["10.0.0.1"].lastSeen = oldTime
	rl.limiters["10.0.0.2"].lastSeen = oldTime
	rl.mu.Unlock()

	// Run eviction.
	rl.evict(5 * time.Minute)

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.limiters) != 1 {
		t.Errorf("expected 1 entry after eviction, got %d", len(rl.limiters))
	}
	if _, ok := rl.limiters["10.0.0.3"]; !ok {
		t.Error("expected 10.0.0.3 to survive eviction")
	}
}

func TestRateLimiterMaxEntries(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(10), 20, 3)

	rl.getLimiter("10.0.0.1")
	rl.getLimiter("10.0.0.2")
	rl.getLimiter("10.0.0.3")

	rl.mu.Lock()
	if len(rl.limiters) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(rl.limiters))
	}
	rl.mu.Unlock()

	// Adding a 4th should evict the oldest.
	rl.getLimiter("10.0.0.4")

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.limiters) != 3 {
		t.Errorf("expected 3 entries after cap, got %d", len(rl.limiters))
	}
}

// === Resource map tests ===

func mustBuildEndpointAllowlists(t *testing.T, rm resources.Map) (signCSR, handoff map[string]bool) {
	t.Helper()
	signCSR, handoff, err := buildEndpointAllowlists(rm)
	if err != nil {
		t.Fatal(err)
	}
	return signCSR, handoff
}

func TestLoadResourceMap(t *testing.T) {
	mapJSON := `{
		"abc123": ["default/inference/*", "cert-issuer/sign-csr"],
		"def456": ["cert-issuer/handoff"]
	}`

	tmpFile := filepath.Join(t.TempDir(), "resource-map.json")
	if err := os.WriteFile(tmpFile, []byte(mapJSON), 0644); err != nil {
		t.Fatal(err)
	}

	rm, err := loadResourceMap(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(rm) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(rm))
	}
	if len(rm["abc123"]) != 2 {
		t.Errorf("abc123 globs = %v, want 2 entries", rm["abc123"])
	}
	if len(rm["def456"]) != 1 {
		t.Errorf("def456 globs = %v, want 1 entry", rm["def456"])
	}
}

func TestLoadResourceMap_Empty(t *testing.T) {
	rm, err := loadResourceMap("")
	if err != nil {
		t.Fatal(err)
	}
	if rm != nil {
		t.Errorf("expected nil for empty path, got %v", rm)
	}
}

func TestLoadResourceMap_InvalidJSON(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmpFile, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadResourceMap(tmpFile)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestBuildEndpointAllowlists(t *testing.T) {
	rm := resources.Map{
		"measurement_a": {resources.CertIssuerSignCSR, resources.CertIssuerHandoff},
		"measurement_b": {resources.CertIssuerHandoff},
		"measurement_c": {"default/inference/*"}, // no cert-issuer paths
	}

	signCSR, handoff := mustBuildEndpointAllowlists(t, rm)

	if !signCSR["measurement_a"] {
		t.Error("expected measurement_a allowed for sign-csr")
	}
	if signCSR["measurement_b"] {
		t.Error("measurement_b should not be allowed for sign-csr")
	}
	if len(signCSR) != 1 {
		t.Errorf("sign-csr allowlist size = %d, want 1", len(signCSR))
	}

	if !handoff["measurement_a"] || !handoff["measurement_b"] {
		t.Errorf("expected measurement_a and measurement_b allowed for handoff, got %v", handoff)
	}
	if len(handoff) != 2 {
		t.Errorf("handoff allowlist size = %d, want 2", len(handoff))
	}
}

func TestBuildEndpointAllowlists_WildcardGlob(t *testing.T) {
	rm := resources.Map{
		"measurement_wild": {"cert-issuer/*"},
	}

	signCSR, handoff := mustBuildEndpointAllowlists(t, rm)

	if !signCSR["measurement_wild"] {
		t.Error("cert-issuer/* should match sign-csr")
	}
	if !handoff["measurement_wild"] {
		t.Error("cert-issuer/* should match handoff")
	}
}

func TestBuildEndpointAllowlists_Empty(t *testing.T) {
	signCSR, handoff := mustBuildEndpointAllowlists(t, nil)
	if signCSR != nil || handoff != nil {
		t.Error("expected nil allowlists for nil resource map")
	}
}

func TestBuildEndpointAllowlists_NoCertIssuerPaths(t *testing.T) {
	rm := resources.Map{
		"measurement_x": {"default/inference/*", "default/keys/*"},
	}

	signCSR, handoff := mustBuildEndpointAllowlists(t, rm)
	if signCSR != nil || handoff != nil {
		t.Error("expected nil allowlists when no cert-issuer paths match")
	}
}

func TestBuildEndpointAllowlists_InvalidGlobFailsClosed(t *testing.T) {
	rm := resources.Map{
		"measurement_x": {"cert-issuer/["},
	}

	_, _, err := buildEndpointAllowlists(rm)
	if err == nil {
		t.Fatal("expected invalid glob error")
	}
	if !strings.Contains(err.Error(), "invalid resource map glob") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildEndpointAllowlists_HandoffOnly(t *testing.T) {
	rm := resources.Map{
		"measurement_h": {resources.CertIssuerHandoff},
	}

	signCSR, handoff := mustBuildEndpointAllowlists(t, rm)
	if signCSR != nil {
		t.Errorf("expected nil sign-csr allowlist, got %v", signCSR)
	}
	if !handoff["measurement_h"] {
		t.Error("expected measurement_h allowed for handoff")
	}
}

func TestBuildEndpointAllowlistsNormalizesMeasurements(t *testing.T) {
	rm := resources.Map{
		"DEADBEEF": {resources.CertIssuerSignCSR},
	}

	signCSR, _, err := buildEndpointAllowlists(rm)
	if err != nil {
		t.Fatalf("buildEndpointAllowlists: %v", err)
	}
	if !signCSR["deadbeef"] {
		t.Fatalf("expected lowercase measurement key, got %v", signCSR)
	}
}

func TestCheckMeasurement_WithResourceMap(t *testing.T) {
	rm := resources.Map{
		"allowed_measurement": {resources.CertIssuerSignCSR},
		"other_measurement":   {"default/inference/*"},
	}
	signCSR, _ := mustBuildEndpointAllowlists(t, rm)

	evidence := map[string]any{
		earclaims.SubmodAttester: map[string]any{
			earclaims.LaunchDigest: "allowed_measurement",
		},
	}
	rawEvidence, _ := json.Marshal(evidence)
	claims := &issuer.EARClaims{RawEvidence: rawEvidence}

	if err := issuer.CheckMeasurement(claims, signCSR, "sign-csr"); err != nil {
		t.Errorf("expected allowed for sign-csr, got: %v", err)
	}

	evidenceDenied := map[string]any{
		earclaims.SubmodAttester: map[string]any{
			earclaims.LaunchDigest: "unknown_measurement",
		},
	}
	rawDenied, _ := json.Marshal(evidenceDenied)
	claimsDenied := &issuer.EARClaims{RawEvidence: rawDenied}

	if err := issuer.CheckMeasurement(claimsDenied, signCSR, "sign-csr"); err == nil {
		t.Error("expected denial for unknown measurement on sign-csr")
	}
}

func TestCheckMeasurement_WithChartManagedAssamLaunchDigest(t *testing.T) {
	rm := resources.Map{
		"allowed_measurement": {resources.CertIssuerSignCSR},
	}
	signCSR, _ := mustBuildEndpointAllowlists(t, rm)

	evidence := map[string]any{
		earclaims.SubmodAttester: map[string]any{
			earclaims.LaunchDigest:   "allowed_measurement",
			earclaims.EARRawEvidence: map[string]any{"opaque": true},
		},
	}
	rawEvidence, _ := json.Marshal(evidence)
	claims := &issuer.EARClaims{RawEvidence: rawEvidence}

	if err := issuer.CheckMeasurement(claims, signCSR, "sign-csr"); err != nil {
		t.Errorf("expected chart-managed Assam launch_digest to be allowed, got: %v", err)
	}
}
