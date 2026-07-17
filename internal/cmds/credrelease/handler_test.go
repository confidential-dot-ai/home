package credrelease

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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
