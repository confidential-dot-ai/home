package cdsclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/types"
)

// fakeASEvidence stands up a minimal attestation-service stub that returns
// canned SNP evidence for any /attest call. Required because RequestCert
// dials the AS to embed an attestation report into the CSR before talking
// to CDS — we want the test to fail at the CDS TLS handshake, not at
// CSR construction.
func fakeASEvidence(t *testing.T) *httptest.Server {
	t.Helper()
	report := make([]byte, ratls.SNPReportSize)
	evidence, err := json.Marshal(map[string]string{
		"attestation_report": base64.StdEncoding.EncodeToString(report),
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(types.AttestResponse{
			Platform: "snp",
			Evidence: evidence,
		})
	}))
}

// TestProviderRATLSRejectsUnattestedCDS proves the cdsclient's default
// (no HTTPClient override) http.Client refuses to talk to an CDS server
// whose serving cert lacks an RA-TLS attestation extension. This is the
// safety net that closes the bootstrap-channel MITM gap: an on-path attacker
// cannot present a TEE-attested cert with an allowed measurement, so the TLS
// handshake fails before any cert-issuance bytes flow.
func TestProviderRATLSRejectsUnattestedCDS(t *testing.T) {
	as := fakeASEvidence(t)
	defer as.Close()

	// Plain HTTPS server with a regular self-signed cert (no RA-TLS extension).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request to unattested CDS: %s", r.URL.Path)
	}))
	defer srv.Close()

	p, err := NewProvider(&Config{
		CDSURL:                srv.URL,
		AttestationServiceURL: as.URL,
		CDSCAURL:              "http://unused.invalid",
		NodeIP:                "10.0.0.1",
		TEEType:               ratls.TEETypeSEVSNP,
		CDSMeasurements:       [][]byte{make([]byte, ratls.SNPMeasurementSize)},
		// HTTPClient deliberately nil so NewClient builds the RA-TLS transport.
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = p.Provision(context.Background())
	if err == nil {
		t.Fatal("Provision succeeded against unattested CDS")
	}
	// The exact error wording depends on which side of the handshake fails
	// first, but it must be a TLS-layer failure (not e.g. a parse error from
	// a successful HTTP exchange).
	if !strings.Contains(err.Error(), "tls") && !strings.Contains(err.Error(), "ratls") && !strings.Contains(err.Error(), "x509") {
		t.Fatalf("Provision error = %v, want TLS/RA-TLS handshake failure", err)
	}
}

// TestProviderRATLSRejectsCertWithoutAttestationExtension is a tighter test
// than the previous one: it stands up an HTTPS server whose cert is issued by
// a well-known x509 path (not self-signed by httptest), and confirms the
// cdsclient still rejects it because the cert lacks the RA-TLS extension.
func TestProviderRATLSRejectsCertWithoutAttestationExtension(t *testing.T) {
	as := fakeASEvidence(t)
	defer as.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rogue-cds"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"127.0.0.1", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request: %s", r.URL.Path)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	defer srv.Close()

	p, err := NewProvider(&Config{
		CDSURL:                srv.URL,
		AttestationServiceURL: as.URL,
		CDSCAURL:              "http://unused.invalid",
		NodeIP:                "10.0.0.1",
		TEEType:               ratls.TEETypeSEVSNP,
		CDSMeasurements:       [][]byte{make([]byte, ratls.SNPMeasurementSize)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Provision(context.Background()); err == nil {
		t.Fatal("Provision accepted CDS cert without an RA-TLS attestation extension")
	}
}
