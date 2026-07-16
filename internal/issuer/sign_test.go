package issuer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

func mustCSR(t *testing.T, cn string, dnsNames []string, ips []net.IP, extraExtensions []pkix.Extension) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate csr key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		DNSNames:        dnsNames,
		IPAddresses:     ips,
		ExtraExtensions: extraExtensions,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	return csr, key
}

func TestCASignCSR_SignsLeafAgainstCA(t *testing.T) {
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	csr, _ := mustCSR(t, "test-node", nil, []net.IP{net.ParseIP("10.0.0.1")}, nil)

	certPEM, serial, err := ca.SignCSR(issuer.SignCSRParams{
		CSR:      csr,
		TTL:      time.Hour,
		Evidence: []byte(`{"test":true}`),
	})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if serial == nil || serial.Sign() <= 0 {
		t.Fatalf("expected positive serial, got %v", serial)
	}
	leaf, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if err := leaf.CheckSignatureFrom(ca.Cert); err != nil {
		t.Fatalf("leaf not signed by CA: %v", err)
	}
	if leaf.Subject.CommonName != "test-node" {
		t.Errorf("CN: got %q, want test-node", leaf.Subject.CommonName)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("IP SAN: got %v", leaf.IPAddresses)
	}
}

func TestCASignCSR_EmbedsAttestationDigest(t *testing.T) {
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	evidence := []byte(`{"submods":{"cpu0":"snp"}}`)
	csr, _ := mustCSR(t, "node", nil, nil, nil)

	certPEM, _, err := ca.SignCSR(issuer.SignCSRParams{
		CSR:      csr,
		TTL:      time.Hour,
		Evidence: evidence,
	})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	leaf := mustParseCert(t, certPEM)

	want := sha256.Sum256(evidence)
	got := extractAttestationDigest(t, leaf)
	if len(got) != len(want) {
		t.Fatalf("digest length: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("digest mismatch at byte %d", i)
		}
	}
}

func TestCASignCSR_AlwaysEmbedsAttestationDigest(t *testing.T) {
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	csr, _ := mustCSR(t, "node", nil, nil, nil)

	certPEM, _, err := ca.SignCSR(issuer.SignCSRParams{CSR: csr, TTL: time.Hour})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	leaf := mustParseCert(t, certPEM)

	want := sha256.Sum256(nil)
	got := extractAttestationDigest(t, leaf)
	if string(got) != string(want[:]) {
		t.Fatalf("empty-evidence digest mismatch: got %x, want %x", got, want)
	}
}

func TestCASignCSR_CopiesRATLSExtension(t *testing.T) {
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	ratlsValue := []byte{0x30, 0x03, 0x02, 0x01, 0x42}
	csr, _ := mustCSR(t, "node", nil, nil, []pkix.Extension{
		{Id: ratls.OIDRATLSAttestation, Value: ratlsValue},
	})

	certPEM, _, err := ca.SignCSR(issuer.SignCSRParams{CSR: csr, TTL: time.Hour})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	leaf := mustParseCert(t, certPEM)
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(ratls.OIDRATLSAttestation) {
			if string(ext.Value) != string(ratlsValue) {
				t.Errorf("ratls ext value mismatch: got %x, want %x", ext.Value, ratlsValue)
			}
			return
		}
	}
	t.Fatalf("RA-TLS extension not propagated to leaf")
}

func TestCASignCSR_RejectsNilCAOrCSR(t *testing.T) {
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	csr, _ := mustCSR(t, "node", nil, nil, nil)

	if _, _, err := (*issuer.CA)(nil).SignCSR(issuer.SignCSRParams{CSR: csr, TTL: time.Hour}); err == nil {
		t.Error("nil CA: expected error, got nil")
	}
	if _, _, err := ca.SignCSR(issuer.SignCSRParams{CSR: nil, TTL: time.Hour}); err == nil {
		t.Error("nil CSR: expected error, got nil")
	}
}

func mustParseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	cert, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

func extractAttestationDigest(t *testing.T, leaf *x509.Certificate) []byte {
	t.Helper()
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(certutil.OIDAttestationDigest) {
			var digest []byte
			if _, err := asn1.Unmarshal(ext.Value, &digest); err != nil {
				t.Fatalf("unmarshal digest ext: %v", err)
			}
			return digest
		}
	}
	t.Fatal("OIDAttestationDigest extension not found on leaf")
	return nil
}
