package credrelease

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

// testCA builds a self-signed ECDSA CA standing in for the RKE2 client-CA.
func testCA(t *testing.T) *clusterCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          bigOne(),
		Subject:               pkix.Name{CommonName: "test-client-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &clusterCA{cert: cert, key: key}
}

func testCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ignored-by-signer"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestSignOperatorCert issues a cert and checks it: chains to the CA, carries
// the requested kube identity (O -> group, CN -> user), is client-auth only,
// and honours the TTL.
func TestSignOperatorCert(t *testing.T) {
	ca := testCA(t)
	csr := testCSR(t)
	now := time.Now()

	certPEM, err := ca.signOperatorCert(signParams{
		csr: csr,
		org: "system:masters",
		cn:  "operator",
		ttl: 24 * time.Hour,
	}, now)
	if err != nil {
		t.Fatalf("signOperatorCert: %v", err)
	}

	cert := parseLeaf(t, certPEM)

	// Identity: the signer sets Subject from signParams, not the CSR.
	if cert.Subject.CommonName != "operator" {
		t.Errorf("CN = %q, want operator", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "system:masters" {
		t.Errorf("O = %v, want [system:masters]", cert.Subject.Organization)
	}
	// Client auth only.
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
	// Chains to the CA.
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: now,
	}); err != nil {
		t.Errorf("issued cert does not chain to CA: %v", err)
	}
	// TTL.
	if got := cert.NotAfter.Sub(now).Round(time.Hour); got != 24*time.Hour {
		t.Errorf("TTL = %v, want 24h", got)
	}
}

// TestSignOperatorCertRejectsBadCSR: a CSR with a broken self-signature is
// refused (the signer verifies it).
func TestSignOperatorCertRejectsBadCSR(t *testing.T) {
	ca := testCA(t)
	csr := testCSR(t)
	csr.Signature = []byte("tampered") // invalidate the self-signature

	if _, err := ca.signOperatorCert(signParams{
		csr: csr, org: "system:masters", cn: "operator", ttl: time.Hour,
	}, time.Now()); err == nil {
		t.Error("expected error for CSR with invalid self-signature")
	}
}

// TestParseCAKey covers the PEM encodings the supported distributions emit:
// SEC1 EC (RKE2), PKCS#1 RSA (kubeadm), and PKCS#8.
func TestParseCAKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	sec1, _ := x509.MarshalECPrivateKey(ecKey)
	if _, err := parseCAKey(sec1, "EC PRIVATE KEY"); err != nil {
		t.Errorf("SEC1 EC: %v", err)
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)
	if _, err := parseCAKey(pkcs1, "RSA PRIVATE KEY"); err != nil {
		t.Errorf("PKCS#1 RSA: %v", err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	if _, err := parseCAKey(pkcs8, "PRIVATE KEY"); err != nil {
		t.Errorf("PKCS#8: %v", err)
	}
	if _, err := parseCAKey(sec1, "CERTIFICATE"); err == nil {
		t.Error("unsupported PEM type accepted")
	}
}

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block := decodeOnePEM(t, certPEM, "CERTIFICATE")
	cert, err := x509.ParseCertificate(block)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
