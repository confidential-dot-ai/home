package credrelease

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// testCA builds a self-signed CA standing in for the RKE2 client-CA.
func testCA(t *testing.T) *clusterCA {
	t.Helper()
	ca, err := issuer.NewCA("test-client-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &clusterCA{cert: ca.Cert, key: ca.Key}
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

// namedCA writes a fresh self-signed CA to files in dir, the key in the SEC1
// "EC PRIVATE KEY" form RKE2 writes, and returns the paths and the CA cert.
// Stands in for RKE2's distinct client-ca / server-ca on disk.
func namedCA(t *testing.T, dir, name string) (certPath, keyPath string, cert *x509.Certificate) {
	t.Helper()
	ca, err := issuer.NewCA(name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, certutil.EncodeCertPEM(ca.Cert.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, ca.Cert
}

// TestLoadClusterCAReleasesServerCA guards the CA-confusion regression: the
// released kubeconfig anchors on the server CA while issued certs chain to the
// client CA (the CA-path consts in sign.go explain the RKE2/kubeadm split).
func TestLoadClusterCAReleasesServerCA(t *testing.T) {
	dir := t.TempDir()
	clientCertPath, clientKeyPath, clientCA := namedCA(t, dir, "client-ca")
	serverCertPath, _, serverCA := namedCA(t, dir, "server-ca")

	ca, err := loadClusterCA(clientCertPath, clientKeyPath, serverCertPath)
	if err != nil {
		t.Fatal(err)
	}

	// The kubeconfig anchor is the SERVER CA and nothing else.
	if string(ca.pem) != string(certutil.EncodeCertPEM(serverCA.Raw)) {
		t.Error("clusterCA.pem is not exactly the server CA; kubeconfig would fail apiserver verification")
	}

	// A cert issued by the loaded CA chains to the CLIENT CA: proves the cert
	// and the key both came from the client-CA files.
	certPEM, err := ca.signOperatorCert(signParams{
		csr: testCSR(t), org: "system:masters", cn: "operator", ttl: time.Hour,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(clientCA)
	if _, err := parseLeaf(t, certPEM).Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("issued cert does not chain to the client CA: %v", err)
	}
}

// TestLoadClusterCAKubeadmSingleCA covers the kubeadm shape: one RSA ca.crt
// with a PKCS#1 ca.key signs both serving and client certs, so all three
// paths point at the same files.
func TestLoadClusterCAKubeadmSingleCA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := certutil.GenerateSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := certutil.NewCATemplate(serial, "kubernetes", time.Now().Add(time.Hour))
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := certutil.EncodeCertPEM(der)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	ca, err := loadClusterCA(certPath, keyPath, certPath)
	if err != nil {
		t.Fatalf("single-CA (kubeadm) load failed: %v", err)
	}
	if string(ca.pem) != string(certPEM) {
		t.Error("single-CA anchor mismatch")
	}
}

// TestLoadClusterCAErrors drives every refusal branch: missing files and each
// malformed PEM shape for the three inputs.
func TestLoadClusterCAErrors(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := namedCA(t, dir, "client-ca")
	serverPath, _, _ := namedCA(t, dir, "server-ca")

	write := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	notPEM := write("not-pem", []byte("junk"))
	wrongTypeCert := write("wrong-type.crt", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("x")}))
	badDERCert := write("bad-der.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))
	badTypeKey := write("bad-type.key", pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("x")}))
	missing := filepath.Join(dir, "does-not-exist")

	tests := []struct {
		name                string
		cert, key, serverCA string
		wantErr             string
	}{
		{"missing client cert", missing, keyPath, serverPath, "read client CA cert"},
		{"missing client key", certPath, missing, serverPath, "read client CA key"},
		{"missing server CA", certPath, keyPath, missing, "read server CA cert"},
		{"client cert wrong PEM type", wrongTypeCert, keyPath, serverPath, "not a CERTIFICATE PEM"},
		{"client cert bad DER", badDERCert, keyPath, serverPath, "parse client CA cert"},
		{"client key not PEM", certPath, notPEM, serverPath, "is not PEM"},
		{"client key unsupported type", certPath, badTypeKey, serverPath, "parse client CA key"},
		{"server CA wrong PEM type", certPath, keyPath, wrongTypeCert, "not a CERTIFICATE PEM"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadClusterCA(tc.cert, tc.key, tc.serverCA)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestParseCAKeyPKCS8Errors: garbage PKCS#8 DER fails to parse, and a valid
// PKCS#8 key that cannot sign (X25519) is refused.
func TestParseCAKeyPKCS8Errors(t *testing.T) {
	if _, err := parseCAKey([]byte("junk"), "PRIVATE KEY"); err == nil {
		t.Error("garbage PKCS#8 DER accepted")
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(xKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseCAKey(der, "PRIVATE KEY"); err == nil || !strings.Contains(err.Error(), "cannot sign") {
		t.Errorf("X25519 key: err = %v, want \"cannot sign\"", err)
	}
}

// TestSignOperatorCertNilCSR: a nil CSR is refused before any signing.
func TestSignOperatorCertNilCSR(t *testing.T) {
	if _, err := testCA(t).signOperatorCert(signParams{
		org: "system:masters", cn: "operator", ttl: time.Hour,
	}, time.Now()); err == nil || !strings.Contains(err.Error(), "nil CSR") {
		t.Errorf("err = %v, want nil CSR error", err)
	}
}

// TestSignOperatorCertSerialErrors: a failing serial source and a serial
// CreateCertificate rejects (negative) both surface as errors.
func TestSignOperatorCertSerialErrors(t *testing.T) {
	ca := testCA(t)
	csr := testCSR(t)

	if _, err := ca.signOperatorCert(signParams{
		csr: csr, org: "o", cn: "cn", ttl: time.Hour,
		serialFn: func() (*big.Int, error) { return nil, errors.New("entropy exhausted") },
	}, time.Now()); err == nil || !strings.Contains(err.Error(), "serial") {
		t.Errorf("serialFn error: err = %v, want serial error", err)
	}

	if _, err := ca.signOperatorCert(signParams{
		csr: csr, org: "o", cn: "cn", ttl: time.Hour,
		serialFn: func() (*big.Int, error) { return big.NewInt(-1), nil },
	}, time.Now()); err == nil || !strings.Contains(err.Error(), "sign") {
		t.Errorf("negative serial: err = %v, want sign error", err)
	}
}
