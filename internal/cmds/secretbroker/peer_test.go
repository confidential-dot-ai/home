package secretbroker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pemCert holds a parsed leaf and its PEM-encoded cert/key.
type pemCert struct {
	cert    *x509.Certificate
	certPEM []byte
	keyPEM  []byte
}

func mustCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mesh-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
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
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, caPEM
}

func mustLeaf(t *testing.T, cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) pemCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemCert{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

func writePEM(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestBuildServerTLSDerivesMeshCA proves that with --client-ca unset the broker
// sources the mesh CA from ca.crt beside --tls-cert (the get-cert mount), and
// the resulting client pool accepts a caller cert signed by that CA.
func TestBuildServerTLSDerivesMeshCA(t *testing.T) {
	ca, caKey, caPEM := mustCA(t)
	srv := mustLeaf(t, "broker", ca, caKey)
	client := mustLeaf(t, "api", ca, caKey)

	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "tls.crt"), srv.certPEM)
	writePEM(t, filepath.Join(dir, "tls.key"), srv.keyPEM)
	writePEM(t, filepath.Join(dir, "ca.crt"), caPEM)

	cfg := config{
		tlsCert: filepath.Join(dir, "tls.crt"),
		tlsKey:  filepath.Join(dir, "tls.key"),
	}
	tlsCfg, verifier, err := buildServerTLS(cfg)
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	if tlsCfg == nil || tlsCfg.ClientCAs == nil || verifier == nil {
		t.Fatal("buildServerTLS returned a nil tls config, client pool, or verifier")
	}
	if _, err := client.cert.Verify(x509.VerifyOptions{
		Roots:     tlsCfg.ClientCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("derived mesh CA pool rejected a cert it signed: %v", err)
	}
}

// TestBuildServerTLSClientCAOverride proves --client-ca still works as an
// explicit override (the chart's current behavior) and takes precedence over
// the ca.crt beside --tls-cert.
func TestBuildServerTLSClientCAOverride(t *testing.T) {
	ca, caKey, caPEM := mustCA(t)
	srv := mustLeaf(t, "broker", ca, caKey)
	client := mustLeaf(t, "api", ca, caKey)

	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "tls.crt"), srv.certPEM)
	writePEM(t, filepath.Join(dir, "tls.key"), srv.keyPEM)
	caPath := filepath.Join(dir, "override-ca.crt")
	writePEM(t, caPath, caPEM)

	cfg := config{
		tlsCert:  filepath.Join(dir, "tls.crt"),
		tlsKey:   filepath.Join(dir, "tls.key"),
		clientCA: caPath,
	}
	tlsCfg, _, err := buildServerTLS(cfg)
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	if _, err := client.cert.Verify(x509.VerifyOptions{
		Roots:     tlsCfg.ClientCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("override mesh CA pool rejected a cert it signed: %v", err)
	}
}
