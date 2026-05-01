package certrotator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func selfSignedCert(t *testing.T, key *ecdsa.PrivateKey, cn string, isCA bool) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  isCA,
		BasicConstraintsValid: isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.MaxPathLen = 0
		tmpl.MaxPathLenZero = true
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return certDER
}

func selfSignedCertPEM(t *testing.T, key *ecdsa.PrivateKey, cn string, isCA bool) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedCert(t, key, cn, isCA)})
}

func ecKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestRotateMeshCA_NewKeypairAndBundle(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Create existing mesh CA Secret and ConfigMap.
	oldKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	oldCertPEM := selfSignedCertPEM(t, oldKey, "Old Mesh CA", true)
	oldKeyPEM := ecKeyPEM(t, oldKey)

	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kbs-mesh-ca",
				Namespace: "tee-attestation",
			},
			Data: map[string][]byte{
				"mesh-ca.key": oldKeyPEM,
				"mesh-ca.crt": oldCertPEM,
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mesh-ca-cert",
				Namespace: "tee-attestation",
			},
			Data: map[string]string{
				"ca.pem": string(oldCertPEM),
			},
		},
	)

	fingerprint, err := rotateMeshCA(ctx, client, "tee-attestation", 365, 4*time.Hour, logger)
	if err != nil {
		t.Fatalf("rotateMeshCA failed: %v", err)
	}
	if fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}

	// Verify Secret was updated.
	secret, err := client.CoreV1().Secrets("tee-attestation").Get(ctx, "kbs-mesh-ca", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["mesh-ca.crt"]) == string(oldCertPEM) {
		t.Error("mesh CA cert was not rotated")
	}

	// Verify ConfigMap bundle contains new + old certs.
	cm, err := client.CoreV1().ConfigMaps("tee-attestation").Get(ctx, "mesh-ca-cert", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bundle := cm.Data["ca.pem"]

	// Count PEM blocks in bundle.
	certCount := 0
	remaining := []byte(bundle)
	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		certCount++
	}
	if certCount < 2 {
		t.Errorf("bundle should contain at least 2 certs (new + old), got %d", certCount)
	}

	// Verify rotation timestamp annotation.
	if cm.Annotations["lunal.dev/ca-rotation-timestamp"] == "" {
		t.Error("missing rotation timestamp annotation")
	}
}

func TestRotateMeshCA_ConfigMapNotFound_SucceedsWithSecretOnly(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Secret exists but no ConfigMap — rotation should still succeed
	// (dynamic CA URL mode: cert-issuer serves the cert via /v1/ca).
	oldKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	oldCertPEM := selfSignedCertPEM(t, oldKey, "Old Mesh CA", true)
	oldKeyPEM := ecKeyPEM(t, oldKey)

	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kbs-mesh-ca",
				Namespace: "tee-attestation",
			},
			Data: map[string][]byte{
				"mesh-ca.key": oldKeyPEM,
				"mesh-ca.crt": oldCertPEM,
			},
		},
	)

	fp, err := rotateMeshCA(ctx, client, "tee-attestation", 365, 4*time.Hour, logger)
	if err != nil {
		t.Fatalf("rotateMeshCA should succeed without ConfigMap: %v", err)
	}
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}

	// Verify Secret WAS updated (not rolled back).
	secret, err := client.CoreV1().Secrets("tee-attestation").Get(ctx, "kbs-mesh-ca", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["mesh-ca.crt"]) == string(oldCertPEM) {
		t.Error("Secret should have been updated with new cert")
	}
}

func TestVerifyCertIssuerReload_Success(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	expectedFP := "abc123"
	// Mock metrics server returning incremented counter and matching fingerprint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `# HELP cert_issuer_cert_reloads_total Total successful certificate reloads.
# TYPE cert_issuer_cert_reloads_total counter
cert_issuer_cert_reloads_total 5
# HELP cert_issuer_ca_cert_fingerprint_info Info metric
# TYPE cert_issuer_ca_cert_fingerprint_info gauge
cert_issuer_ca_cert_fingerprint_info{fingerprint="%s"} 1
`, expectedFP)
	}))
	defer srv.Close()

	httpClient := &http.Client{Timeout: 5 * time.Second}
	err := verifyCertIssuerReload(ctx, httpClient, srv.URL, 10*time.Second, 1*time.Second, 3.0, expectedFP, logger)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestVerifyCertIssuerReload_Timeout(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	// Mock server that never returns the expected fingerprint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `cert_issuer_cert_reloads_total 1
cert_issuer_ca_cert_fingerprint_info{fingerprint="wrong"} 1
`)
	}))
	defer srv.Close()

	httpClient := &http.Client{Timeout: 5 * time.Second}
	err := verifyCertIssuerReload(ctx, httpClient, srv.URL, 2*time.Second, 500*time.Millisecond, 0, "expected-fp", logger)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTrimExpiredCerts(t *testing.T) {
	logger := slog.Default()

	// Create two certs: one fresh, one expired long ago.
	freshKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	freshCertPEM := selfSignedCertPEM(t, freshKey, "Fresh CA", true)

	// Create an expired cert (expired 24h ago).
	expiredKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	expiredTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Expired CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	expiredDER, _ := x509.CreateCertificate(rand.Reader, expiredTmpl, expiredTmpl, &expiredKey.PublicKey, expiredKey)
	expiredCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredDER})

	bundle := string(freshCertPEM) + string(expiredCertPEM)

	// maxTTL=4h, so cutoff is 8h ago. Cert expired 24h ago should be trimmed.
	trimmed := trimExpiredCerts(bundle, 4*time.Hour, logger)

	// Count remaining certs.
	certCount := 0
	remaining := []byte(trimmed)
	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		certCount++
	}
	if certCount != 1 {
		t.Errorf("expected 1 cert after trimming, got %d", certCount)
	}
}

func TestParseMetricValue(t *testing.T) {
	body := `# HELP cert_issuer_cert_reloads_total Total reloads
# TYPE cert_issuer_cert_reloads_total counter
cert_issuer_cert_reloads_total 42
cert_issuer_ca_cert_fingerprint_info{fingerprint="abc123"} 1
`
	v := parseMetricValue(body, "cert_issuer_cert_reloads_total")
	if v != 42 {
		t.Errorf("parseMetricValue = %v, want 42", v)
	}

	fp := parseMetricLabel(body, "cert_issuer_ca_cert_fingerprint_info", "fingerprint")
	if fp != "abc123" {
		t.Errorf("parseMetricLabel = %q, want %q", fp, "abc123")
	}
}
