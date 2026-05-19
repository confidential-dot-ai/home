package getcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/pkg/attestclient"
)

func TestParseFileMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		want    os.FileMode
		wantErr bool
	}{
		{name: "owner-only", mode: "0600", want: 0600},
		{name: "group-readable", mode: "0640", want: 0640},
		{name: "without-leading-zero", mode: "640", want: 0640},
		{name: "invalid-octal", mode: "0999", wantErr: true},
		{name: "special-bits", mode: "1777", wantErr: true},
		{name: "empty", mode: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFileMode(tt.mode)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseFileMode(%q) succeeded, want error", tt.mode)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFileMode(%q): %v", tt.mode, err)
			}
			if got != tt.want {
				t.Fatalf("parseFileMode(%q) = %#o, want %#o", tt.mode, got, tt.want)
			}
		})
	}
}

func TestBuildDiscoveryDocumentIncludesCertificateAndEvidence(t *testing.T) {
	certPEM := testCertificatePEM(t)
	result := attestclient.CertificateResult{
		Certificate: certPEM,
		Challenge:   "dGVzdC1jaGFsbGVuZ2U=",
		Platform:    "snp",
		Evidence:    json.RawMessage(`{"quote":"abc"}`),
	}

	doc, err := buildDiscoveryDocument(config{
		SAN:                    "confidential-gke.lunal.dev",
		DiscoveryCDSCertURL:    "/.well-known/cds-cert.pem",
		DiscoveryMeshCAURL:     "/.well-known/mesh-ca.pem",
		DiscoveryPublicTLSMode: "webpki",
	}, result)
	if err != nil {
		t.Fatalf("buildDiscoveryDocument: %v", err)
	}

	if doc.Version != "v1" {
		t.Fatalf("version = %q, want v1", doc.Version)
	}
	if doc.PublicTLS.Hostname != "confidential-gke.lunal.dev" {
		t.Fatalf("hostname = %q", doc.PublicTLS.Hostname)
	}
	if doc.PublicTLS.Mode != "webpki" {
		t.Fatalf("public tls mode = %q, want webpki", doc.PublicTLS.Mode)
	}
	if doc.CDSTLS.CertificatePEM != certPEM {
		t.Fatal("CDS certificate PEM not preserved")
	}
	if len(doc.CDSTLS.CertificateSHA256) != 64 {
		t.Fatalf("certificate sha256 = %q, want 64 hex chars", doc.CDSTLS.CertificateSHA256)
	}
	if doc.CDSTLS.CertificateURL != "/.well-known/cds-cert.pem" {
		t.Fatalf("certificate URL = %q", doc.CDSTLS.CertificateURL)
	}
	if doc.CDSTLS.MeshCAURL != "/.well-known/mesh-ca.pem" {
		t.Fatalf("mesh CA URL = %q", doc.CDSTLS.MeshCAURL)
	}
	if doc.Attestation.Challenge != result.Challenge {
		t.Fatalf("challenge = %q", doc.Attestation.Challenge)
	}
	if doc.Attestation.Platform != "snp" {
		t.Fatalf("platform = %q", doc.Attestation.Platform)
	}
	if !strings.Contains(string(doc.Attestation.Evidence), `"quote":"abc"`) {
		t.Fatalf("evidence = %s", doc.Attestation.Evidence)
	}
}

func TestValidateConfigRejectsInvalidDiscoveryPublicTLSMode(t *testing.T) {
	err := validateConfig(config{
		AssamURL:               "http://assam:8080",
		AttestationServiceURL:  "http://attestation-service:8400",
		SAN:                    "confidential-gke.lunal.dev",
		DiscoveryOutPath:       "/tmp/discovery.json",
		DiscoveryPublicTLSMode: "invalid",
	})
	if err == nil {
		t.Fatal("validateConfig succeeded, want invalid discovery public TLS mode error")
	}
	if !errors.Is(err, errInvalidDiscoveryPublicTLSMode) {
		t.Fatalf("error = %v, want discovery public TLS mode error", err)
	}
}

func TestValidateConfigRejectsInvalidReloadWatchInterval(t *testing.T) {
	err := validateConfig(config{
		AssamURL:              "http://assam:8080",
		AttestationServiceURL: "http://attestation-service:8400",
		SAN:                   "confidential-gke.lunal.dev",
		ReloadWatchPaths:      []string{"/public-tls/tls.crt"},
	})
	if err == nil {
		t.Fatal("validateConfig succeeded, want reload watch interval error")
	}
	if !errors.Is(err, errInvalidReloadWatchInterval) {
		t.Fatalf("error = %v, want reload watch interval error", err)
	}
}

func TestValidateConfigRejectsReloadWatchWithoutRenewInterval(t *testing.T) {
	err := validateConfig(config{
		AssamURL:              "http://assam:8080",
		AttestationServiceURL: "http://attestation-service:8400",
		SAN:                   "confidential-gke.lunal.dev",
		ReloadWatchPaths:      []string{"/public-tls/tls.crt"},
		ReloadWatchInterval:   time.Minute,
	})
	if err == nil {
		t.Fatal("validateConfig succeeded, want reload watch renew interval error")
	}
	if !errors.Is(err, errReloadWatchRequiresRenewInterval) {
		t.Fatalf("error = %v, want renew interval error", err)
	}
}

func TestValidateConfigRejectsContinueOnInitialErrorWithoutRenewInterval(t *testing.T) {
	err := validateConfig(config{
		AssamURL:               "http://assam:8080",
		AttestationServiceURL:  "http://attestation-service:8400",
		SAN:                    "confidential-gke.lunal.dev",
		ContinueOnInitialError: true,
	})
	if err == nil {
		t.Fatal("validateConfig succeeded, want continue-on-initial-error renew interval error")
	}
	if !errors.Is(err, errContinueOnInitialErrorRequiresRenewalLoop) {
		t.Fatalf("error = %v, want continue-on-initial-error error", err)
	}
}

func TestWriteFileAtomicReplacesFileAndCleansTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := writeFileAtomic(path, []byte("new"), 0644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("data = %q, want new", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Fatalf("mode = %#o, want 0644", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".cert.pem.tmp-") {
			t.Fatalf("temporary file was not cleaned up: %s", entry.Name())
		}
	}
}

func TestReloadWatchChangedDetectsFileReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	previous, err := snapshotReloadWatchPaths([]string{path})
	if err != nil {
		t.Fatalf("snapshotReloadWatchPaths: %v", err)
	}

	if err := writeFileAtomic(path, []byte("new certificate"), 0644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	changed, next, err := reloadWatchChanged(previous, []string{path})
	if err != nil {
		t.Fatalf("reloadWatchChanged: %v", err)
	}
	if !changed {
		t.Fatal("reloadWatchChanged = false, want true")
	}

	changed, _, err = reloadWatchChanged(next, []string{path})
	if err != nil {
		t.Fatalf("reloadWatchChanged second check: %v", err)
	}
	if changed {
		t.Fatal("reloadWatchChanged detected change without file mutation")
	}
}

func testCertificatePEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
		DNSNames:  []string{"confidential-gke.lunal.dev"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
