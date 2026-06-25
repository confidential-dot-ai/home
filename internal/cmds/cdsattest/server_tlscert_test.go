package cdsattest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// capturingProvider records the report_data it was asked to bind, so a test can
// assert what the server committed to the hardware report.
type capturingProvider struct {
	lastReportData []byte
}

func (p *capturingProvider) Evidence(_ context.Context, reportData []byte) (json.RawMessage, string, string, error) {
	p.lastReportData = append([]byte(nil), reportData...)
	return json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), "snp", "genoa", nil
}

// writeTestLeaf writes a self-signed leaf PEM to a temp file and returns the
// path plus the cert's SubjectPublicKeyInfo (DER).
func writeTestLeaf(t *testing.T) (path string, spki []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "c8s-tls-lb.c8s-system.svc"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, cert.RawSubjectPublicKeyInfo
}

func TestAttestationTLSCertBinding(t *testing.T) {
	certPath, spki := writeTestLeaf(t)
	prov := &capturingProvider{}
	srv := NewServer(Config{Evidence: prov, ServingCertFile: certPath})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(ts.URL + "/.well-known/c8s/attestation?nonce=" + b64url(nonce) + "&pq=false")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var b types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}

	if b.Binding != types.BindingTLSCert {
		t.Errorf("binding = %q, want %q", b.Binding, types.BindingTLSCert)
	}
	if b.SessionPubKey != nil {
		t.Errorf("tls-cert binding must omit session_pubkey, got %+v", b.SessionPubKey)
	}
	if b.Nonce != b64url(nonce) {
		t.Errorf("nonce not echoed: got %q", b.Nonce)
	}

	// The hardware report_data the server bound must be SHA-384(spki || nonce).
	want := sha512.Sum384(append(append([]byte(nil), spki...), nonce...))
	if !bytes.Equal(prov.lastReportData, want[:]) {
		t.Errorf("report_data = %x, want SHA-384(spki||nonce) = %x", prov.lastReportData, want[:])
	}
}

func TestAttestationTLSCertBindingUnconfigured(t *testing.T) {
	// No ServingCertFile: pq=false must fail closed rather than silently fall
	// back to a different binding.
	srv := NewServer(Config{Evidence: &capturingProvider{}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(ts.URL + "/.well-known/c8s/attestation?nonce=" + b64url(nonce) + "&pq=false")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 when serving cert is not configured", resp.StatusCode)
	}
}
