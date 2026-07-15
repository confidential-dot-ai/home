package cdsattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type testMeshIdentity struct {
	certFile string
	keyFile  string
	caFile   string
	leaf     *x509.Certificate
	ca       *x509.Certificate
	key      *ecdsa.PrivateKey
}

func writeTestMeshIdentity(t *testing.T) testMeshIdentity {
	t.Helper()
	now := time.Now()
	return writeTestMeshIdentityWithLeafValidity(t, now.Add(-time.Hour), now.Add(time.Hour))
}

func writeTestMeshIdentityWithLeafValidity(t *testing.T, leafNotBefore, leafNotAfter time.Time) testMeshIdentity {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test mesh CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "lb.c8s-system.svc"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	caFile := filepath.Join(dir, "ca.pem")
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, certFile, "CERTIFICATE", leafDER)
	writeTestPEM(t, keyFile, "EC PRIVATE KEY", keyDER)
	writeTestPEM(t, caFile, "CERTIFICATE", caDER)
	return testMeshIdentity{certFile: certFile, keyFile: keyFile, caFile: caFile, leaf: leaf, ca: ca, key: leafKey}
}

func writeTestPEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityBoundAttestationAndChannel(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	provider := &capturingProvider{}
	srv := NewServer(Config{
		Evidence:             provider,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	endpoint := ts.URL + "/.well-known/c8s/attestation?nonce=" + b64url(nonce)
	resp, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attestation status = %d, want 200", resp.StatusCode)
	}
	var bundle types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Version != types.ProtocolVersion {
		t.Fatalf("unexpected bundle header: %+v", bundle)
	}
	if bundle.IdentityProof == nil || bundle.SessionPubKey == nil {
		t.Fatalf("bundle missing identity proof or session key: %+v", bundle)
	}

	x25519, err := base64.RawURLEncoding.DecodeString(bundle.SessionPubKey.X25519)
	if err != nil {
		t.Fatal(err)
	}
	mlkem, err := base64.RawURLEncoding.DecodeString(bundle.SessionPubKey.MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	pub := overenc.PublicKey{X25519: x25519, MLKEM768: mlkem}
	wantReportData, err := overenc.IdentityTranscriptHash(pub, nonce, identity.leaf.Raw, identity.ca.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(provider.lastReportData, wantReportData) {
		t.Fatalf("report_data = %x, want identity transcript %x", provider.lastReportData, wantReportData)
	}

	leafHash := sha256.Sum256(identity.leaf.Raw)
	caHash := sha256.Sum256(identity.ca.Raw)
	if bundle.IdentityProof.LeafSHA256 != b64url(leafHash[:]) || bundle.IdentityProof.MeshCASHA256 != b64url(caHash[:]) {
		t.Fatalf("identity fingerprints do not match committed certificates: %+v", bundle.IdentityProof)
	}
	signature, err := base64.RawURLEncoding.DecodeString(bundle.IdentityProof.Signature)
	if err != nil {
		t.Fatal(err)
	}
	message, err := overenc.IdentityProofMessage(wantReportData)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(message)
	if !ecdsa.VerifyASN1(&identity.key.PublicKey, digest[:], signature) {
		t.Fatal("mesh identity proof signature did not verify")
	}

	clientChannel, handshake, err := overenc.ClientAgree(pub, wantReportData)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := postHandshake(t, ts.URL, nonce, handshake)
	got := tunnel(t, ts.URL, clientChannel, sessionID, types.TunnelRequest{Method: "GET", Path: "/identity"})
	if got.Status != http.StatusOK {
		t.Fatalf("identity-bound tunnel response status = %d", got.Status)
	}
}

func postHandshake(t *testing.T, base string, nonce []byte, hs overenc.Handshake) string {
	t.Helper()
	body, err := json.Marshal(types.HandshakeRequest{
		Nonce:        b64url(nonce),
		ClientX25519: b64url(hs.ClientX25519),
		MLKEMCt:      b64url(hs.MLKEMCiphertext),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(base+"/.well-known/c8s/handshake", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("handshake status = %d, want 200", resp.StatusCode)
	}
	var result types.HandshakeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.SessionID == "" {
		t.Fatal("identity-bound handshake returned no session id")
	}
	return result.SessionID
}

func TestIdentityBoundAttestationFailsClosedWithoutIdentity(t *testing.T) {
	srv := NewServer(Config{Evidence: &capturingProvider{}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/.well-known/c8s/attestation?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
}

func TestIdentityBoundAttestationFailsClosedOnInvalidConfiguredIdentity(t *testing.T) {
	srv := NewServer(Config{
		Evidence:             &capturingProvider{},
		MeshIdentityCertFile: "/does/not/exist/cert.pem",
		MeshIdentityKeyFile:  "/does/not/exist/key.pem",
		MeshIdentityCAFile:   "/does/not/exist/ca.pem",
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/.well-known/c8s/attestation?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestLoadMeshIdentityRejectsCopiedLeafWithoutPrivateKey(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalECPrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, identity.keyFile, "EC PRIVATE KEY", otherDER)
	if _, err := loadMeshIdentity(identity.certFile, identity.keyFile, identity.caFile); err == nil {
		t.Fatal("copied public leaf was accepted without its private key")
	}
}

func TestLoadMeshIdentityRejectsExpiredLeaf(t *testing.T) {
	now := time.Now()
	identity := writeTestMeshIdentityWithLeafValidity(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err := loadMeshIdentity(identity.certFile, identity.keyFile, identity.caFile); err == nil {
		t.Fatal("expired mesh identity leaf was accepted")
	}
}

// The endpoint takes no binding parameter: there is a single over-encryption
// binding and nothing to negotiate. Any binding param — even the served
// binding's own name — must get a loud 400.
func TestAttestationRejectsBindingParam(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             &capturingProvider{},
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	for _, query := range []string{
		"binding=over-encryption",
		"binding=unknown",
		"pq=false&binding=tls-cert",
	} {
		resp, err := http.Get(ts.URL + "/.well-known/c8s/attestation?nonce=" + b64url(make([]byte, 32)) + "&" + query)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", query, resp.StatusCode)
		}
	}
}

func TestIdentityBoundAttestationRejectsShortNonce(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             &capturingProvider{},
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	// 16 bytes passes the generic minNonceBytes gate but not the identity
	// transcript's exact 32-byte requirement.
	resp, err := http.Get(ts.URL + "/.well-known/c8s/attestation?nonce=" + b64url(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
