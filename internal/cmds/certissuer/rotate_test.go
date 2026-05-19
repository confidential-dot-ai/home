package certissuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/pkg/certutil"
)

func TestRotateCAUsesConfiguredCommonName(t *testing.T) {
	iss, _ := testIssuer(t)
	rotator := testCARotator(iss, "Custom Mesh CA")

	cert, _, err := rotator.rotateCA()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "Custom Mesh CA" {
		t.Fatalf("rotated CA CN = %q, want %q", cert.Subject.CommonName, "Custom Mesh CA")
	}
	if got := iss.getBundle().caCert.Subject.CommonName; got != "Custom Mesh CA" {
		t.Fatalf("active CA CN = %q, want %q", got, "Custom Mesh CA")
	}
}

func TestRotateCASetsParentCertificateForContinuity(t *testing.T) {
	iss, _ := testIssuer(t)
	oldBundle := iss.getBundle()
	iss.bundle.Store(&certBundle{
		caCert:          oldBundle.caCert,
		caKey:           oldBundle.caKey,
		tokenSignerCert: oldBundle.tokenSignerCert,
		parentCert:      oldBundle.caCert,
	})
	rotator := testCARotator(iss, "c8s Mesh CA")

	if _, _, err := rotator.rotateCA(); err != nil {
		t.Fatal(err)
	}
	rotated := iss.getBundle()
	if parent := rotated.parentCert; parent == nil || !sameCert(parent, oldBundle.caCert) {
		t.Fatalf("rotated CA parent = %v, want previous active CA", parent)
	}
	if err := rotated.caCert.CheckSignatureFrom(oldBundle.caCert); err != nil {
		t.Fatalf("rotated CA was not signed by previous CA: %v", err)
	}
}

func TestBundleRotateDoesNotPublishOnPersistFailure(t *testing.T) {
	iss, _ := testIssuer(t)
	replacement, _ := testIssuer(t)
	oldCert := iss.getBundle().caCert
	newCert := replacement.getBundle().caCert

	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "default"), []byte("not a directory"), 0644); err != nil {
		t.Fatal(err)
	}
	bm := newBundleManager(iss.MaxTTL, repoDir, "default/mesh/ca-bundle", slog.Default())
	bm.setInitial(oldCert)

	err := bm.rotate(newCert)
	if err == nil {
		t.Fatal("expected persist failure")
	}
	certs, err := certutil.ParsePEMCertificates(bm.bundlePEM())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("bundle cert count = %d, want 1", len(certs))
	}
	if got, want := certutil.CertFingerprint(certs[0].Raw), certutil.CertFingerprint(oldCert.Raw); got != want {
		t.Fatalf("published CA fingerprint = %s, want old CA %s", got, want)
	}
}

func TestBundleRotateDoesNotCommitBundleFileBeforeRetirements(t *testing.T) {
	iss, _ := testIssuer(t)
	replacement, _ := testIssuer(t)
	oldCert := iss.getBundle().caCert
	newCert := replacement.getBundle().caCert

	repoDir := t.TempDir()
	bm := newBundleManager(iss.MaxTTL, repoDir, "default/mesh/ca-bundle", slog.Default())
	bm.setInitial(oldCert)
	if err := bm.persistCurrent(); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(bm.retirementsFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bm.retirementsFile(), 0755); err != nil {
		t.Fatal(err)
	}

	err := bm.rotate(newCert)
	if err == nil {
		t.Fatal("expected retirement metadata persist failure")
	}
	data, err := os.ReadFile(filepath.Join(repoDir, "default/mesh/ca-bundle"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.ParsePEMCertificates(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("persisted bundle cert count = %d, want 1", len(certs))
	}
	if got, want := certutil.CertFingerprint(certs[0].Raw), certutil.CertFingerprint(oldCert.Raw); got != want {
		t.Fatalf("persisted CA fingerprint = %s, want old CA %s", got, want)
	}
}

func TestBundlePersistCurrentWritesInitialBundle(t *testing.T) {
	iss, _ := testIssuer(t)
	oldCert := iss.getBundle().caCert

	repoDir := t.TempDir()
	bm := newBundleManager(iss.MaxTTL, repoDir, "default/mesh/ca-bundle", slog.Default())
	bm.setInitial(oldCert)

	if err := bm.persistCurrent(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repoDir, "default/mesh/ca-bundle"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.ParsePEMCertificates(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("persisted bundle cert count = %d, want 1", len(certs))
	}
	if got, want := certutil.CertFingerprint(certs[0].Raw), certutil.CertFingerprint(oldCert.Raw); got != want {
		t.Fatalf("persisted CA fingerprint = %s, want %s", got, want)
	}
}

func TestBundleRotateDropsRetiredCAsAfterMaxTTLWindow(t *testing.T) {
	iss, _ := testIssuer(t)
	retiredIssuer, _ := testIssuer(t)
	replacement, _ := testIssuer(t)
	currentCert := iss.getBundle().caCert
	retiredCert := retiredIssuer.getBundle().caCert
	newCert := replacement.getBundle().caCert
	retiredFP := certutil.CertFingerprint(retiredCert.Raw)

	bm := newBundleManager(time.Hour, "", "default/mesh/ca-bundle", slog.Default())
	bm.certs = []*x509.Certificate{currentCert, retiredCert}
	bm.retiredAt = map[string]time.Time{
		retiredFP: time.Now().Add(-3 * time.Hour),
	}

	if err := bm.rotate(newCert); err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.ParsePEMCertificates(bm.bundlePEM())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("bundle cert count = %d, want new current + previous current", len(certs))
	}
	if !sameCert(certs[0], newCert) {
		t.Fatalf("first bundle cert is not the new current CA")
	}
	if !sameCert(certs[1], currentCert) {
		t.Fatalf("second bundle cert is not the previous current CA")
	}
	if _, ok := bm.retiredAt[retiredFP]; ok {
		t.Fatalf("stale retired CA still has retirement metadata")
	}
	if _, ok := bm.retiredAt[certutil.CertFingerprint(currentCert.Raw)]; !ok {
		t.Fatalf("previous current CA was not marked retired")
	}
}

func TestBundleRetirementMetadataSurvivesReload(t *testing.T) {
	iss, _ := testIssuer(t)
	retiredIssuer, _ := testIssuer(t)
	currentCert := iss.getBundle().caCert
	retiredCert := retiredIssuer.getBundle().caCert
	retiredFP := certutil.CertFingerprint(retiredCert.Raw)
	retiredAt := time.Unix(1893456000, 1234).UTC()

	repoDir := t.TempDir()
	bm := newBundleManager(time.Hour, repoDir, "default/mesh/ca-bundle", slog.Default())
	bm.certs = []*x509.Certificate{currentCert, retiredCert}
	bm.retiredAt = map[string]time.Time{retiredFP: retiredAt}
	if err := bm.persistCurrent(); err != nil {
		t.Fatal(err)
	}

	reloaded := newBundleManager(time.Hour, repoDir, "default/mesh/ca-bundle", slog.Default())
	certs, err := reloaded.loadFromRepo()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("reloaded bundle cert count = %d, want 2", len(certs))
	}
	if got := reloaded.retiredAt[retiredFP]; !got.Equal(retiredAt) {
		t.Fatalf("retiredAt = %s, want %s", got.Format(time.RFC3339Nano), retiredAt.Format(time.RFC3339Nano))
	}
}

func TestBundleLoadKeepsPublicBundleWhenRetirementMetadataIsCorrupt(t *testing.T) {
	iss, _ := testIssuer(t)
	currentCert := iss.getBundle().caCert

	repoDir := t.TempDir()
	bm := newBundleManager(time.Hour, repoDir, "default/mesh/ca-bundle", slog.Default())
	bm.setInitial(currentCert)
	if err := bm.persistCurrent(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bm.retirementsFile(), []byte("{not-json"), 0644); err != nil {
		t.Fatal(err)
	}

	reloaded := newBundleManager(time.Hour, repoDir, "default/mesh/ca-bundle", slog.Default())
	certs, err := reloaded.loadFromRepo()
	if err != nil {
		t.Fatalf("loadFromRepo returned error for corrupt retirement metadata: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("reloaded bundle cert count = %d, want 1", len(certs))
	}
	if got, want := certutil.CertFingerprint(certs[0].Raw), certutil.CertFingerprint(currentCert.Raw); got != want {
		t.Fatalf("reloaded CA fingerprint = %s, want %s", got, want)
	}
	if len(reloaded.retiredAt) != 0 {
		t.Fatalf("retirement metadata should be reset on corrupt file, got %d entries", len(reloaded.retiredAt))
	}
}

func TestHandleSignCSRReturnsFullPublicBundleAfterMultipleRotations(t *testing.T) {
	iss, tokenKey := testIssuer(t)
	rotator := testCARotator(iss, "c8s Mesh CA")

	for range 2 {
		if _, _, err := rotator.rotateCA(); err != nil {
			t.Fatal(err)
		}
	}

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := generateCSR(t, csrKey, "ratls-mesh-10.0.0.1", net.ParseIP("10.0.0.1"))
	signEAR := signJWT(t, tokenKey, map[string]any{
		earclaims.Issuer:       "kbs",
		earclaims.IssuedAt:     time.Now().Unix(),
		earclaims.ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		earclaims.Submods:      "test-evidence",
		earclaims.TEEPublicKey: teePubKeyB64(t, csrKey),
	})
	body, err := json.Marshal(newSignCSRRequest(signEAR, csr, "12h"))
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body))
	iss.HandleSignCSR(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sign-csr status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp signCSRResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if got := len(resp.CACertificate.DERAll()); got != 3 {
		t.Fatalf("sign-csr CA bundle count = %d, want current + two retained parents", got)
	}
}

func testCARotator(iss *Issuer, commonName string) *caRotator {
	bm := newBundleManager(iss.MaxTTL, "", "default/mesh/ca-bundle", slog.Default())
	bm.setInitial(iss.getBundle().caCert)
	iss.caBundle = bm
	return &caRotator{
		issuer:         iss,
		bundle:         bm,
		caCertValidity: 365 * 24 * time.Hour,
		caCommonName:   commonName,
	}
}
