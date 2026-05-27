package issuer

import (
	"crypto/x509"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/pkg/certutil"
)

const testBundlePath = "default/mesh/ca-bundle"

func mustNewCA(t *testing.T) *x509.Certificate {
	t.Helper()
	ca, err := NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca.Cert
}

func TestBundleRotateDoesNotPublishOnPersistFailure(t *testing.T) {
	oldCert := mustNewCA(t)
	newCert := mustNewCA(t)

	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "default"), []byte("not a directory"), 0644); err != nil {
		t.Fatal(err)
	}
	bm := NewBundleManager(time.Hour, repoDir, testBundlePath, slog.Default())
	bm.SetInitial(oldCert)

	if err := bm.Rotate(newCert); err == nil {
		t.Fatal("expected persist failure")
	}
	certs, err := certutil.ParsePEMCertificates(bm.BundlePEM())
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
	oldCert := mustNewCA(t)
	newCert := mustNewCA(t)

	repoDir := t.TempDir()
	bm := NewBundleManager(time.Hour, repoDir, testBundlePath, slog.Default())
	bm.SetInitial(oldCert)
	if err := bm.PersistCurrent(); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(bm.retirementsFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bm.retirementsFile(), 0755); err != nil {
		t.Fatal(err)
	}

	if err := bm.Rotate(newCert); err == nil {
		t.Fatal("expected retirement metadata persist failure")
	}
	data, err := os.ReadFile(filepath.Join(repoDir, testBundlePath))
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
	oldCert := mustNewCA(t)

	repoDir := t.TempDir()
	bm := NewBundleManager(time.Hour, repoDir, testBundlePath, slog.Default())
	bm.SetInitial(oldCert)

	if err := bm.PersistCurrent(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repoDir, testBundlePath))
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
	currentCert := mustNewCA(t)
	retiredCert := mustNewCA(t)
	newCert := mustNewCA(t)
	retiredFP := certutil.CertFingerprint(retiredCert.Raw)

	bm := NewBundleManager(time.Hour, "", testBundlePath, slog.Default())
	bm.certs = []*x509.Certificate{currentCert, retiredCert}
	bm.retiredAt = map[string]time.Time{retiredFP: time.Now().Add(-3 * time.Hour)}

	if err := bm.Rotate(newCert); err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.ParsePEMCertificates(bm.BundlePEM())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("bundle cert count = %d, want new current + previous current", len(certs))
	}
	if !certs[0].Equal(newCert) {
		t.Fatalf("first bundle cert is not the new current CA")
	}
	if !certs[1].Equal(currentCert) {
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
	currentCert := mustNewCA(t)
	retiredCert := mustNewCA(t)
	retiredFP := certutil.CertFingerprint(retiredCert.Raw)
	retiredAt := time.Unix(1893456000, 1234).UTC()

	repoDir := t.TempDir()
	bm := NewBundleManager(time.Hour, repoDir, testBundlePath, slog.Default())
	bm.certs = []*x509.Certificate{currentCert, retiredCert}
	bm.retiredAt = map[string]time.Time{retiredFP: retiredAt}
	if err := bm.PersistCurrent(); err != nil {
		t.Fatal(err)
	}

	reloaded := NewBundleManager(time.Hour, repoDir, testBundlePath, slog.Default())
	certs, err := reloaded.LoadFromRepo()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("reloaded bundle cert count = %d, want 2", len(certs))
	}
	got, ok := reloaded.retiredAt[retiredFP]
	if !ok || !got.Equal(retiredAt) {
		t.Fatalf("retiredAt = %s (ok=%v), want %s", got.Format(time.RFC3339Nano), ok, retiredAt.Format(time.RFC3339Nano))
	}
}

func TestBundleLoadKeepsPublicBundleWhenRetirementMetadataIsCorrupt(t *testing.T) {
	currentCert := mustNewCA(t)

	repoDir := t.TempDir()
	bm := NewBundleManager(time.Hour, repoDir, testBundlePath, slog.Default())
	bm.SetInitial(currentCert)
	if err := bm.PersistCurrent(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bm.retirementsFile(), []byte("{not-json"), 0644); err != nil {
		t.Fatal(err)
	}

	reloaded := NewBundleManager(time.Hour, repoDir, testBundlePath, slog.Default())
	certs, err := reloaded.LoadFromRepo()
	if err != nil {
		t.Fatalf("LoadFromRepo returned error for corrupt retirement metadata: %v", err)
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
