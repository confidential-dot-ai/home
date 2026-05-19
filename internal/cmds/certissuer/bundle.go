package certissuer

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lunal-dev/c8s/pkg/certutil"
)

// bundleManager maintains the public CA certificate bundle. Private CA keys
// remain in process memory; this manager only persists public trust anchors.
type bundleManager struct {
	mu        sync.RWMutex
	certs     []*x509.Certificate  // current CA cert first, then retained old ones
	retiredAt map[string]time.Time // CA fingerprint -> time it stopped being the active signer
	maxTTL    time.Duration

	// repoDir is the local path for public bundle write-back.
	// Empty string disables persistence.
	repoDir    string
	bundlePath string
	logger     *slog.Logger
}

func newBundleManager(maxTTL time.Duration, repoDir, bundlePath string, logger *slog.Logger) *bundleManager {
	return &bundleManager{
		maxTTL:     maxTTL,
		retiredAt:  make(map[string]time.Time),
		repoDir:    repoDir,
		bundlePath: bundlePath,
		logger:     logger,
	}
}

// setInitial sets the initial CA certificate bundle. Called once at startup.
func (bm *bundleManager) setInitial(caCert *x509.Certificate) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.certs = []*x509.Certificate{caCert}
	bm.retiredAt = make(map[string]time.Time)
}

func (bm *bundleManager) setWithCurrent(current *x509.Certificate, retained []*x509.Certificate) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.certs = prependCurrentCA(current, retained)
	bm.retiredAt = bm.retirementsForCurrentLocked(current, time.Now())
}

// loadFromRepo loads the public CA bundle from the repository directory.
// Returns nil if the bundle file doesn't exist.
func (bm *bundleManager) loadFromRepo() ([]*x509.Certificate, error) {
	if bm.repoDir == "" {
		return nil, nil
	}

	bundleFile := filepath.Join(bm.repoDir, bm.bundlePath)
	data, err := os.ReadFile(bundleFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read bundle file: %w", err)
	}

	certs, err := certutil.ParsePEMCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	retiredAt, err := bm.loadRetirementsFromRepo()
	if err != nil {
		bm.logger.Warn("failed to load CA bundle retirement metadata; continuing with public bundle",
			"error", err,
			"path", bm.retirementsFile(),
		)
		retiredAt = make(map[string]time.Time)
	}
	bm.mu.Lock()
	bm.retiredAt = retiredAt
	bm.mu.Unlock()
	return certs, nil
}

// rotate adds a new CA cert to the front of the bundle, retains old certs
// subject to 2x maxTTL trimming, and persists the public bundle.
func (bm *bundleManager) rotate(newCACert *x509.Certificate) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()
	retained, nextRetiredAt, dropped := bm.retainedRetiredCAsLocked(newCACert, now)
	for _, dropped := range dropped {
		bm.logger.Info("trimming expired CA from bundle",
			"fingerprint", certutil.CertFingerprint(dropped.cert.Raw),
			"retired_at", dropped.retiredAt.Format(time.RFC3339),
			"retain_until", dropped.retiredAt.Add(2*bm.maxTTL).Format(time.RFC3339),
			"not_after", dropped.cert.NotAfter.Format(time.RFC3339),
		)
	}

	// New cert goes first. Build and persist a candidate before publishing it,
	// so /ca cannot serve a bundle for a CA that failed rotation.
	next := append([]*x509.Certificate{newCACert}, retained...)

	if err := bm.persistLocked(next, nextRetiredAt); err != nil {
		return fmt.Errorf("persist bundle: %w", err)
	}

	bm.certs = next
	bm.retiredAt = nextRetiredAt
	return nil
}

// persistCurrent writes the currently published public CA bundle to the
// repository. It no-ops when repoDir is empty.
func (bm *bundleManager) persistCurrent() error {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	return bm.persistLocked(bm.certs, bm.retirementsForCurrentLocked(firstCert(bm.certs), time.Now()))
}

// bundlePEM returns the full CA bundle as PEM bytes.
func (bm *bundleManager) bundlePEM() []byte {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.encodePEMLocked()
}

func (bm *bundleManager) bundlePEMForCurrent(current *x509.Certificate) []byte {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return encodeCertBundlePEM(prependCurrentCA(current, bm.certs))
}

// encodePEMLocked encodes all certs as PEM. Caller must hold bm.mu.
func (bm *bundleManager) encodePEMLocked() []byte {
	return encodeCertBundlePEM(bm.certs)
}

func encodeCertBundlePEM(certs []*x509.Certificate) []byte {
	var result []byte
	for _, cert := range certs {
		result = append(result, certutil.EncodeCertPEM(cert.Raw)...)
	}
	return result
}

// persistLocked writes the public bundle. Caller must hold bm.mu.
func (bm *bundleManager) persistLocked(certs []*x509.Certificate, retiredAt map[string]time.Time) error {
	if bm.repoDir == "" {
		return nil
	}

	bundleFile := filepath.Join(bm.repoDir, bm.bundlePath)
	dir := filepath.Dir(bundleFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	if err := bm.persistRetirementsLocked(retiredAt); err != nil {
		return err
	}
	if err := writeFileAtomic(bundleFile, encodeCertBundlePEM(certs), 0644); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}

	bm.logger.Debug("persisted CA bundle",
		"path", bundleFile,
		"count", len(certs),
	)
	return nil
}

type retiredCA struct {
	cert      *x509.Certificate
	retiredAt time.Time
}

type bundleRetirementsFile struct {
	Version   int               `json:"version"`
	RetiredAt map[string]string `json:"retired_at"`
}

func (bm *bundleManager) retainedRetiredCAsLocked(newCurrent *x509.Certificate, now time.Time) ([]*x509.Certificate, map[string]time.Time, []retiredCA) {
	nextRetiredAt := make(map[string]time.Time)
	retained := make([]*x509.Certificate, 0, len(bm.certs))
	var dropped []retiredCA
	for i, cert := range bm.certs {
		if cert == nil || sameCert(cert, newCurrent) {
			continue
		}
		fp := certutil.CertFingerprint(cert.Raw)
		retiredAt := bm.retiredAt[fp]
		if retiredAt.IsZero() {
			retiredAt = now
		}
		if i == 0 {
			retiredAt = now
		}
		if bm.shouldDropRetiredCA(cert, retiredAt, now) {
			dropped = append(dropped, retiredCA{cert: cert, retiredAt: retiredAt})
			continue
		}
		retained = append(retained, cert)
		nextRetiredAt[fp] = retiredAt
	}
	return retained, nextRetiredAt, dropped
}

func (bm *bundleManager) shouldDropRetiredCA(cert *x509.Certificate, retiredAt, now time.Time) bool {
	if !cert.NotAfter.After(now) {
		return true
	}
	if bm.maxTTL <= 0 {
		return false
	}
	return !retiredAt.Add(2 * bm.maxTTL).After(now)
}

func (bm *bundleManager) retirementsForCurrentLocked(current *x509.Certificate, fallback time.Time) map[string]time.Time {
	out := make(map[string]time.Time)
	currentFP := ""
	if current != nil {
		currentFP = certutil.CertFingerprint(current.Raw)
	}
	for _, cert := range bm.certs {
		if cert == nil {
			continue
		}
		fp := certutil.CertFingerprint(cert.Raw)
		if fp == currentFP {
			continue
		}
		retiredAt := bm.retiredAt[fp]
		if retiredAt.IsZero() {
			retiredAt = fallback
		}
		out[fp] = retiredAt
	}
	return out
}

func (bm *bundleManager) loadRetirementsFromRepo() (map[string]time.Time, error) {
	out := make(map[string]time.Time)
	if bm.repoDir == "" {
		return out, nil
	}
	data, err := os.ReadFile(bm.retirementsFile())
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read bundle retirements: %w", err)
	}
	var file bundleRetirementsFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse bundle retirements: %w", err)
	}
	for fp, raw := range file.RetiredAt {
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return nil, fmt.Errorf("parse retirement timestamp for %s: %w", fp, err)
		}
		out[fp] = t
	}
	return out, nil
}

func (bm *bundleManager) persistRetirementsLocked(retiredAt map[string]time.Time) error {
	file := bundleRetirementsFile{
		Version:   1,
		RetiredAt: make(map[string]string, len(retiredAt)),
	}
	for fp, t := range retiredAt {
		if t.IsZero() {
			continue
		}
		file.RetiredAt[fp] = t.UTC().Format(time.RFC3339Nano)
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle retirements: %w", err)
	}
	data = append(data, '\n')
	if err := writeFileAtomic(bm.retirementsFile(), data, 0644); err != nil {
		return fmt.Errorf("write bundle retirements: %w", err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (bm *bundleManager) retirementsFile() string {
	return filepath.Join(bm.repoDir, bm.bundlePath+".retirements.json")
}

func firstCert(certs []*x509.Certificate) *x509.Certificate {
	if len(certs) == 0 {
		return nil
	}
	return certs[0]
}

func sameCert(a, b *x509.Certificate) bool {
	return a != nil && b != nil && bytes.Equal(a.Raw, b.Raw)
}

func prependCurrentCA(current *x509.Certificate, certs []*x509.Certificate) []*x509.Certificate {
	if current == nil {
		return certs
	}
	out := []*x509.Certificate{current}
	for _, cert := range certs {
		if cert == nil || bytes.Equal(cert.Raw, current.Raw) {
			continue
		}
		out = append(out, cert)
	}
	return out
}
