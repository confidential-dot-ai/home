package main

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lunal-dev/c8s/pkg/certutil"
)

// bundleManager maintains the CA certificate bundle (current + retained old CAs).
// In KBS mode, the bundle is persisted to the KBS repository directory
// so it survives pod restarts. The /v1/ca endpoint returns this bundle.
type bundleManager struct {
	mu     sync.RWMutex
	certs  []*x509.Certificate // current CA cert first, then retained old ones
	maxTTL time.Duration

	// repoDir is the local path to KBS repository for write-back.
	// Empty string disables persistence.
	repoDir    string
	bundlePath string // e.g., "default/mesh/ca-bundle"
	logger     *slog.Logger
}

func newBundleManager(maxTTL time.Duration, repoDir, bundlePath string, logger *slog.Logger) *bundleManager {
	return &bundleManager{
		maxTTL:     maxTTL,
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
}

// loadFromRepo loads the CA bundle from the KBS repository directory.
// Returns nil if the bundle file doesn't exist (first-time startup).
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
	return certs, nil
}

// rotate adds a new CA cert to the front of the bundle, retains old certs
// subject to 2x maxTTL trimming, and persists to the KBS repository.
func (bm *bundleManager) rotate(newCACert *x509.Certificate) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// Trim old certs that expired more than 2x maxTTL ago.
	cutoff := time.Now().Add(-2 * bm.maxTTL)
	var retained []*x509.Certificate
	for _, cert := range bm.certs {
		if cert.NotAfter.Before(cutoff) {
			fingerprint := certutil.CertFingerprint(cert.Raw)
			bm.logger.Info("trimming expired CA from bundle",
				"fingerprint", fingerprint,
				"not_after", cert.NotAfter.Format(time.RFC3339),
			)
			continue
		}
		retained = append(retained, cert)
	}

	// New cert goes first.
	bm.certs = append([]*x509.Certificate{newCACert}, retained...)

	// Persist bundle to KBS repository.
	if err := bm.persistLocked(); err != nil {
		return fmt.Errorf("persist bundle: %w", err)
	}

	return nil
}

// bundlePEM returns the full CA bundle as PEM bytes.
func (bm *bundleManager) bundlePEM() []byte {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.encodePEMLocked()
}

// encodePEMLocked encodes all certs as PEM. Caller must hold bm.mu.
func (bm *bundleManager) encodePEMLocked() []byte {
	var result []byte
	for _, cert := range bm.certs {
		result = append(result, certutil.EncodeCertPEM(cert.Raw)...)
	}
	return result
}

// persistLocked writes the bundle to the KBS repository. Caller must hold bm.mu.
func (bm *bundleManager) persistLocked() error {
	if bm.repoDir == "" {
		return nil
	}

	bundleFile := filepath.Join(bm.repoDir, bm.bundlePath)
	dir := filepath.Dir(bundleFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	if err := os.WriteFile(bundleFile, bm.encodePEMLocked(), 0644); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}

	bm.logger.Debug("persisted CA bundle to KBS repository",
		"path", bundleFile,
		"count", len(bm.certs),
	)
	return nil
}
