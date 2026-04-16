package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/lunal-dev/c8s/pkg/certutil"
)

// certReloader watches certificate files and hot-swaps the Issuer's bundle.
type certReloader struct {
	issuer         *Issuer
	caKeyPath      string
	caCertPath     string
	tokenCertPath  string
	parentCertPath string // Optional: root CA for intermediate mode.
	debounceDelay  time.Duration
	logger         *slog.Logger
}

func newCertReloader(iss *Issuer, caKeyPath, caCertPath, tokenCertPath, parentCertPath string, debounceDelay time.Duration, logger *slog.Logger) *certReloader {
	return &certReloader{
		issuer:         iss,
		caKeyPath:      caKeyPath,
		caCertPath:     caCertPath,
		tokenCertPath:  tokenCertPath,
		parentCertPath: parentCertPath,
		debounceDelay:  debounceDelay,
		logger:         logger,
	}
}

// run starts watching cert directories and reloads on changes. Blocks until ctx is done.
func (cr *certReloader) run(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create fsnotify watcher: %w", err)
	}
	defer watcher.Close()

	// Watch parent directories (K8s secret mounts use symlink swaps on parent dir).
	var paths []string
	for _, p := range []string{cr.caKeyPath, cr.caCertPath, cr.tokenCertPath, cr.parentCertPath} {
		if p != "" {
			paths = append(paths, p)
		}
	}
	dirs := uniqueDirs(paths...)
	for _, d := range dirs {
		if err := watcher.Add(d); err != nil {
			return fmt.Errorf("watch %s: %w", d, err)
		}
		cr.logger.Info("watching directory for cert changes", "dir", d)
	}

	// Debounce: K8s symlink swap can trigger multiple events.
	var debounceTimer *time.Timer

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// Only react to Create events (symlink swap) and Write events on relevant files/dirs.
			if event.Op&(fsnotify.Create|fsnotify.Write) == 0 {
				continue
			}
			cr.logger.Debug("filesystem event", "op", event.Op, "name", event.Name)
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(cr.debounceDelay, func() {
				cr.reload()
			})
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			cr.logger.Warn("fsnotify error", "error", err)
		}
	}
}

func (cr *certReloader) reload() {
	cr.logger.Info("reloading certificates")

	var caKey *ecdsa.PrivateKey
	if cr.caKeyPath != "" {
		var err error
		caKey, err = certutil.LoadECPrivateKeyFile(cr.caKeyPath)
		if err != nil {
			cr.logger.Error("cert reload failed: CA key", "error", err)
			certReloadFailuresTotal.Inc()
			return
		}
	} else {
		// KBS mode: preserve existing key from bundle.
		b := cr.issuer.getBundle()
		if b != nil {
			caKey = b.caKey
		}
	}

	caCert, err := certutil.LoadCertificateFile(cr.caCertPath)
	if err != nil {
		cr.logger.Error("cert reload failed: CA cert", "error", err)
		certReloadFailuresTotal.Inc()
		return
	}

	var tokenCert *x509.Certificate
	if cr.tokenCertPath != "" {
		tokenCert, err = certutil.LoadCertificateFile(cr.tokenCertPath)
		if err != nil {
			cr.logger.Error("cert reload failed: token cert", "error", err)
			certReloadFailuresTotal.Inc()
			return
		}
	}

	var parentCert *x509.Certificate
	if cr.parentCertPath != "" {
		parentCert, err = certutil.LoadCertificateFile(cr.parentCertPath)
		if err != nil {
			cr.logger.Error("cert reload failed: parent cert", "error", err)
			certReloadFailuresTotal.Inc()
			return
		}
	}

	// Validate chain: intermediate must be signed by parent.
	if parentCert != nil {
		if err := validateChain(caCert, parentCert); err != nil {
			cr.logger.Error("cert reload failed: chain validation", "error", err)
			certReloadFailuresTotal.Inc()
			return
		}
	}

	cr.issuer.bundle.Store(&certBundle{
		caCert:          caCert,
		caKey:           caKey,
		tokenSignerCert: tokenCert,
		parentCert:      parentCert,
	})

	certReloadsTotal.Inc()

	// Update CA fingerprint metric for rotation verification.
	fingerprint := updateCACertFingerprint(caCert.Raw)

	cr.logger.Info("certificates reloaded successfully",
		"ca_not_after", caCert.NotAfter.Format(time.RFC3339),
		"ca_fingerprint_sha256", fingerprint,
		"token_not_after", tokenCert.NotAfter.Format(time.RFC3339),
	)
}

// validateChain verifies that the intermediate CA certificate is signed by the parent (root) CA.
func validateChain(intermediate, root *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err := intermediate.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		return fmt.Errorf("intermediate CA is not signed by parent CA: %w", err)
	}
	return nil
}

// uniqueDirs returns deduplicated parent directories of the given file paths.
func uniqueDirs(paths ...string) []string {
	seen := make(map[string]bool)
	var dirs []string
	for _, p := range paths {
		d := filepath.Dir(p)
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	return dirs
}
