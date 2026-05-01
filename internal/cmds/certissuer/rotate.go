package certissuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/issuerapi"
)

// Type aliases for the shared wire types, kept for local readability.
type RotateCARequest = issuerapi.RotateCARequest
type RotateCAResponse = issuerapi.RotateCAResponse

// rotateHandler holds state for the /v1/rotate-ca endpoint.
type rotateHandler struct {
	issuer         *Issuer
	bundle         *bundleManager
	caRepoDir      string // local path to CDS repository for key write-back
	keyPath        string // resource path for CA key (e.g., "default/mesh/ca-key")
	maxTTL         time.Duration
	caCertValidity time.Duration
}

// HandleRotateCA handles POST /v1/rotate-ca.
// Validates EAR JWT, generates new CA keypair, writes to the CDS repo, swaps bundle.
func (rh *rotateHandler) HandleRotateCA(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	b := rh.issuer.getBundle()
	if b == nil {
		http.Error(w, "service unavailable: no certificates loaded", http.StatusServiceUnavailable)
		rotateRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Note: request body is already limited by http.MaxBytesHandler in main.go.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		rh.issuer.Logger.Error("failed to read rotate request body", "error", err)
		http.Error(w, "bad request: failed to read body", http.StatusBadRequest)
		rotateRequestsTotal.WithLabelValues("bad_request").Inc()
		return
	}

	var req RotateCARequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request: invalid JSON", http.StatusBadRequest)
		rotateRequestsTotal.WithLabelValues("bad_request").Inc()
		return
	}

	if req.EAR == "" {
		http.Error(w, "missing 'ear' field", http.StatusBadRequest)
		rotateRequestsTotal.WithLabelValues("bad_request").Inc()
		return
	}

	// Validate EAR JWT (same validation as sign-csr).
	claims, err := validateEARToken(req.EAR, rh.issuer.keyProvider, rh.issuer.ExpectedIssuer, rh.issuer.JWTClockSkew)
	if err != nil {
		rh.issuer.Logger.Warn("rotate-ca: EAR token validation failed", "error", err)
		var tve *tokenValidationError
		if errors.As(err, &tve) {
			tokenValidationFailuresTotal.WithLabelValues(tve.Reason).Inc()
		}
		http.Error(w, "unauthorized: invalid attestation token", http.StatusUnauthorized)
		rotateRequestsTotal.WithLabelValues("unauthorized").Inc()
		return
	}

	// Check measurement allowlist.
	if err := checkMeasurement(claims, rh.issuer.RotateCAMeasurements, "rotate-ca"); err != nil {
		rh.issuer.Logger.Warn("rotate-ca: measurement check failed", "error", err)
		measurementDeniedTotal.WithLabelValues("rotate-ca").Inc()
		http.Error(w, "forbidden: measurement not allowed", http.StatusForbidden)
		rotateRequestsTotal.WithLabelValues("forbidden").Inc()
		return
	}

	// Generate a fresh P-384 mesh CA (rotation curve is wider than the
	// in-process operator's P-256 default).
	ca, err := issuer.NewCAWithCurve("Mesh CA", rh.caCertValidity, elliptic.P384())
	if err != nil {
		rh.issuer.Logger.Error("rotate-ca: mint new CA", "error", err)
		http.Error(w, "internal error: certificate creation failed", http.StatusInternalServerError)
		rotateRequestsTotal.WithLabelValues("error").Inc()
		return
	}
	newKey, newCert := ca.Key, ca.Cert

	// Write new key to the CDS repository via the shared workdir volume.
	if err := rh.writeKeyToRepo(newKey); err != nil {
		rh.issuer.Logger.Error("rotate-ca: failed to write key to CDS repo", "error", err)
		http.Error(w, "internal error: key persistence failed", http.StatusInternalServerError)
		rotateRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Update CA bundle (adds old cert, trims expired).
	if rh.bundle != nil {
		if err := rh.bundle.rotate(newCert); err != nil {
			rh.issuer.Logger.Error("rotate-ca: bundle rotation failed", "error", err)
			http.Error(w, "internal error: bundle update failed", http.StatusInternalServerError)
			rotateRequestsTotal.WithLabelValues("error").Inc()
			return
		}
	}

	// Atomic swap: update the issuer's cert bundle.
	oldBundle := rh.issuer.getBundle()
	rh.issuer.bundle.Store(&certBundle{
		caCert:          newCert,
		caKey:           newKey,
		tokenSignerCert: oldBundle.tokenSignerCert,
		parentCert:      oldBundle.parentCert,
	})

	// Update metrics.
	certReloadsTotal.Inc()
	fingerprint := updateCACertFingerprint(newCert.Raw)

	resp := RotateCAResponse{
		CACertificate: issuerapi.NewPEMDataFromDER("CERTIFICATE", newCert.Raw),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		rh.issuer.Logger.Error("failed to encode rotate-ca response", "error", err)
		return
	}

	rotateRequestsTotal.WithLabelValues("success").Inc()
	rh.issuer.Logger.Info("CA rotated via /v1/rotate-ca",
		"audit", true,
		"new_fingerprint", fingerprint,
		"not_after", newCert.NotAfter.Format(time.RFC3339),
		"latency", time.Since(start).String(),
	)
}

// writeKeyToRepo writes the CA private key to the CDS repository directory.
func (rh *rotateHandler) writeKeyToRepo(key *ecdsa.PrivateKey) error {
	if rh.caRepoDir == "" {
		return nil
	}

	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return err
	}

	keyFile := filepath.Join(rh.caRepoDir, rh.keyPath)
	dir := filepath.Dir(keyFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	return nil
}
