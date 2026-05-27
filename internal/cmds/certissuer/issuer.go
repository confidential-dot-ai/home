package certissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/issuerapi"
	"github.com/lunal-dev/c8s/pkg/resources"
)

// certBundle holds the loaded certificate material for atomic hot-swap.
type certBundle struct {
	caCert          *x509.Certificate
	caKey           *ecdsa.PrivateKey
	tokenSignerCert *x509.Certificate
	// parentCert, when set, is the root CA that signed the intermediate caCert.
	// The SignCSR response includes the full chain: leaf + intermediate + root.
	parentCert *x509.Certificate
}

// Issuer validates EAR JWT tokens (issued by assam) and signs CSRs with its CA key.
type Issuer struct {
	bundle           atomic.Pointer[certBundle]
	keyProvider      issuer.KeyProvider
	MaxTTL           time.Duration
	SANValidation    bool           // When true, CSR IP SANs must match the request source IP; when false, CSRs carrying IP SANs are rejected.
	DNSSANPattern    *regexp.Regexp // When set, DNS SANs matching this pattern in full are allowed. Nil = reject all DNS SANs.
	AllowedCNPattern *regexp.Regexp // When set, CSR CN must match this pattern in full. Nil = no CN restriction.
	ExpectedIssuer   string         // When non-empty, validates the EAR issuer claim.
	RequestTimeout   time.Duration  // Per-request timeout. Zero = no timeout.
	MinCAValidity    time.Duration  // Minimum remaining CA cert validity for readiness.
	Logger           *slog.Logger
	tracker          *nodeTracker
	caBundle         *issuer.BundleManager // Optional public CA bundle source for sign-csr responses.

	// Per-endpoint measurement allowlists. Empty map = skip check (opt-in).
	SignCSRMeasurements map[string]bool
	HandoffMeasurements map[string]bool
}

func (iss *Issuer) getBundle() *certBundle {
	return iss.bundle.Load()
}

// Type aliases for the shared wire types, kept for local readability.
type signCSRRequest = issuerapi.SignCSRRequest
type signCSRResponse = issuerapi.SignCSRResponse

// HandleSignCSR handles POST /sign-csr.
func (iss *Issuer) HandleSignCSR(w http.ResponseWriter, r *http.Request) {
	activeRequests.Inc()
	defer activeRequests.Dec()
	start := time.Now()
	defer func() { signLatencySeconds.Observe(time.Since(start).Seconds()) }()

	// Apply per-request timeout.
	ctx := r.Context()
	if iss.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, iss.RequestTimeout)
		defer cancel()
	}

	b := iss.getBundle()
	if b == nil {
		http.Error(w, "service unavailable: no certificates loaded", http.StatusServiceUnavailable)
		signRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Note: request body is already limited by http.MaxBytesHandler in main.go.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		iss.Logger.Error("failed to read request body", "error", err)
		http.Error(w, "bad request: failed to read body", http.StatusBadRequest)
		signRequestsTotal.WithLabelValues("bad_request").Inc()
		return
	}

	var req signCSRRequest
	if err := json.Unmarshal(body, &req); err != nil {
		msg := "bad request: invalid JSON"
		if strings.Contains(err.Error(), "issuerapi: duration") {
			msg = "bad request: invalid TTL"
		} else if strings.Contains(err.Error(), "issuerapi: no valid PEM") {
			msg = "bad request: invalid CSR"
		}
		iss.Logger.Warn(msg, "error", err)
		http.Error(w, msg, http.StatusBadRequest)
		signRequestsTotal.WithLabelValues("bad_request").Inc()
		return
	}

	if req.EAR == "" {
		http.Error(w, "missing 'ear' field", http.StatusBadRequest)
		signRequestsTotal.WithLabelValues("bad_request").Inc()
		return
	}
	if req.CSR.DER() == nil {
		http.Error(w, "missing 'csr' field", http.StatusBadRequest)
		signRequestsTotal.WithLabelValues("bad_request").Inc()
		return
	}

	// Validate EAR JWT token.
	claims, err := issuer.ValidateEARToken(req.EAR, iss.keyProvider, iss.ExpectedIssuer)
	if err != nil {
		iss.Logger.Warn("EAR token validation failed", "error", err)
		var tve *issuer.TokenValidationError
		if errors.As(err, &tve) {
			tokenValidationFailuresTotal.WithLabelValues(string(tve.Reason)).Inc()
		}
		http.Error(w, "unauthorized: invalid attestation token", http.StatusUnauthorized)
		signRequestsTotal.WithLabelValues("unauthorized").Inc()
		return
	}

	// Check measurement allowlist.
	if err := issuer.CheckMeasurement(claims, iss.SignCSRMeasurements, "sign-csr"); err != nil {
		iss.Logger.Warn("measurement check failed", "error", err)
		measurementDeniedTotal.WithLabelValues("sign-csr").Inc()
		http.Error(w, "forbidden: measurement not allowed", http.StatusForbidden)
		signRequestsTotal.WithLabelValues("forbidden").Inc()
		return
	}

	// Parse CSR (PEM already validated by issuerapi.PEMData unmarshal).
	csr, err := x509.ParseCertificateRequest(req.CSR.DER())
	if err != nil {
		iss.Logger.Warn("invalid CSR", "error", err)
		http.Error(w, "bad request: invalid CSR", http.StatusBadRequest)
		signRequestsTotal.WithLabelValues("bad_request").Inc()
		return
	}

	// Verify CSR signature (proves key possession).
	if err := csr.CheckSignature(); err != nil {
		iss.Logger.Warn("CSR signature verification failed", "error", err)
		http.Error(w, "bad request: CSR signature invalid", http.StatusBadRequest)
		signRequestsTotal.WithLabelValues("bad_request").Inc()
		return
	}

	// Verify key binding: CSR public key must match the tee_public_key in EAR claims.
	if err := issuer.VerifyKeyBinding(csr, claims); err != nil {
		iss.Logger.Warn("key binding failed", "error", err)
		http.Error(w, "forbidden: certificate request denied", http.StatusForbidden)
		tokenValidationFailuresTotal.WithLabelValues("key_binding").Inc()
		signRequestsTotal.WithLabelValues("forbidden").Inc()
		return
	}

	policy := issuer.CSRPolicy{
		DNSSANPattern:    iss.DNSSANPattern,
		AllowedCNPattern: iss.AllowedCNPattern,
	}
	if iss.SANValidation {
		policy.SourceIP = issuer.SourceIPFromRemoteAddr(r.RemoteAddr)
	}
	if err := issuer.ValidateCSR(csr, policy); err != nil {
		iss.Logger.Warn("CSR validation failed", "error", err, "remote_addr", r.RemoteAddr)
		http.Error(w, "forbidden: certificate request denied", http.StatusForbidden)
		sanValidationFailuresTotal.Inc()
		if len(csr.DNSNames) > 0 {
			dnsSanValidationFailuresTotal.Inc()
		}
		signRequestsTotal.WithLabelValues("forbidden").Inc()
		return
	}

	// Cap TTL (already parsed by issuerapi.Duration unmarshal).
	ttl := capTTL(req.TTL.Duration, iss.MaxTTL)

	// Check context before signing.
	if ctx.Err() != nil {
		http.Error(w, "request timeout", http.StatusGatewayTimeout)
		signRequestsTotal.WithLabelValues("timeout").Inc()
		return
	}

	// Sign the certificate.
	certPEM, serial, err := iss.signCSRWithBundle(b, csr, claims, ttl)
	if err != nil {
		iss.Logger.Error("failed to sign CSR", "error", err)
		http.Error(w, "signing failed", http.StatusInternalServerError)
		signRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	resp := signCSRResponse{
		Certificate:   issuerapi.MustPEMData(certPEM),
		CACertificate: issuerapi.MustPEMData(iss.caBundlePEMForResponse(b)),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		iss.Logger.Error("failed to encode sign-csr response", "error", err)
		return
	}

	signRequestsTotal.WithLabelValues("success").Inc()
	certificatesIssuedTotal.Inc()

	// Update aggregate node certificate metrics.
	srcIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	notAfter := time.Now().Add(ttl)
	if srcIP != "" && iss.tracker != nil {
		iss.tracker.track(srcIP, notAfter)
	}

	// Build SAN lists for audit logging.
	ipSANs := make([]string, len(csr.IPAddresses))
	for i, ip := range csr.IPAddresses {
		ipSANs[i] = ip.String()
	}
	dnsSANs := csr.DNSNames
	attDigest := fmt.Sprintf("%x", sha256.Sum256(claims.RawEvidence))

	// Structured audit log.
	iss.Logger.Info("certificate issued",
		"audit", true,
		"subject", csr.Subject.CommonName,
		"serial", fmt.Sprintf("%x", serial),
		"not_after", notAfter.Format(time.RFC3339),
		"ip_sans", ipSANs,
		"dns_sans", dnsSANs,
		"ttl", ttl,
		"remote_addr", r.RemoteAddr,
		"attestation_digest", attDigest,
	)
}

// HandleCA serves the CA certificate chain (public, no auth).
// When intermediate CA is configured, returns intermediate + root PEM bundle.
func (iss *Issuer) HandleCA(w http.ResponseWriter, _ *http.Request) {
	b := iss.getBundle()
	if b == nil {
		http.Error(w, "service unavailable: no certificates loaded", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b.caCert.Raw,
	})
	if b.parentCert != nil {
		pem.Encode(w, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b.parentCert.Raw,
		})
	}
}

// handleReady checks certificate health for the /ready endpoint.
func (iss *Issuer) handleReady(w http.ResponseWriter, _ *http.Request) {
	b := iss.getBundle()
	if b == nil {
		http.Error(w, "not ready: no certificates loaded", http.StatusServiceUnavailable)
		return
	}
	if time.Until(b.caCert.NotAfter) < iss.MinCAValidity {
		http.Error(w, "not ready: CA certificate expiring soon", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

func (iss *Issuer) caBundlePEMForResponse(b *certBundle) []byte {
	if b == nil {
		return nil
	}
	if iss.caBundle != nil {
		if bundlePEM := iss.caBundle.BundlePEMForCurrent(b.caCert); len(bundlePEM) > 0 {
			return bundlePEM
		}
	}

	caCertPEMBytes := certutil.EncodeCertPEM(b.caCert.Raw)
	if b.parentCert != nil {
		caCertPEMBytes = append(caCertPEMBytes, certutil.EncodeCertPEM(b.parentCert.Raw)...)
	}
	return caCertPEMBytes
}

// signCSR creates a CA-signed certificate from the CSR using the current cert bundle.
// Subject is constructed from validated CN only — O, OU, and other fields are stripped.
func (iss *Issuer) signCSR(csr *x509.CertificateRequest, claims *issuer.EARClaims, ttl time.Duration) ([]byte, *big.Int, error) {
	b := iss.getBundle()
	if b == nil {
		return nil, nil, fmt.Errorf("no certificate bundle loaded")
	}
	return iss.signCSRWithBundle(b, csr, claims, ttl)
}

func (iss *Issuer) signCSRWithBundle(b *certBundle, csr *x509.CertificateRequest, claims *issuer.EARClaims, ttl time.Duration) ([]byte, *big.Int, error) {
	ca, err := issuer.WrapCA(b.caCert, b.caKey)
	if err != nil {
		return nil, nil, err
	}
	return ca.SignCSR(issuer.SignCSRParams{
		CSR:      csr,
		TTL:      ttl,
		Evidence: claims.RawEvidence,
	})
}

// loadResourceMap reads a JSON resource map file and returns the parsed map.
// Returns an empty map if path is empty.
func loadResourceMap(path string) (resources.Map, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read resource map %s: %w", path, err)
	}
	var rm resources.Map
	if err := json.Unmarshal(data, &rm); err != nil {
		return nil, fmt.Errorf("parse resource map %s: %w", path, err)
	}
	return rm, nil
}

// certIssuerResources lists the resource paths cert-issuer's sign-csr and
// handoff endpoints check authorisation against.
var certIssuerResources = []resources.Resource{
	resources.CertIssuerSignCSR,
	resources.CertIssuerHandoff,
}

// buildEndpointAllowlists derives per-endpoint measurement allowlists from a resourceMap.
// For each measurement, if any of its glob patterns matches a cert-issuer resource path,
// that measurement is added to the corresponding endpoint's allowlist.
// Uses path.Match for glob matching with "/" separators.
func buildEndpointAllowlists(rm resources.Map) (signCSR, handoff map[string]bool, err error) {
	if len(rm) == 0 {
		return nil, nil, nil
	}

	allowlists := map[resources.Resource]map[string]bool{
		resources.CertIssuerSignCSR: make(map[string]bool),
		resources.CertIssuerHandoff: make(map[string]bool),
	}

	for measurement, globs := range rm {
		measurement = issuer.NormalizeMeasurement(measurement)
		if measurement == "" {
			continue
		}
		for _, pattern := range globs {
			for _, resource := range certIssuerResources {
				matched, err := path.Match(string(pattern), string(resource))
				if err != nil {
					return nil, nil, fmt.Errorf("invalid resource map glob %q for measurement %q: %w", pattern, measurement, err)
				}
				if matched {
					allowlists[resource][measurement] = true
				}
			}
		}
	}
	signCSR = allowlists[resources.CertIssuerSignCSR]
	handoff = allowlists[resources.CertIssuerHandoff]

	// Return nil instead of empty maps (nil = skip check in checkMeasurement).
	if len(signCSR) == 0 {
		signCSR = nil
	}
	if len(handoff) == 0 {
		handoff = nil
	}
	return signCSR, handoff, nil
}

func capTTL(d time.Duration, maxTTL time.Duration) time.Duration {
	if d <= 0 {
		return maxTTL
	}
	if d > maxTTL {
		return maxTTL
	}
	return d
}

// nodeTracker tracks aggregate certificate issuance metrics without per-IP cardinality.
type nodeTracker struct {
	mu     sync.Mutex
	nodes  map[string]nodeEntry
	maxTTL time.Duration
}

type nodeEntry struct {
	lastSeen   time.Time
	certExpiry time.Time
}

func newNodeTracker(maxTTL time.Duration) *nodeTracker {
	return &nodeTracker{
		nodes:  make(map[string]nodeEntry),
		maxTTL: maxTTL,
	}
}

func (nt *nodeTracker) track(ip string, certExpiry time.Time) {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	nt.nodes[ip] = nodeEntry{
		lastSeen:   time.Now(),
		certExpiry: certExpiry,
	}
}

// updateMetrics recomputes aggregate metrics. Called periodically from a background goroutine.
func (nt *nodeTracker) updateMetrics() {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-2 * nt.maxTTL)

	// Evict stale entries.
	for ip, entry := range nt.nodes {
		if entry.lastSeen.Before(cutoff) {
			delete(nt.nodes, ip)
		}
	}

	activeNodes.Set(float64(len(nt.nodes)))

	if len(nt.nodes) == 0 {
		oldestActiveCertExpiry.Set(0)
		return
	}

	var oldest time.Time
	for _, entry := range nt.nodes {
		if oldest.IsZero() || entry.certExpiry.Before(oldest) {
			oldest = entry.certExpiry
		}
	}
	oldestActiveCertExpiry.Set(oldest.Sub(now).Seconds())
}
