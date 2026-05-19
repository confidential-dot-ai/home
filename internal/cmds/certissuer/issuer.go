package certissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/issuerapi"
	"github.com/lunal-dev/c8s/pkg/ratls"
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
	keyProvider      KeyProvider
	MaxTTL           time.Duration
	SANValidation    bool           // When true, CSR IP SANs must match the request source IP.
	DNSSANPattern    *regexp.Regexp // When set, DNS SANs matching this pattern are allowed. Nil = reject all DNS SANs.
	AllowedCNPattern *regexp.Regexp // When set, CSR CN must match this pattern. Nil = no CN restriction.
	ExpectedIssuer   string         // When non-empty, validates the EAR issuer claim.
	RequestTimeout   time.Duration  // Per-request timeout. Zero = no timeout.
	JWTClockSkew     int64          // Maximum acceptable clock difference (seconds) for JWT validation.
	MinCAValidity    time.Duration  // Minimum remaining CA cert validity for readiness.
	Logger           *slog.Logger
	tracker          *nodeTracker
	caBundle         *bundleManager // Optional public CA bundle source for sign-csr responses.

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

// tokenValidationError classifies token validation failures for metrics.
type tokenValidationError struct {
	Reason string // "expired", "invalid_signature", "malformed", "invalid_issuer"
	Err    error
}

func (e *tokenValidationError) Error() string { return e.Err.Error() }
func (e *tokenValidationError) Unwrap() error { return e.Err }

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
	claims, err := validateEARToken(req.EAR, iss.keyProvider, iss.ExpectedIssuer, iss.JWTClockSkew)
	if err != nil {
		iss.Logger.Warn("EAR token validation failed", "error", err)
		var tve *tokenValidationError
		if errors.As(err, &tve) {
			tokenValidationFailuresTotal.WithLabelValues(tve.Reason).Inc()
		}
		http.Error(w, "unauthorized: invalid attestation token", http.StatusUnauthorized)
		signRequestsTotal.WithLabelValues("unauthorized").Inc()
		return
	}

	// Check measurement allowlist.
	if err := checkMeasurement(claims, iss.SignCSRMeasurements, "sign-csr"); err != nil {
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
	if err := verifyKeyBinding(csr, claims); err != nil {
		iss.Logger.Warn("key binding failed", "error", err)
		http.Error(w, "forbidden: certificate request denied", http.StatusForbidden)
		tokenValidationFailuresTotal.WithLabelValues("key_binding").Inc()
		signRequestsTotal.WithLabelValues("forbidden").Inc()
		return
	}

	// Validate requested names even when source-IP matching is disabled for
	// forwarding brokers such as Assam.
	if err := iss.validateCSRRequestedNames(csr); err != nil {
		iss.Logger.Warn("CSR requested-name validation failed", "error", err, "remote_addr", r.RemoteAddr)
		http.Error(w, "forbidden: certificate request denied", http.StatusForbidden)
		sanValidationFailuresTotal.Inc()
		signRequestsTotal.WithLabelValues("forbidden").Inc()
		return
	}

	// Validate CSR source binding: IP SANs must match the request source IP.
	if iss.SANValidation {
		if err := iss.validateCSRSourceIP(csr, r.RemoteAddr); err != nil {
			iss.Logger.Warn("CSR source-IP validation failed", "error", err, "remote_addr", r.RemoteAddr)
			http.Error(w, "forbidden: certificate request denied", http.StatusForbidden)
			sanValidationFailuresTotal.Inc()
			signRequestsTotal.WithLabelValues("forbidden").Inc()
			return
		}
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
		if bundlePEM := iss.caBundle.bundlePEMForCurrent(b.caCert); len(bundlePEM) > 0 {
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
func (iss *Issuer) signCSR(csr *x509.CertificateRequest, claims *earClaims, ttl time.Duration) ([]byte, *big.Int, error) {
	b := iss.getBundle()
	if b == nil {
		return nil, nil, fmt.Errorf("no certificate bundle loaded")
	}
	return iss.signCSRWithBundle(b, csr, claims, ttl)
}

func (iss *Issuer) signCSRWithBundle(b *certBundle, csr *x509.CertificateRequest, claims *earClaims, ttl time.Duration) ([]byte, *big.Int, error) {
	template, err := certutil.NewLeafTemplate(csr.Subject.CommonName, ttl)
	if err != nil {
		return nil, nil, err
	}
	template.DNSNames = csr.DNSNames
	template.IPAddresses = csr.IPAddresses
	attDigest := sha256.Sum256(claims.RawEvidence)
	if err := certutil.AppendAttestationDigest(template, attDigest[:]); err != nil {
		return nil, nil, err
	}
	copyRATLSExtension(template, csr)

	certDER, err := x509.CreateCertificate(rand.Reader, template, b.caCert, csr.PublicKey, b.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}

	certPEM := certutil.EncodeCertPEM(certDER)
	return certPEM, template.SerialNumber, nil
}

func copyRATLSExtension(template *x509.Certificate, csr *x509.CertificateRequest) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(ratls.OIDRATLSAttestation) {
			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
				Id:    ext.Id,
				Value: ext.Value,
			})
			return
		}
	}
}

// earClaims represents the relevant claims from an EAR (Entity Attestation
// Result) JWT token issued by assam after successful TEE attestation.
type earClaims struct {
	// Issuer is matched against --expected-issuer at startup.
	Issuer string
	// IssuedAt is a Unix timestamp.
	IssuedAt int64
	// Expiry is a Unix timestamp.
	Expiry int64
	// TEEPubKey is the base64url-encoded DER PKIX public key from the TEE,
	// bound to the attestation report via REPORTDATA.
	TEEPubKey string
	// RawEvidence is the raw attestation evidence for audit hashing.
	// EAR carries submods as a JSON object, so we use json.RawMessage.
	RawEvidence json.RawMessage
}

func (claims *earClaims) UnmarshalJSON(raw []byte) error {
	*claims = earClaims{RawEvidence: append(json.RawMessage(nil), raw...)}
	var rawEvidence json.RawMessage
	if err := earclaims.UnmarshalObject(raw,
		earclaims.Bind(earclaims.Issuer, &claims.Issuer),
		earclaims.Bind(earclaims.IssuedAt, &claims.IssuedAt),
		earclaims.Bind(earclaims.ExpiresAt, &claims.Expiry),
		earclaims.Bind(earclaims.TEEPublicKey, &claims.TEEPubKey),
		earclaims.Bind(earclaims.Submods, &rawEvidence),
	); err != nil {
		return err
	}
	if len(rawEvidence) > 0 {
		claims.RawEvidence = rawEvidence
	}
	return nil
}

// validateEARToken validates the EAR JWT signature, claims, and issuer.
func validateEARToken(tokenStr string, provider KeyProvider, expectedIssuer string, clockSkew int64) (*earClaims, error) {
	claims, err := parseAndVerifyJWT(tokenStr, provider)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	if claims.Expiry == 0 {
		return nil, &tokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("token missing exp claim"),
		}
	}

	// Check expiry with clock skew tolerance.
	if now > claims.Expiry+clockSkew {
		return nil, &tokenValidationError{
			Reason: "expired",
			Err:    fmt.Errorf("token expired at %d, now %d (skew tolerance %ds)", claims.Expiry, now, clockSkew),
		}
	}

	// Check issued-at: reject tokens claiming to be from the future.
	if claims.IssuedAt > 0 && claims.IssuedAt > now+clockSkew {
		return nil, &tokenValidationError{
			Reason: "expired",
			Err:    fmt.Errorf("token issued in the future: iat %d, now %d (skew tolerance %ds)", claims.IssuedAt, now, clockSkew),
		}
	}

	// Validate issuer claim.
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return nil, &tokenValidationError{
			Reason: "invalid_issuer",
			Err:    fmt.Errorf("token issuer %q does not match expected %q", claims.Issuer, expectedIssuer),
		}
	}

	return claims, nil
}

// checkMeasurement validates that the EAR token's attestation evidence contains
// a measurement in the allowed set. Returns nil if allowed is empty (opt-in).
func checkMeasurement(claims *earClaims, allowed map[string]bool, endpoint string) error {
	if len(allowed) == 0 {
		return nil
	}
	measurement, err := earclaims.LaunchDigestFromSubmods(claims.RawEvidence)
	if err != nil {
		return &tokenValidationError{
			Reason: "measurement_denied",
			Err:    fmt.Errorf("extract measurement for %s: %w", endpoint, err),
		}
	}
	if !allowed[measurement] {
		return &tokenValidationError{
			Reason: "measurement_denied",
			Err:    fmt.Errorf("measurement not allowed for %s", endpoint),
		}
	}
	return nil
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

// verifyKeyBinding checks that the CSR's public key matches the TEE-bound key
// in the EAR claims.
func verifyKeyBinding(csr *x509.CertificateRequest, claims *earClaims) error {
	if claims.TEEPubKey == "" {
		return fmt.Errorf("EAR is missing %s claim", earclaims.TEEPublicKey)
	}

	csrPubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal CSR public key: %w", err)
	}

	claimPubDER, err := base64.RawURLEncoding.DecodeString(claims.TEEPubKey)
	if err != nil {
		return fmt.Errorf("decode %s claim: %w", earclaims.TEEPublicKey, err)
	}

	csrHash := sha256.Sum256(csrPubDER)
	claimHash := sha256.Sum256(claimPubDER)
	if csrHash != claimHash {
		return fmt.Errorf("CSR public key does not match TEE-attested key")
	}

	return nil
}

// validateCSRSourceIP checks that all IP SANs in the CSR match the request
// source IP. This prevents a directly connected compromised TEE node from
// requesting IP SANs for other nodes. Brokers that forward CSRs can disable this
// source-IP check while still using validateCSRRequestedNames below.
func (iss *Issuer) validateCSRSourceIP(csr *x509.CertificateRequest, remoteAddr string) error {
	srcIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// remoteAddr might not have a port (e.g., Unix socket).
		srcIP = remoteAddr
	}

	for _, ip := range csr.IPAddresses {
		if ip.String() != srcIP {
			return fmt.Errorf("CSR IP SAN %s does not match request source %s", ip, srcIP)
		}
	}

	return nil
}

// validateCSRRequestedNames checks requested DNS names and common names. DNS
// SANs are rejected by default unless the caller configures DNSSANPattern. CN is
// validated against AllowedCNPattern when set.
func (iss *Issuer) validateCSRRequestedNames(csr *x509.CertificateRequest) error {
	if len(csr.DNSNames) > 0 {
		if iss.DNSSANPattern == nil {
			dnsSanValidationFailuresTotal.Inc()
			return fmt.Errorf("CSR contains DNS SANs %v but no DNS SAN pattern configured", csr.DNSNames)
		}
		for _, dns := range csr.DNSNames {
			if !iss.DNSSANPattern.MatchString(dns) {
				dnsSanValidationFailuresTotal.Inc()
				return fmt.Errorf("CSR DNS SAN %q does not match allowed pattern", dns)
			}
		}
	}

	if iss.AllowedCNPattern != nil && csr.Subject.CommonName != "" {
		if !iss.AllowedCNPattern.MatchString(csr.Subject.CommonName) {
			return fmt.Errorf("CSR CN %q does not match allowed pattern", csr.Subject.CommonName)
		}
	}

	return nil
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

// parseAndVerifyJWT is a minimal JWT parser for ES256/ES384 tokens.
func parseAndVerifyJWT(tokenStr string, provider KeyProvider) (*earClaims, error) {
	tokenBytes := []byte(tokenStr)
	msg, err := jws.Parse(tokenBytes)
	if err != nil {
		return nil, &tokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("parse JWT: %w", err),
		}
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return nil, &tokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("JWT has %d signatures, expected 1", len(sigs)),
		}
	}
	header := sigs[0].ProtectedHeaders()
	alg := header.Algorithm()
	if alg != jwa.ES256 && alg != jwa.ES384 {
		return nil, &tokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("unsupported JWT algorithm: %s (need ES256 or ES384)", alg),
		}
	}

	ecPub, err := provider.PublicKey(header.KeyID())
	if err != nil {
		return nil, &tokenValidationError{
			Reason: "invalid_signature",
			Err:    fmt.Errorf("resolve signing key: %w", err),
		}
	}

	if _, err := jws.Verify(tokenBytes, jws.WithKey(alg, ecPub)); err != nil {
		return nil, &tokenValidationError{
			Reason: "invalid_signature",
			Err:    fmt.Errorf("JWT signature verification failed: %w", err),
		}
	}

	payload := msg.Payload()
	var claims earClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, &tokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("parse JWT claims: %w", err),
		}
	}
	if len(claims.RawEvidence) == 0 {
		claims.RawEvidence = payload
	}

	return &claims, nil
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
