package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
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

	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/issuerapi"
)

// OID for the attestation digest extension.
// 1.3.6.1.4.1.59888.1.2 — SHA-256 of the attestation evidence (audit trail).
var OIDAttestationDigest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1, 2}

// certBundle holds the loaded certificate material for atomic hot-swap.
type certBundle struct {
	caCert          *x509.Certificate
	caKey           *ecdsa.PrivateKey
	tokenSignerCert *x509.Certificate
	// parentCert, when set, is the root CA that signed the intermediate caCert.
	// The SignCSR response includes the full chain: leaf + intermediate + root.
	parentCert *x509.Certificate
}

// Issuer validates EAR JWT tokens from KBS and signs CSRs with its CA key.
type Issuer struct {
	bundle           atomic.Pointer[certBundle]
	keyProvider      KeyProvider
	MaxTTL           time.Duration
	SANValidation    bool           // When true, CSR IP SANs must match the request source IP.
	DNSSANPattern    *regexp.Regexp // When set, DNS SANs matching this pattern are allowed. Nil = reject all DNS SANs.
	AllowedCNPattern *regexp.Regexp // When set, CSR CN must match this pattern. Nil = no CN restriction.
	ExpectedIssuer   string         // When non-empty, validates the "iss" claim in EAR tokens.
	RequestTimeout   time.Duration  // Per-request timeout. Zero = no timeout.
	JWTClockSkew     int64          // Maximum acceptable clock difference (seconds) for JWT validation.
	MinCAValidity    time.Duration  // Minimum remaining CA cert validity for readiness.
	Logger           *slog.Logger
	tracker          *nodeTracker

	// Per-endpoint measurement allowlists. Empty map = skip check (opt-in).
	SignCSRMeasurements  map[string]bool
	RotateCAMeasurements map[string]bool
	CAMeasurements       map[string]bool
}

func (iss *Issuer) getBundle() *certBundle {
	return iss.bundle.Load()
}

// Type aliases for the shared wire types, kept for local readability.
type SignCSRRequest = issuerapi.SignCSRRequest
type SignCSRResponse = issuerapi.SignCSRResponse

// TokenValidationError classifies token validation failures for metrics.
type TokenValidationError struct {
	Reason string // "expired", "invalid_signature", "malformed", "invalid_issuer"
	Err    error
}

func (e *TokenValidationError) Error() string { return e.Err.Error() }
func (e *TokenValidationError) Unwrap() error { return e.Err }

// HandleSignCSR handles POST /v1/sign-csr.
func (iss *Issuer) HandleSignCSR(w http.ResponseWriter, r *http.Request) {
	activeRequests.Inc()
	defer activeRequests.Dec()
	start := time.Now()
	defer func() { signLatencySeconds.Observe(time.Since(start).Seconds()) }()

	// Apply per-request timeout (4.1).
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

	var req SignCSRRequest
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
		var tve *TokenValidationError
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

	// Verify key binding: CSR public key must match the tee-pubkey in EAR claims.
	if err := verifyKeyBinding(csr, claims); err != nil {
		iss.Logger.Warn("key binding failed", "error", err)
		http.Error(w, "forbidden: certificate request denied", http.StatusForbidden)
		tokenValidationFailuresTotal.WithLabelValues("key_binding").Inc()
		signRequestsTotal.WithLabelValues("forbidden").Inc()
		return
	}

	// Validate CSR SANs: IP SANs must match the request source IP; DNS SANs validated against pattern.
	if iss.SANValidation {
		if err := iss.validateCSRSANs(csr, r.RemoteAddr); err != nil {
			iss.Logger.Warn("CSR SAN validation failed", "error", err, "remote_addr", r.RemoteAddr)
			http.Error(w, "forbidden: certificate request denied", http.StatusForbidden)
			sanValidationFailuresTotal.Inc()
			signRequestsTotal.WithLabelValues("forbidden").Inc()
			return
		}
	}

	// Cap TTL (already parsed by issuerapi.Duration unmarshal).
	ttl := capTTL(req.TTL.Duration, iss.MaxTTL)

	// Check context before signing (4.1).
	if ctx.Err() != nil {
		http.Error(w, "request timeout", http.StatusGatewayTimeout)
		signRequestsTotal.WithLabelValues("timeout").Inc()
		return
	}

	// Sign the certificate.
	certPEM, serial, err := iss.signCSR(csr, claims, ttl)
	if err != nil {
		iss.Logger.Error("failed to sign CSR", "error", err)
		http.Error(w, "signing failed", http.StatusInternalServerError)
		signRequestsTotal.WithLabelValues("error").Inc()
		return
	}

	// Build CA certificate PEM: intermediate + root if parent is set.
	caCertPEMBytes := certutil.EncodeCertPEM(b.caCert.Raw)
	if b.parentCert != nil {
		caCertPEMBytes = append(caCertPEMBytes, certutil.EncodeCertPEM(b.parentCert.Raw)...)
	}

	resp := SignCSRResponse{
		Certificate:   issuerapi.MustPEMData(certPEM),
		CACertificate: issuerapi.MustPEMData(caCertPEMBytes),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		iss.Logger.Error("failed to encode sign-csr response", "error", err)
		return
	}

	signRequestsTotal.WithLabelValues("success").Inc()
	certificatesIssuedTotal.Inc()

	// Update aggregate node certificate metrics (2.6).
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

	// Structured audit log (3.4).
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

// signCSR creates a CA-signed certificate from the CSR using the current cert bundle.
// Subject is constructed from validated CN only — O, OU, and other fields are stripped (1.1).
func (iss *Issuer) signCSR(csr *x509.CertificateRequest, claims *EARClaims, ttl time.Duration) ([]byte, *big.Int, error) {
	b := iss.getBundle()
	if b == nil {
		return nil, nil, fmt.Errorf("no certificate bundle loaded")
	}

	serialNumber, err := certutil.GenerateSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	// Compute attestation digest for audit trail.
	attDigest := sha256.Sum256(claims.RawEvidence)
	attDigestExt, err := asn1.Marshal(attDigest[:])
	if err != nil {
		return nil, nil, fmt.Errorf("marshal attestation digest: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: csr.Subject.CommonName},
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       OIDAttestationDigest,
				Critical: false,
				Value:    attDigestExt,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, b.caCert, csr.PublicKey, b.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}

	certPEM := certutil.EncodeCertPEM(certDER)
	return certPEM, serialNumber, nil
}

// EARClaims represents the relevant claims from an EAR (Entity Attestation
// Result) JWT token issued by KBS after successful TEE attestation.
type EARClaims struct {
	// Issuer is the "iss" claim (should be KBS).
	Issuer string `json:"iss"`
	// IssuedAt is the "iat" claim (Unix timestamp).
	IssuedAt int64 `json:"iat"`
	// Expiry is the "exp" claim (Unix timestamp).
	Expiry int64 `json:"exp"`
	// TEEPubKey is the base64url-encoded DER PKIX public key from the TEE,
	// bound to the attestation report via REPORTDATA.
	TEEPubKey string `json:"tee-pubkey"`
	// RawEvidence is the raw attestation evidence for audit hashing.
	// KBS returns submods as a JSON object, so we use json.RawMessage.
	RawEvidence json.RawMessage `json:"submods"`
}

// validateEARToken validates the EAR JWT signature, claims, and issuer (1.5).
func validateEARToken(tokenStr string, provider KeyProvider, expectedIssuer string, clockSkew int64) (*EARClaims, error) {
	claims, err := parseAndVerifyJWT(tokenStr, provider)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	// Check expiry with clock skew tolerance.
	if claims.Expiry > 0 && now > claims.Expiry+clockSkew {
		return nil, &TokenValidationError{
			Reason: "expired",
			Err:    fmt.Errorf("token expired at %d, now %d (skew tolerance %ds)", claims.Expiry, now, clockSkew),
		}
	}

	// Check issued-at: reject tokens claiming to be from the future.
	if claims.IssuedAt > 0 && claims.IssuedAt > now+clockSkew {
		return nil, &TokenValidationError{
			Reason: "expired",
			Err:    fmt.Errorf("token issued in the future: iat %d, now %d (skew tolerance %ds)", claims.IssuedAt, now, clockSkew),
		}
	}

	// Validate issuer claim (1.5).
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return nil, &TokenValidationError{
			Reason: "invalid_issuer",
			Err:    fmt.Errorf("token issuer %q does not match expected %q", claims.Issuer, expectedIssuer),
		}
	}

	return claims, nil
}

// submodsEvidence represents the nested EAR token submods structure
// for extracting the SNP launch measurement.
type submodsEvidence struct {
	CPU0 struct {
		AnnotatedEvidence struct {
			SNP *struct {
				Measurement string `json:"measurement"`
			} `json:"snp,omitempty"`
		} `json:"ear.veraison.annotated-evidence"`
	} `json:"cpu0"`
}

// extractMeasurement parses the EAR submods JSON and returns the SNP launch measurement.
func extractMeasurement(rawEvidence json.RawMessage) (string, error) {
	var evidence submodsEvidence
	if err := json.Unmarshal(rawEvidence, &evidence); err != nil {
		return "", fmt.Errorf("parse submods: %w", err)
	}
	if evidence.CPU0.AnnotatedEvidence.SNP == nil {
		return "", fmt.Errorf("no SNP evidence in submods")
	}
	m := evidence.CPU0.AnnotatedEvidence.SNP.Measurement
	if m == "" {
		return "", fmt.Errorf("empty measurement in SNP evidence")
	}
	return m, nil
}

// checkMeasurement validates that the EAR token's attestation evidence contains
// a measurement in the allowed set. Returns nil if allowed is empty (opt-in).
func checkMeasurement(claims *EARClaims, allowed map[string]bool, endpoint string) error {
	if len(allowed) == 0 {
		return nil
	}
	measurement, err := extractMeasurement(claims.RawEvidence)
	if err != nil {
		return &TokenValidationError{
			Reason: "measurement_denied",
			Err:    fmt.Errorf("extract measurement for %s: %w", endpoint, err),
		}
	}
	if !allowed[measurement] {
		return &TokenValidationError{
			Reason: "measurement_denied",
			Err:    fmt.Errorf("measurement not allowed for %s", endpoint),
		}
	}
	return nil
}

// ResourceMap maps SHA-384 hex launch measurements to allowed KBS resource path globs.
// This is the same structure used by the KBS Rego policy's measurement_resource_map.
type ResourceMap map[string][]string

// loadResourceMap reads a JSON resource map file and returns the parsed map.
// Returns an empty map if path is empty.
func loadResourceMap(path string) (ResourceMap, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read resource map %s: %w", path, err)
	}
	var rm ResourceMap
	if err := json.Unmarshal(data, &rm); err != nil {
		return nil, fmt.Errorf("parse resource map %s: %w", path, err)
	}
	return rm, nil
}

// certIssuerEndpoints maps cert-issuer KBS resource path prefixes to endpoint names.
var certIssuerEndpoints = map[string]string{
	"cert-issuer/sign-csr":  "sign-csr",
	"cert-issuer/rotate-ca": "rotate-ca",
	"cert-issuer/ca":        "ca",
}

// buildEndpointAllowlists derives per-endpoint measurement allowlists from a ResourceMap.
// For each measurement, if any of its glob patterns matches a cert-issuer resource path,
// that measurement is added to the corresponding endpoint's allowlist.
// Uses path.Match for glob matching (same semantics as KBS's glob.match with "/" separator).
func buildEndpointAllowlists(rm ResourceMap) (signCSR, rotateCA, ca map[string]bool) {
	if len(rm) == 0 {
		return nil, nil, nil
	}

	signCSR = make(map[string]bool)
	rotateCA = make(map[string]bool)
	ca = make(map[string]bool)

	for measurement, globs := range rm {
		for _, pattern := range globs {
			for resourcePath, endpoint := range certIssuerEndpoints {
				matched, err := path.Match(pattern, resourcePath)
				if err != nil {
					continue // invalid pattern, skip
				}
				if matched {
					switch endpoint {
					case "sign-csr":
						signCSR[measurement] = true
					case "rotate-ca":
						rotateCA[measurement] = true
					case "ca":
						ca[measurement] = true
					}
				}
			}
		}
	}

	// Return nil instead of empty maps (nil = skip check in checkMeasurement).
	if len(signCSR) == 0 {
		signCSR = nil
	}
	if len(rotateCA) == 0 {
		rotateCA = nil
	}
	if len(ca) == 0 {
		ca = nil
	}
	return signCSR, rotateCA, ca
}

// verifyKeyBinding checks that the CSR's public key matches the TEE-bound key
// in the EAR claims.
func verifyKeyBinding(csr *x509.CertificateRequest, claims *EARClaims) error {
	if claims.TEEPubKey == "" {
		// Trustee KBS EAR tokens don't include a tee-pubkey claim.
		// Key binding is skipped; attestation integrity is ensured by KBS.
		return nil
	}

	csrPubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal CSR public key: %w", err)
	}

	claimPubDER, err := base64.RawURLEncoding.DecodeString(claims.TEEPubKey)
	if err != nil {
		return fmt.Errorf("decode tee-pubkey claim: %w", err)
	}

	csrHash := sha256.Sum256(csrPubDER)
	claimHash := sha256.Sum256(claimPubDER)
	if csrHash != claimHash {
		return fmt.Errorf("CSR public key does not match TEE-attested key")
	}

	return nil
}

// validateCSRSANs checks that all IP SANs in the CSR match the request source
// IP. This prevents a compromised TEE node from requesting certificates with
// arbitrary SANs to impersonate other nodes. DNS SANs are validated against a
// configurable pattern — rejected by default if no pattern is set (1.1).
// CN is validated against AllowedCNPattern when set.
func (iss *Issuer) validateCSRSANs(csr *x509.CertificateRequest, remoteAddr string) error {
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

	// DNS SAN validation (1.1): reject all DNS SANs by default.
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

	// CN validation (1.1).
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
func parseAndVerifyJWT(tokenStr string, provider KeyProvider) (*EARClaims, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, &TokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts)),
		}
	}

	// Decode header to determine algorithm.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, &TokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("decode JWT header: %w", err),
		}
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, &TokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("parse JWT header: %w", err),
		}
	}

	// Determine expected curve and hash from algorithm.
	var curve elliptic.Curve
	var newHash func() hash.Hash
	switch header.Alg {
	case "ES256":
		curve = elliptic.P256()
		newHash = sha256.New
	case "ES384":
		curve = elliptic.P384()
		newHash = sha512.New384
	default:
		return nil, &TokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("unsupported JWT algorithm: %s (need ES256 or ES384)", header.Alg),
		}
	}

	// Resolve ECDSA public key via the provider (JWKS or cert-based).
	ecPub, err := provider.PublicKey(header.Kid)
	if err != nil {
		return nil, &TokenValidationError{
			Reason: "invalid_signature",
			Err:    fmt.Errorf("resolve signing key: %w", err),
		}
	}
	if ecPub.Curve != curve {
		return nil, &TokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("signing key curve %s doesn't match JWT alg %s", ecPub.Curve.Params().Name, header.Alg),
		}
	}

	// Verify signature: hash(header.payload) then ECDSA verify.
	signingInput := []byte(parts[0] + "." + parts[1])
	h := newHash()
	h.Write(signingInput)
	digest := h.Sum(nil)

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, &TokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("decode JWT signature: %w", err),
		}
	}

	// JWT ECDSA signatures are r||s (each half = key size / 8 bytes).
	keySize := (curve.Params().BitSize + 7) / 8
	if len(sigBytes) != 2*keySize {
		return nil, &TokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("JWT signature length %d, expected %d for %s", len(sigBytes), 2*keySize, header.Alg),
		}
	}
	r := new(big.Int).SetBytes(sigBytes[:keySize])
	s := new(big.Int).SetBytes(sigBytes[keySize:])

	if !ecdsa.Verify(ecPub, digest, r, s) {
		return nil, &TokenValidationError{
			Reason: "invalid_signature",
			Err:    fmt.Errorf("JWT signature verification failed"),
		}
	}

	// Decode claims.
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &TokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("decode JWT claims: %w", err),
		}
	}

	var claims EARClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, &TokenValidationError{
			Reason: "malformed",
			Err:    fmt.Errorf("parse JWT claims: %w", err),
		}
	}
	if len(claims.RawEvidence) == 0 {
		claims.RawEvidence = claimsBytes
	}

	return &claims, nil
}

// nodeTracker tracks aggregate certificate issuance metrics without per-IP cardinality (2.6).
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
