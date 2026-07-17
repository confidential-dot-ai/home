package issuer

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/issuerapi"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/cryptobyte"
)

// maxHandoffErrorBytes caps how much of an untrusted peer's non-2xx /handoff
// response body is read into HandoffStatusError. A few KB is plenty for an
// error message.
const maxHandoffErrorBytes = 8 << 10

const (
	handoffProtocolLabel            = "c8s-cds-handoff-v1"
	handoffRequestSignaturePurpose  = "request-signature"
	handoffResponseSignaturePurpose = "response-signature"
	handoffPayloadKeyPurpose        = "payload-key"
	handoffPayloadAADPurpose        = "payload-aad"
)

type HandoffRequest = issuerapi.HandoffRequest
type HandoffResponse = issuerapi.HandoffResponse

var (
	tokenValidationFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cds_token_validation_failures_total",
		Help: "Token validation failures by reason.",
	}, []string{"reason"})

	measurementDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cds_measurement_denied_total",
		Help: "Requests denied due to measurement mismatch.",
	}, []string{"endpoint"})

	handoffEARExpirySeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cds_handoff_ear_expiry_seconds",
		Help: "Seconds until the handoff issuer EAR exp claim; negative when expired or unreadable.",
	})
)

// RecordTokenValidationFailure increments the per-reason counter when err is a
// *TokenValidationError. Untyped failures are logged so they aren't lost from
// the per-reason metric without any trace.
func RecordTokenValidationFailure(err error) {
	var tve *TokenValidationError
	if errors.As(err, &tve) {
		tokenValidationFailuresTotal.WithLabelValues(string(tve.Reason)).Inc()
		return
	}
	slog.Warn("token validation failed without typed reason", "error", err)
}

// RecordMeasurementDenied increments the per-endpoint measurement-denied
// counter (endpoint is the route label, e.g. "sign-csr", "handoff").
func RecordMeasurementDenied(endpoint string) {
	measurementDeniedTotal.WithLabelValues(endpoint).Inc()
}

// HandoffDeps carries the EAR verification context, active CA snapshot, and
// public bundle the handoff handler needs. It decouples the handler from any
// particular Issuer implementation.
type HandoffDeps struct {
	Logger              *slog.Logger
	KeyProvider         KeyProvider
	ExpectedIssuer      string
	AllowedMeasurements map[string]bool
	// OperatorKeysHash is the local CDS operator-key policy commitment. A
	// requester EAR must carry the exact same REPORTDATA-bound value.
	OperatorKeysHash string
	Bundle           *BundleManager // optional; nil falls back to caCert-only bundle PEM

	// Signer (bootstrapped via HandoffBootstrap) signs the response transcript.
	Signer *ecdsa.PrivateKey

	// EARSource yields the issuer EAR refreshed via /attest-key. Need not be
	// ready at construction: the bootstrap runs asynchronously and HandleHandoff
	// returns 503 until the first refresh populates it.
	EARSource HandoffEARSource

	// Snapshot returns the active CA material. ok=false means no bundle is
	// loaded (handler returns 503).
	Snapshot func() (snap CASnapshot, ok bool)
}

// CASnapshot is the active CA material a handoff response transfers: the CA
// cert and its private key, plus the optional parent cert when the CA is an
// intermediate.
type CASnapshot struct {
	Cert       *x509.Certificate
	Key        *ecdsa.PrivateKey
	ParentCert *x509.Certificate // nil for a self-signed root CA
	// AllowlistVersion and Allowlist are copied into the encrypted payload so
	// a rolling adoption preserves runtime operator additions.
	AllowlistVersion string
	Allowlist        map[types.Digest]string
}

func (s CASnapshot) hasCAKeyPair() bool {
	return s.Cert != nil && s.Key != nil
}

// HandoffHandler wraps the active in-memory CA to attested replicas. The CA
// private key never leaves process memory except as recipient-bound ciphertext
// in the handoff response.
type HandoffHandler struct {
	deps      HandoffDeps
	earSource HandoffEARSource
	signer    *ecdsa.PrivateKey
}

// NewHandoffHandler validates the dependencies and returns a HandoffHandler.
//
// Does NOT require deps.EARSource.Current() to succeed at construction: the
// bootstrap runs asynchronously, and HandleHandoff returns 503 until the first
// refresh populates the source.
func NewHandoffHandler(deps HandoffDeps) (*HandoffHandler, error) {
	if deps.Signer == nil {
		return nil, fmt.Errorf("HandoffDeps.Signer is required")
	}
	if deps.EARSource == nil {
		return nil, fmt.Errorf("HandoffDeps.EARSource is required")
	}
	if deps.KeyProvider == nil {
		return nil, fmt.Errorf("HandoffDeps.KeyProvider is required")
	}
	if deps.Snapshot == nil {
		return nil, fmt.Errorf("HandoffDeps.Snapshot is required")
	}
	if len(deps.AllowedMeasurements) == 0 {
		return nil, fmt.Errorf("handoff requires a non-empty measurement allowlist")
	}
	if err := operatorauth.ValidateKeySetHash(deps.OperatorKeysHash); err != nil {
		return nil, fmt.Errorf("handoff requires an operator-key policy: %w", err)
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return &HandoffHandler{deps: deps, earSource: deps.EARSource, signer: deps.Signer}, nil
}

// IssuerEARSource exposes the source so callers can wire the expiry-metric
// updater without re-plumbing it.
func (hh *HandoffHandler) IssuerEARSource() HandoffEARSource { return hh.earSource }

type handoffPayload struct {
	CAKey             string                  `json:"ca_key"`
	CACertificate     string                  `json:"ca_certificate"`
	CABundle          string                  `json:"ca_bundle"`
	ParentCertificate string                  `json:"parent_certificate,omitempty"`
	AllowlistVersion  string                  `json:"allowlist_version"`
	Allowlist         map[types.Digest]string `json:"allowlist"`
}

// HandoffMaterial is the unwrapped result of a successful handoff.
type HandoffMaterial struct {
	CAKey            *ecdsa.PrivateKey
	CACert           *x509.Certificate
	ParentCert       *x509.Certificate
	Bundle           []*x509.Certificate
	AllowlistVersion string
	Allowlist        map[types.Digest]string
}

// HandoffClientDeps carries the EAR verification context the requester needs to
// validate the issuer's response.
type HandoffClientDeps struct {
	KeyProvider         KeyProvider
	ExpectedIssuer      string
	AllowedMeasurements map[string]bool
	// OperatorKeysHash is the local operator-key policy commitment expected
	// in the issuer's REPORTDATA-bound handoff EAR.
	OperatorKeysHash string
}

// HandoffStatusError is a non-2xx handoff response, typed so callers can
// distinguish disabled (404) from not-yet-bootstrapped (503).
type HandoffStatusError struct {
	Status int
	Body   string
}

func (e *HandoffStatusError) Error() string {
	return fmt.Sprintf("handoff peer returned %d: %s", e.Status, e.Body)
}

// HandleHandoff validates a replica EAR and returns the CA material encrypted
// to the requester's X25519 public key.
func (hh *HandoffHandler) HandleHandoff(w http.ResponseWriter, r *http.Request) {
	issuerEAR, err := hh.earSource.Current()
	if err != nil {
		hh.deps.Logger.Error("handoff EAR load failed", "error", err)
		http.Error(w, "handoff unavailable: issuer EAR load failed", http.StatusServiceUnavailable)
		return
	}
	if strings.TrimSpace(issuerEAR) == "" {
		http.Error(w, "handoff unavailable: issuer EAR is not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request: failed to read body", http.StatusBadRequest)
		return
	}

	var req HandoffRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request: invalid JSON", http.StatusBadRequest)
		return
	}
	if req.EAR == "" || req.PublicKey == "" || req.Signature == "" {
		http.Error(w, "bad request: ear, public_key, and signature are required", http.StatusBadRequest)
		return
	}

	claims, err := ValidateEARToken(req.EAR, hh.deps.KeyProvider, hh.deps.ExpectedIssuer)
	if err != nil {
		RecordTokenValidationFailure(err)
		http.Error(w, "unauthorized: invalid requester attestation token", http.StatusUnauthorized)
		return
	}
	if err := checkRequiredMeasurement(claims, hh.deps.AllowedMeasurements, "handoff"); err != nil {
		RecordTokenValidationFailure(err)
		RecordMeasurementDenied("handoff")
		http.Error(w, "forbidden: requester measurement not allowed", http.StatusForbidden)
		return
	}
	if err := checkOperatorPolicy(claims, hh.deps.OperatorKeysHash, "requester"); err != nil {
		RecordTokenValidationFailure(err)
		http.Error(w, "forbidden: requester operator-key policy does not match", http.StatusForbidden)
		return
	}
	requestMessage, err := handoffRequestMessage(req.EAR, req.PublicKey)
	if err != nil {
		hh.deps.Logger.Warn("handoff requester transcript failed", "error", err)
		http.Error(w, "bad request: invalid requester handoff transcript", http.StatusBadRequest)
		return
	}
	if err := verifyHandoffSignature(claims, req.Signature, requestMessage, "requester"); err != nil {
		hh.deps.Logger.Warn("handoff requester key proof failed", "error", err)
		http.Error(w, "unauthorized: invalid requester key proof", http.StatusUnauthorized)
		return
	}

	snap, ok := hh.deps.Snapshot()
	if !ok || !snap.hasCAKeyPair() {
		http.Error(w, "service unavailable: no certificates loaded", http.StatusServiceUnavailable)
		return
	}

	resp, err := hh.wrap(req, snap, issuerEAR)
	if err != nil {
		hh.deps.Logger.Error("handoff wrap failed", "error", err)
		http.Error(w, "internal error: handoff wrap failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		hh.deps.Logger.Error("handoff response encode failed", "error", err)
	}
}

func (hh *HandoffHandler) wrap(req HandoffRequest, snap CASnapshot, issuerEAR string) (HandoffResponse, error) {
	if !snap.hasCAKeyPair() {
		return HandoffResponse{}, fmt.Errorf("handoff CA snapshot requires cert and key")
	}

	requesterPubRaw, err := decodeB64(req.PublicKey, "requester public key")
	if err != nil {
		return HandoffResponse{}, err
	}
	requesterPub, err := ecdh.X25519().NewPublicKey(requesterPubRaw)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("parse requester public key: %w", err)
	}

	keyPEM, err := certutil.MarshalECKeyPEM(snap.Key)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("marshal CA key: %w", err)
	}

	bundlePEM := certutil.EncodeCertPEM(snap.Cert.Raw)
	if hh.deps.Bundle != nil {
		bundlePEM = hh.deps.Bundle.BundlePEMForCurrent(snap.Cert)
	}

	payload := handoffPayload{
		CAKey:            string(keyPEM),
		CACertificate:    string(certutil.EncodeCertPEM(snap.Cert.Raw)),
		CABundle:         string(bundlePEM),
		AllowlistVersion: snap.AllowlistVersion,
		Allowlist:        snap.Allowlist,
	}
	if err := validateAllowlistSnapshot(payload.AllowlistVersion, payload.Allowlist); err != nil {
		return HandoffResponse{}, err
	}
	if snap.ParentCert != nil {
		payload.ParentCertificate = string(certutil.EncodeCertPEM(snap.ParentCert.Raw))
	}

	plain, err := json.Marshal(payload)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("marshal handoff payload: %w", err)
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("generate handoff key: %w", err)
	}
	shared, err := priv.ECDH(requesterPub)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("derive handoff secret: %w", err)
	}

	serverPub := encodeB64(priv.PublicKey().Bytes())
	aead, err := handoffAEAD(shared, req.EAR, issuerEAR)
	if err != nil {
		return HandoffResponse{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return HandoffResponse{}, fmt.Errorf("generate handoff nonce: %w", err)
	}

	aad, err := handoffAAD(req.EAR, issuerEAR, req.PublicKey, serverPub)
	if err != nil {
		return HandoffResponse{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plain, aad)
	responseMessage, err := handoffResponseMessage(req.EAR, issuerEAR, req.PublicKey, serverPub)
	if err != nil {
		return HandoffResponse{}, err
	}
	signature, err := signHandoffMessage(hh.signer, responseMessage)
	if err != nil {
		return HandoffResponse{}, err
	}
	return HandoffResponse{
		IssuerEAR:  issuerEAR,
		PublicKey:  serverPub,
		Signature:  signature,
		Nonce:      encodeB64(nonce),
		Ciphertext: encodeB64(ciphertext),
	}, nil
}

// RunHandoffEARExpiryUpdater refreshes the handoff EAR expiry gauge on a fixed
// interval. On read or parse failure it sets the gauge negative so expiry
// alerts fail closed instead of preserving a stale positive value.
func RunHandoffEARExpiryUpdater(ctx context.Context, src HandoffEARSource, interval time.Duration, logger *slog.Logger) {
	update := func() {
		ear, err := src.Current()
		if err != nil {
			logger.Warn("handoff EAR refresh failed for metrics", "error", err)
			handoffEARExpirySeconds.Set(-1)
			return
		}
		exp, err := HandoffEARExpiry(ear)
		if err != nil {
			logger.Warn("handoff EAR parse failed for metrics", "error", err)
			handoffEARExpirySeconds.Set(-1)
			return
		}
		handoffEARExpirySeconds.Set(time.Until(exp).Seconds())
	}
	update()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			update()
		}
	}
}

// RequestHandoff drives the client side of the handoff protocol against
// peerURL and returns verified, decrypted CA material. requesterSigningKey is
// the ECDSA key bound into requesterEAR and signs the request transcript. A
// distinct, one-request X25519 key below encrypts the response; the CA private
// key appears only inside the decrypted HandoffMaterial.
func RequestHandoff(ctx context.Context, deps HandoffClientDeps, peerURL, requesterEAR string, requesterSigningKey *ecdsa.PrivateKey, client *http.Client) (*HandoffMaterial, error) {
	if strings.TrimSpace(requesterEAR) == "" {
		return nil, fmt.Errorf("handoff requester EAR is required")
	}
	if requesterSigningKey == nil {
		return nil, fmt.Errorf("handoff requester signing key is required")
	}
	if len(deps.AllowedMeasurements) == 0 {
		return nil, fmt.Errorf("handoff requires a non-empty measurement allowlist")
	}
	if err := operatorauth.ValidateKeySetHash(deps.OperatorKeysHash); err != nil {
		return nil, fmt.Errorf("handoff requires an operator-key policy: %w", err)
	}
	if client == nil {
		client = http.DefaultClient
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate handoff recipient key: %w", err)
	}
	pub := encodeB64(priv.PublicKey().Bytes())
	requestMessage, err := handoffRequestMessage(requesterEAR, pub)
	if err != nil {
		return nil, err
	}
	signature, err := signHandoffMessage(requesterSigningKey, requestMessage)
	if err != nil {
		return nil, err
	}

	reqBody, err := json.Marshal(HandoffRequest{EAR: requesterEAR, PublicKey: pub, Signature: signature})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(peerURL, "/")+"/handoff", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request handoff: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Untrusted peer error body: cap it so a hostile or misconfigured
		// peer cannot balloon memory (or the retry log) with a huge response.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHandoffErrorBytes))
		return nil, &HandoffStatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}

	var hr HandoffResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return nil, fmt.Errorf("decode handoff response: %w", err)
	}
	return UnwrapHandoffResponse(hr, deps, requesterEAR, pub, priv)
}

// UnwrapHandoffResponse verifies the issuer EAR + signature, decrypts the
// recipient-bound payload, and returns the parsed CA material.
func UnwrapHandoffResponse(resp HandoffResponse, deps HandoffClientDeps, requesterEAR, requesterPub string, requesterKey *ecdh.PrivateKey) (*HandoffMaterial, error) {
	if resp.IssuerEAR == "" || resp.PublicKey == "" || resp.Signature == "" || resp.Nonce == "" || resp.Ciphertext == "" {
		return nil, fmt.Errorf("handoff response missing issuer_ear, public_key, signature, nonce, or ciphertext")
	}

	claims, err := ValidateEARToken(resp.IssuerEAR, deps.KeyProvider, deps.ExpectedIssuer)
	if err != nil {
		RecordTokenValidationFailure(err)
		return nil, fmt.Errorf("validate handoff issuer EAR: %w", err)
	}
	if err := checkRequiredMeasurement(claims, deps.AllowedMeasurements, "handoff"); err != nil {
		RecordTokenValidationFailure(err)
		RecordMeasurementDenied("handoff")
		return nil, fmt.Errorf("validate handoff issuer measurement: %w", err)
	}
	if err := checkOperatorPolicy(claims, deps.OperatorKeysHash, "issuer"); err != nil {
		RecordTokenValidationFailure(err)
		return nil, fmt.Errorf("validate handoff issuer operator-key policy: %w", err)
	}
	responseMessage, err := handoffResponseMessage(requesterEAR, resp.IssuerEAR, requesterPub, resp.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := verifyHandoffSignature(claims, resp.Signature, responseMessage, "issuer"); err != nil {
		return nil, err
	}

	peerPubRaw, err := decodeB64(resp.PublicKey, "handoff peer public key")
	if err != nil {
		return nil, err
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubRaw)
	if err != nil {
		return nil, fmt.Errorf("parse handoff peer public key: %w", err)
	}
	shared, err := requesterKey.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("derive handoff secret: %w", err)
	}
	aead, err := handoffAEAD(shared, requesterEAR, resp.IssuerEAR)
	if err != nil {
		return nil, err
	}

	nonce, err := decodeB64(resp.Nonce, "handoff nonce")
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("handoff nonce length = %d, want %d", len(nonce), aead.NonceSize())
	}
	ciphertext, err := decodeB64(resp.Ciphertext, "handoff ciphertext")
	if err != nil {
		return nil, err
	}
	aad, err := handoffAAD(requesterEAR, resp.IssuerEAR, requesterPub, resp.PublicKey)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt handoff payload: %w", err)
	}
	return ParseHandoffPayload(plain)
}

// ParseHandoffPayload decodes a decrypted handoff payload into typed material
// and validates the CA cert/key pair.
func ParseHandoffPayload(plain []byte) (*HandoffMaterial, error) {
	var payload handoffPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("parse handoff payload: %w", err)
	}
	if payload.CAKey == "" || payload.CACertificate == "" || payload.CABundle == "" {
		return nil, fmt.Errorf("handoff payload missing CA fields")
	}
	if err := validateAllowlistSnapshot(payload.AllowlistVersion, payload.Allowlist); err != nil {
		return nil, err
	}

	caKey, err := certutil.ParseECPrivateKey([]byte(payload.CAKey))
	if err != nil {
		return nil, fmt.Errorf("parse handoff CA key: %w", err)
	}
	caCert, err := certutil.ParseCertificatePEM([]byte(payload.CACertificate))
	if err != nil {
		return nil, fmt.Errorf("parse handoff CA certificate: %w", err)
	}
	if err := ValidateCAKeyPair(caCert, caKey); err != nil {
		return nil, err
	}

	certs, err := certutil.ParsePEMCertificates([]byte(payload.CABundle))
	if err != nil {
		return nil, fmt.Errorf("parse handoff CA bundle: %w", err)
	}
	var parentCert *x509.Certificate
	if payload.ParentCertificate != "" {
		parentCert, err = certutil.ParseCertificatePEM([]byte(payload.ParentCertificate))
		if err != nil {
			return nil, fmt.Errorf("parse handoff parent certificate: %w", err)
		}
	}

	return &HandoffMaterial{
		CAKey:            caKey,
		CACert:           caCert,
		ParentCert:       parentCert,
		Bundle:           certs,
		AllowlistVersion: payload.AllowlistVersion,
		Allowlist:        payload.Allowlist,
	}, nil
}

func validateAllowlistSnapshot(version string, digests map[types.Digest]string) error {
	parsedVersion, err := strconv.ParseUint(version, 10, 64)
	if err != nil || parsedVersion == 0 {
		return fmt.Errorf("invalid handoff allowlist version %q", version)
	}
	if digests == nil {
		return fmt.Errorf("handoff allowlist digests are required")
	}
	return nil
}

// ValidateCAKeyPair confirms a parsed CA certificate is currently usable for
// signing and that key matches the cert's public key.
func ValidateCAKeyPair(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	if cert == nil {
		return fmt.Errorf("handoff CA certificate is required")
	}
	if key == nil {
		return fmt.Errorf("handoff CA key is required")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return fmt.Errorf("handoff CA certificate is not a CA")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("handoff CA certificate cannot sign certificates")
	}
	now := time.Now()
	if cert.NotBefore.After(now) || !cert.NotAfter.After(now) {
		return fmt.Errorf("handoff CA certificate is not currently valid")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("handoff CA certificate has non-ECDSA public key: %T", cert.PublicKey)
	}
	if !key.PublicKey.Equal(pub) {
		return fmt.Errorf("handoff CA key does not match certificate")
	}
	return nil
}

func checkRequiredMeasurement(claims *EARClaims, allowed map[string]bool, endpoint string) error {
	if len(allowed) == 0 {
		return &TokenValidationError{
			Reason: ReasonMeasurementDenied,
			Err:    fmt.Errorf("measurement allowlist required for %s", endpoint),
		}
	}
	return CheckMeasurement(claims, allowed, endpoint)
}

func checkOperatorPolicy(claims *EARClaims, expected, label string) error {
	if claims == nil || claims.OperatorKeysHash == "" {
		return &TokenValidationError{
			Reason: ReasonOperatorPolicy,
			Err:    fmt.Errorf("%s EAR is missing %s claim", label, earclaims.OperatorKeysHash),
		}
	}
	if err := operatorauth.ValidateKeySetHash(claims.OperatorKeysHash); err != nil {
		return &TokenValidationError{
			Reason: ReasonOperatorPolicy,
			Err:    fmt.Errorf("%s EAR has invalid %s claim: %w", label, earclaims.OperatorKeysHash, err),
		}
	}
	if claims.OperatorKeysHash != expected {
		return &TokenValidationError{
			Reason: ReasonOperatorPolicy,
			Err:    fmt.Errorf("%s EAR operator-key policy %s does not match expected %s", label, claims.OperatorKeysHash, expected),
		}
	}
	return nil
}

func signHandoffMessage(key *ecdsa.PrivateKey, message []byte) (string, error) {
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign handoff key proof: %w", err)
	}
	return encodeB64(sig), nil
}

func verifyHandoffSignature(claims *EARClaims, signature string, message []byte, label string) error {
	if claims.TEEPubKey == "" {
		return fmt.Errorf("%s EAR is missing %s claim", label, earclaims.TEEPublicKey)
	}
	pubDER, err := decodeB64(claims.TEEPubKey, label+" "+earclaims.TEEPublicKey)
	if err != nil {
		return err
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return fmt.Errorf("parse %s %s: %w", label, earclaims.TEEPublicKey, err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%s %s is not ECDSA: %T", label, earclaims.TEEPublicKey, pubAny)
	}
	sig, err := decodeB64(signature, label+" handoff signature")
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("%s handoff signature verification failed", label)
	}
	return nil
}

func handoffRequestMessage(ear, requesterPub string) ([]byte, error) {
	return handoffTranscript(handoffRequestSignaturePurpose, ear, requesterPub)
}

func handoffResponseMessage(requesterEAR, issuerEAR, requesterPub, issuerPub string) ([]byte, error) {
	return handoffTranscript(handoffResponseSignaturePurpose, requesterEAR, issuerEAR, requesterPub, issuerPub)
}

func handoffAEAD(shared []byte, requesterEAR, issuerEAR string) (cipher.AEAD, error) {
	info, err := handoffTranscript(handoffPayloadKeyPurpose, requesterEAR, issuerEAR)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("derive handoff key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create handoff cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create handoff aead: %w", err)
	}
	return aead, nil
}

func handoffAAD(requesterEAR, issuerEAR, requesterPub, issuerPub string) ([]byte, error) {
	return handoffTranscript(handoffPayloadAADPurpose, requesterEAR, issuerEAR, requesterPub, issuerPub)
}

// handoffTranscript TLS-style length-prefixes every signed, KDF, and
// AEAD-authenticated transcript component. The first two components are the
// protocol label and purpose-specific domain separator.
func handoffTranscript(purpose string, fields ...string) ([]byte, error) {
	components := make([]string, 0, 2+len(fields))
	components = append(components, handoffProtocolLabel, purpose)
	components = append(components, fields...)

	var builder cryptobyte.Builder
	for _, component := range components {
		component := []byte(component)
		builder.AddUint32LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddBytes(component)
		})
	}
	out, err := builder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("build handoff transcript: %w", err)
	}
	return out, nil
}

func encodeB64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeB64(s, label string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return data, nil
}
