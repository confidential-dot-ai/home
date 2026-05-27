package certissuer

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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/issuerapi"
	"github.com/lunal-dev/c8s/pkg/resources"
	"golang.org/x/crypto/cryptobyte"
)

const (
	handoffProtocolLabel            = "c8s-cert-issuer-handoff-v1"
	handoffRequestSignaturePurpose  = "request-signature"
	handoffResponseSignaturePurpose = "response-signature"
	handoffPayloadKeyPurpose        = "payload-key"
	handoffPayloadAADPurpose        = "payload-aad"
)

type HandoffRequest = issuerapi.HandoffRequest
type HandoffResponse = issuerapi.HandoffResponse

// handoffHandler wraps the active in-memory CA to attested cert-issuer replicas.
type handoffHandler struct {
	issuer          *Issuer
	bundle          *bundleManager
	issuerEARSource handoffEARSource
	signer          *ecdsa.PrivateKey
}

// newHandoffHandler constructs a handoffHandler from an in-memory signer key
// and an EAR source. The signer is bootstrapped via Assam's /attest-key
// (see handoff_bootstrap.go); the alternative — loading a key from a Secret
// or a file path — would put CA-adjacent material into Kubernetes Secrets,
// which the chart-managed CVM design forbids.
//
// The constructor does NOT require src.Current() to succeed: the bootstrap
// runs asynchronously, and HandleHandoff returns 503 until the first
// /attest-key call has completed. This keeps cert-issuer's startup
// independent of Assam's reachability — a transient outage at the wrong
// moment doesn't crash-loop the cert-issuer pod.
func newHandoffHandler(iss *Issuer, bm *bundleManager, signer *ecdsa.PrivateKey, src handoffEARSource) (*handoffHandler, error) {
	if signer == nil {
		return nil, fmt.Errorf("handoff signer key is required to enable /handoff")
	}
	if src == nil {
		return nil, fmt.Errorf("handoff EAR source is required when handoff signer key is set")
	}
	if len(iss.HandoffMeasurements) == 0 {
		return nil, fmt.Errorf("/handoff requires a %s measurement allowlist in --resource-map", resources.CertIssuerHandoff)
	}
	return &handoffHandler{
		issuer:          iss,
		bundle:          bm,
		issuerEARSource: src,
		signer:          signer,
	}, nil
}

type handoffEARSource interface {
	Current() (string, error)
}

type staticHandoffEARSource struct {
	ear string
}

func (s staticHandoffEARSource) Current() (string, error) {
	return strings.TrimSpace(s.ear), nil
}

// handoffEARExpiry returns the EAR token's exp claim. The token is decoded
// without signature verification — this is for operator-facing observability
// of the locally provisioned EAR. Handoff peers re-validate signature, issuer,
// and expiry via validateEARToken before trusting any material.
func handoffEARExpiry(token string) (time.Time, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("decode JWT claims: %w", err)
	}
	var c issuer.EARClaims
	if err := json.Unmarshal(claimsBytes, &c); err != nil {
		return time.Time{}, fmt.Errorf("parse JWT claims: %w", err)
	}
	if c.Expiry == 0 {
		return time.Time{}, fmt.Errorf("JWT missing exp claim")
	}
	return time.Unix(c.Expiry, 0), nil
}

// handoffEARExpiryUpdater refreshes the handoff EAR expiry gauge on a fixed
// interval. On read or parse failure it logs and sets the gauge negative so
// expiry alerts fail closed instead of preserving a stale positive value.
func handoffEARExpiryUpdater(ctx context.Context, src handoffEARSource, interval time.Duration, logger *slog.Logger) {
	update := func() {
		ear, err := src.Current()
		if err != nil {
			logger.Warn("handoff EAR refresh failed for metrics", "error", err)
			handoffEARExpirySeconds.Set(-1)
			return
		}
		exp, err := handoffEARExpiry(ear)
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

type handoffPayload struct {
	CAKey             string `json:"ca_key"`
	CACertificate     string `json:"ca_certificate"`
	CABundle          string `json:"ca_bundle"`
	ParentCertificate string `json:"parent_certificate,omitempty"`
}

type handoffMaterial struct {
	caKey      *ecdsa.PrivateKey
	caCert     *x509.Certificate
	parentCert *x509.Certificate
	bundle     []*x509.Certificate
}

// HandleHandoff validates a replica EAR and returns the CA material encrypted
// to the requester's X25519 public key. The CA key never leaves process memory
// except in this recipient-bound ciphertext.
func (hh *handoffHandler) HandleHandoff(w http.ResponseWriter, r *http.Request) {
	if hh.issuerEARSource == nil {
		http.Error(w, "handoff unavailable: issuer EAR is not configured", http.StatusServiceUnavailable)
		return
	}
	issuerEAR, err := hh.issuerEARSource.Current()
	if err != nil {
		hh.issuer.Logger.Error("handoff EAR load failed", "error", err)
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

	claims, err := issuer.ValidateEARToken(req.EAR, hh.issuer.keyProvider, hh.issuer.ExpectedIssuer)
	if err != nil {
		recordTokenValidationFailure(err)
		http.Error(w, "unauthorized: invalid requester attestation token", http.StatusUnauthorized)
		return
	}
	if err := checkRequiredMeasurement(claims, hh.issuer.HandoffMeasurements, "handoff"); err != nil {
		recordTokenValidationFailure(err)
		measurementDeniedTotal.WithLabelValues("handoff").Inc()
		http.Error(w, "forbidden: requester measurement not allowed", http.StatusForbidden)
		return
	}
	requestMessage, err := handoffRequestMessage(req.EAR, req.PublicKey)
	if err != nil {
		hh.issuer.Logger.Warn("handoff requester transcript failed", "error", err)
		http.Error(w, "bad request: invalid requester handoff transcript", http.StatusBadRequest)
		return
	}
	if err := verifyHandoffSignature(claims, req.Signature, requestMessage, "requester"); err != nil {
		hh.issuer.Logger.Warn("handoff requester key proof failed", "error", err)
		http.Error(w, "unauthorized: invalid requester key proof", http.StatusUnauthorized)
		return
	}
	if hh.signer == nil {
		http.Error(w, "handoff unavailable: issuer signing key is not configured", http.StatusServiceUnavailable)
		return
	}

	b := hh.issuer.getBundle()
	if b == nil {
		http.Error(w, "service unavailable: no certificates loaded", http.StatusServiceUnavailable)
		return
	}

	resp, err := hh.wrap(req, b, issuerEAR)
	if err != nil {
		hh.issuer.Logger.Error("handoff wrap failed", "error", err)
		http.Error(w, "internal error: handoff wrap failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		hh.issuer.Logger.Error("handoff response encode failed", "error", err)
	}
}

func (hh *handoffHandler) wrap(req HandoffRequest, b *certBundle, issuerEAR string) (HandoffResponse, error) {
	requesterPubRaw, err := decodeB64(req.PublicKey, "requester public key")
	if err != nil {
		return HandoffResponse{}, err
	}
	requesterPub, err := ecdh.X25519().NewPublicKey(requesterPubRaw)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("parse requester public key: %w", err)
	}

	keyPEM, err := certutil.MarshalECKeyPEM(b.caKey)
	if err != nil {
		return HandoffResponse{}, fmt.Errorf("marshal CA key: %w", err)
	}

	bundlePEM := certutil.EncodeCertPEM(b.caCert.Raw)
	if hh.bundle != nil {
		bundlePEM = hh.bundle.bundlePEMForCurrent(b.caCert)
	}

	payload := handoffPayload{
		CAKey:         string(keyPEM),
		CACertificate: string(certutil.EncodeCertPEM(b.caCert.Raw)),
		CABundle:      string(bundlePEM),
	}
	if b.parentCert != nil {
		payload.ParentCertificate = string(certutil.EncodeCertPEM(b.parentCert.Raw))
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

func requestHandoff(ctx context.Context, peerURL, requesterEAR string, signer *ecdsa.PrivateKey, iss *Issuer, client *http.Client) (*handoffMaterial, error) {
	if strings.TrimSpace(requesterEAR) == "" {
		return nil, fmt.Errorf("handoff requester EAR is required")
	}
	if signer == nil {
		return nil, fmt.Errorf("handoff requester signing key is required")
	}
	if len(iss.HandoffMeasurements) == 0 {
		return nil, fmt.Errorf("handoff requires %s measurement allowlist", resources.CertIssuerHandoff)
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
	signature, err := signHandoffMessage(signer, requestMessage)
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
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("handoff peer returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var hr HandoffResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return nil, fmt.Errorf("decode handoff response: %w", err)
	}
	return unwrapHandoffResponse(hr, requesterEAR, pub, priv, iss)
}

func unwrapHandoffResponse(resp HandoffResponse, requesterEAR, requesterPub string, requesterKey *ecdh.PrivateKey, iss *Issuer) (*handoffMaterial, error) {
	if resp.IssuerEAR == "" || resp.PublicKey == "" || resp.Signature == "" || resp.Nonce == "" || resp.Ciphertext == "" {
		return nil, fmt.Errorf("handoff response missing issuer_ear, public_key, signature, nonce, or ciphertext")
	}

	claims, err := issuer.ValidateEARToken(resp.IssuerEAR, iss.keyProvider, iss.ExpectedIssuer)
	if err != nil {
		recordTokenValidationFailure(err)
		return nil, fmt.Errorf("validate handoff issuer EAR: %w", err)
	}
	if err := checkRequiredMeasurement(claims, iss.HandoffMeasurements, "handoff"); err != nil {
		recordTokenValidationFailure(err)
		measurementDeniedTotal.WithLabelValues("handoff").Inc()
		return nil, fmt.Errorf("validate handoff issuer measurement: %w", err)
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
	return parseHandoffPayload(plain)
}

func parseHandoffPayload(plain []byte) (*handoffMaterial, error) {
	var payload handoffPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("parse handoff payload: %w", err)
	}
	if payload.CAKey == "" || payload.CACertificate == "" || payload.CABundle == "" {
		return nil, fmt.Errorf("handoff payload missing ca_key, ca_certificate, or ca_bundle")
	}

	caKey, err := certutil.ParseECPrivateKey([]byte(payload.CAKey))
	if err != nil {
		return nil, fmt.Errorf("parse handoff CA key: %w", err)
	}
	caCert, err := certutil.ParseCertificatePEM([]byte(payload.CACertificate))
	if err != nil {
		return nil, fmt.Errorf("parse handoff CA certificate: %w", err)
	}
	if err := validateCAKeyPair(caCert, caKey); err != nil {
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

	return &handoffMaterial{
		caKey:      caKey,
		caCert:     caCert,
		parentCert: parentCert,
		bundle:     certs,
	}, nil
}

func validateCAKeyPair(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
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

func checkRequiredMeasurement(claims *issuer.EARClaims, allowed map[string]bool, endpoint string) error {
	if len(allowed) == 0 {
		return &issuer.TokenValidationError{
			Reason: "measurement_denied",
			Err:    fmt.Errorf("measurement allowlist required for %s", endpoint),
		}
	}
	return issuer.CheckMeasurement(claims, allowed, endpoint)
}

func signHandoffMessage(key *ecdsa.PrivateKey, message []byte) (string, error) {
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign handoff key proof: %w", err)
	}
	return encodeB64(sig), nil
}

func verifyHandoffSignature(claims *issuer.EARClaims, signature string, message []byte, label string) error {
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

// handoffRequestMessage is signed by the requester to prove possession of the
// private key matching its EAR's tee_public_key. It deliberately omits issuer
// identity: the requester only consents to "I am EAR X with pubkey P", and
// any active replica can independently verify that consent. Replay across
// replicas is harmless because each response (signed by the active replica
// over both EARs and both pubkeys) is recipient-bound through ECDH.
func handoffRequestMessage(ear, requesterPub string) ([]byte, error) {
	return handoffTranscript(handoffRequestSignaturePurpose, ear, requesterPub)
}

// handoffResponseMessage is signed by the active replica and binds both EARs
// and both ephemeral X25519 pubkeys, so the requester can pin which replica
// served it before decrypting the wrapped CA payload.
func handoffResponseMessage(requesterEAR, issuerEAR, requesterPub, issuerPub string) ([]byte, error) {
	return handoffTranscript(handoffResponseSignaturePurpose, requesterEAR, issuerEAR, requesterPub, issuerPub)
}

func handoffAEAD(shared []byte, requesterEAR, issuerEAR string) (cipher.AEAD, error) {
	info, err := handoffTranscript(handoffPayloadKeyPurpose, requesterEAR, issuerEAR)
	if err != nil {
		return nil, err
	}
	// Empty salt is fine: the X25519 ECDH output is a uniformly random 32-byte
	// secret per handshake, so HKDF-Extract with a zero salt still produces an
	// independent PRK. Both EARs and the handoff protocol purpose are bound
	// through the info parameter.
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
