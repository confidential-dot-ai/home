package attestation

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/lunal-dev/c8s/internal/certissuerclient"
	"github.com/lunal-dev/c8s/internal/ear"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/types"
)

// Handler holds the dependencies for attestation HTTP handlers.
type Handler struct {
	Challenges        *ChallengeStore
	AttestationClient attestationclient.Client
	CertIssuer        certissuerclient.Client
	CertTTL           string
	EarIssuer         ear.Issuer
}

// HandleAuthenticate handles POST /authenticate - returns a base64 challenge nonce.
func (h Handler) HandleAuthenticate(w http.ResponseWriter, r *http.Request) {
	challenge := h.Challenges.Create()
	encoded := base64.StdEncoding.EncodeToString(challenge[:])

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: encoded})
}

// HandleAttest handles POST /attest - verifies evidence and returns a signed
// certificate chain.
func (h Handler) HandleAttest(w http.ResponseWriter, r *http.Request) {
	var req types.AttestRequestBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
		return
	}

	// Decode and consume the challenge (single use)
	challengeBytes, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_challenge", "invalid or expired challenge")
		return
	}

	if !h.Challenges.Consume(challengeBytes) {
		writeError(w, http.StatusBadRequest, "invalid_challenge", "invalid or expired challenge")
		return
	}

	csr, err := parseAndVerifyCSR(req.CSR)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_csr", err.Error())
		return
	}
	csrPubKey, err := ecdsaPublicKeyFromCSR(csr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_csr", err.Error())
		return
	}
	expectedReportData, err := ratls.ReportDataForKey(csrPubKey, challengeBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_csr", err.Error())
		return
	}

	// Serialise evidence for embedding in the EAR token
	evidenceJSON, err := json.Marshal(req.Evidence)
	if err != nil {
		evidenceJSON = []byte("null")
	}

	// Verify the evidence with the attestation service
	reportData := types.NewBase64Bytes(expectedReportData[:sha512.Size384])
	verifyReq := types.VerifyRequest{
		Evidence: req.Evidence,
		Params: &types.VerifyParams{
			ExpectedReportData: &reportData,
		},
		IssueToken: new(bool),
	}

	verifyResp, err := h.AttestationClient.Verify(r.Context(), verifyReq)
	if err != nil {
		h.handleAttestationError(w, err)
		return
	}

	if !verifyResp.Result.SignatureValid {
		slog.Warn("attestation signature invalid")
		writeError(w, http.StatusUnauthorized, "verification_failed", "attestation signature invalid")
		return
	}

	if verifyResp.Result.ReportDataMatch == nil || !*verifyResp.Result.ReportDataMatch {
		slog.Warn("challenge did not match attestation evidence",
			"report_data_match", verifyResp.Result.ReportDataMatch)
		writeError(w, http.StatusUnauthorized, "verification_failed", "challenge mismatch in attestation evidence")
		return
	}

	// Issue an EAR token for the cert-issuer
	earToken, err := h.EarIssuer.IssueWithLaunchDigestAndPubKey(json.RawMessage(evidenceJSON), verifyResp.Result.Claims.LaunchDigest, csrPubKey)
	if err != nil {
		slog.Error("failed to issue EAR token", "error", err)
		writeError(w, http.StatusInternalServerError, "ear_issuance_failed",
			fmt.Sprintf("failed to issue EAR token: %s", err))
		return
	}

	// Forward the caller's CSR to the cert-issuer with the EAR token. The
	// response is a PEM chain: issued leaf followed by the CA bundle.
	// Authenticity of this response on the network path is provided by the
	// RA-TLS handshake the workload performed against this Assam — without
	// that handshake, an on-path attacker could swap the bundle for an
	// attacker-controlled CA.
	certPEM, err := h.CertIssuer.SignCSR(r.Context(), earToken, req.CSR, h.CertTTL)
	if err != nil {
		h.handleCertIssuerError(w, err)
		return
	}

	slog.Info("certificate issued successfully")

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write([]byte(certPEM))
}

// HandleAttestKey handles POST /attest-key. The flow mirrors HandleAttest
// but issues just an EAR (no certificate) and takes a raw ECDSA pubkey
// instead of a CSR — used by in-cluster c8s components that need a
// TEE-attested EAR for a key they generate in-process (today: cert-issuer's
// handoff signer key).
func (h Handler) HandleAttestKey(w http.ResponseWriter, r *http.Request) {
	var req types.AttestKeyRequestBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
		return
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_challenge", "invalid or expired challenge")
		return
	}
	if !h.Challenges.Consume(challengeBytes) {
		writeError(w, http.StatusBadRequest, "invalid_challenge", "invalid or expired challenge")
		return
	}

	pubDER, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_public_key", err.Error())
		return
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_public_key", err.Error())
		return
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_public_key", "public_key must be ECDSA")
		return
	}

	expectedReportData, err := ratls.ReportDataForKey(pub, challengeBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_public_key", err.Error())
		return
	}

	evidenceJSON, err := json.Marshal(req.Evidence)
	if err != nil {
		evidenceJSON = []byte("null")
	}

	reportData := types.NewBase64Bytes(expectedReportData[:sha512.Size384])
	verifyReq := types.VerifyRequest{
		Evidence: req.Evidence,
		Params: &types.VerifyParams{
			ExpectedReportData: &reportData,
		},
		IssueToken: new(bool),
	}
	verifyResp, err := h.AttestationClient.Verify(r.Context(), verifyReq)
	if err != nil {
		h.handleAttestationError(w, err)
		return
	}
	if !verifyResp.Result.SignatureValid {
		slog.Warn("attest-key: attestation signature invalid")
		writeError(w, http.StatusUnauthorized, "verification_failed", "attestation signature invalid")
		return
	}
	if verifyResp.Result.ReportDataMatch == nil || !*verifyResp.Result.ReportDataMatch {
		slog.Warn("attest-key: challenge did not match attestation evidence",
			"report_data_match", verifyResp.Result.ReportDataMatch)
		writeError(w, http.StatusUnauthorized, "verification_failed", "challenge mismatch in attestation evidence")
		return
	}

	earToken, err := h.EarIssuer.IssueWithLaunchDigestAndPubKey(json.RawMessage(evidenceJSON), verifyResp.Result.Claims.LaunchDigest, pub)
	if err != nil {
		slog.Error("attest-key: failed to issue EAR token", "error", err)
		writeError(w, http.StatusInternalServerError, "ear_issuance_failed",
			fmt.Sprintf("failed to issue EAR token: %s", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(types.AttestKeyResponseBody{EAR: earToken})
}

func parseAndVerifyCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("CSR must be a PEM-encoded certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	return csr, nil
}

func ecdsaPublicKeyFromCSR(csr *x509.CertificateRequest) (*ecdsa.PublicKey, error) {
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("CSR public key must be ECDSA, got %T", csr.PublicKey)
	}
	return pub, nil
}

func (h Handler) handleAttestationError(w http.ResponseWriter, err error) {
	var reqErr *attestationclient.RequestError
	var apiErr *attestationclient.APIError
	var unexpErr *attestationclient.UnexpectedError

	switch {
	case errors.As(err, &reqErr):
		slog.Warn("attestation service unreachable", "error", reqErr.Err)
		writeError(w, http.StatusBadGateway, "attestation_service_unreachable",
			fmt.Sprintf("failed to reach attestation service: %s", reqErr.Err))

	case errors.As(err, &apiErr):
		slog.Warn("attestation service returned error",
			"status", apiErr.Status, "error", apiErr.Response.Message)
		writeError(w, http.StatusBadGateway, "attestation_service_error",
			fmt.Sprintf("attestation service returned %d: %s", apiErr.Status, apiErr.Response.Message))

	case errors.As(err, &unexpErr):
		slog.Warn("unexpected response from attestation service",
			"status", unexpErr.Status, "body", unexpErr.Text)
		writeError(w, http.StatusBadGateway, "attestation_service_error",
			fmt.Sprintf("attestation service returned %d: %s", unexpErr.Status, unexpErr.Text))

	default:
		slog.Warn("attestation service unreachable", "error", err)
		writeError(w, http.StatusBadGateway, "attestation_service_unreachable",
			fmt.Sprintf("failed to reach attestation service: %s", err))
	}
}

func (h Handler) handleCertIssuerError(w http.ResponseWriter, err error) {
	var apiErr *certissuerclient.APIError
	if errors.As(err, &apiErr) {
		slog.Warn("cert-issuer returned error",
			"status", apiErr.Status, "body", apiErr.Body)
		writeError(w, http.StatusBadGateway, "cert_issuer_error",
			fmt.Sprintf("cert-issuer returned %d: %s", apiErr.Status, apiErr.Body))
		return
	}

	slog.Warn("cert-issuer unreachable", "error", err)
	writeError(w, http.StatusBadGateway, "cert_issuer_unreachable",
		fmt.Sprintf("failed to reach cert-issuer: %s", err))
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(types.ErrorResponse{
		Error:   code,
		Message: message,
	})
}

// ReadinessFunc is a function that returns whether the service is ready.
type ReadinessFunc func() bool

// HandleReadyz handles GET /readyz.
func HandleReadyz(readyFn ReadinessFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if readyFn() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}
}
