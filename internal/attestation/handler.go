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

	"github.com/lunal-dev/c8s/internal/ear"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/types"
)

// Handler holds the dependencies for attestation HTTP handlers.
type Handler struct {
	Challenges        *ChallengeStore
	AttestationClient attestationclient.Client
	EarIssuer         ear.Issuer
}

// HandleAuthenticate returns a handler that issues a single-use base64
// challenge nonce.
func HandleAuthenticate(challenges *ChallengeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		challenge := challenges.Create()
		encoded := base64.StdEncoding.EncodeToString(challenge[:])
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: encoded})
	}
}

// HandleAttestKey handles POST /attest-key: it issues an EAR (no certificate)
// for a caller-generated ECDSA pubkey — used by in-cluster c8s components that
// need a TEE-attested EAR for a key they generate in-process (CDS's handoff
// signer key).
func (h Handler) HandleAttestKey(w http.ResponseWriter, r *http.Request) {
	var req types.AttestKeyRequestBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		WriteError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
		return
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_challenge", "invalid or expired challenge")
		return
	}
	if !h.Challenges.Consume(challengeBytes) {
		WriteError(w, http.StatusBadRequest, "invalid_challenge", "invalid or expired challenge")
		return
	}

	pubDER, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_public_key", err.Error())
		return
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_public_key", err.Error())
		return
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		WriteError(w, http.StatusBadRequest, "invalid_public_key", "public_key must be ECDSA")
		return
	}

	expectedReportData, err := ratls.ReportDataForKey(pub, challengeBytes)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_public_key", err.Error())
		return
	}

	evidenceJSON, err := json.Marshal(req.Evidence)
	if err != nil {
		evidenceJSON = []byte("null")
	}

	reportData := types.NewBase64Bytes(expectedReportData[:sha512.Size384])
	verifyReq := types.VerifyReportData(req.Evidence, reportData)
	verifyResp, err := h.AttestationClient.Verify(r.Context(), verifyReq)
	if err != nil {
		h.handleAttestationError(w, err)
		return
	}
	if !verifyResp.Result.SignatureValid {
		slog.Warn("attest-key: attestation signature invalid")
		WriteError(w, http.StatusUnauthorized, "verification_failed", "attestation signature invalid")
		return
	}
	if verifyResp.Result.ReportDataMatch == nil || !*verifyResp.Result.ReportDataMatch {
		slog.Warn("attest-key: challenge did not match attestation evidence",
			"report_data_match", verifyResp.Result.ReportDataMatch)
		WriteError(w, http.StatusUnauthorized, "verification_failed", "challenge mismatch in attestation evidence")
		return
	}

	earToken, err := h.EarIssuer.IssueWithLaunchDigestAndPubKey(json.RawMessage(evidenceJSON), verifyResp.Result.Claims.LaunchDigest, pub)
	if err != nil {
		slog.Error("attest-key: failed to issue EAR token", "error", err)
		WriteError(w, http.StatusInternalServerError, "ear_issuance_failed",
			fmt.Sprintf("failed to issue EAR token: %s", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(types.AttestKeyResponseBody{EAR: earToken})
}

// ParseAndVerifyCSR decodes a PEM CSR and verifies its self-signature.
func ParseAndVerifyCSR(csrPEM string) (*x509.CertificateRequest, error) {
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

// ECDSAPublicKeyFromCSR returns the CSR's ECDSA public key or an error if
// the key is not ECDSA.
func ECDSAPublicKeyFromCSR(csr *x509.CertificateRequest) (*ecdsa.PublicKey, error) {
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
		WriteError(w, http.StatusBadGateway, "attestation_service_unreachable",
			fmt.Sprintf("failed to reach attestation service: %s", reqErr.Err))

	case errors.As(err, &apiErr):
		slog.Warn("attestation service returned error",
			"status", apiErr.Status, "error", apiErr.Response.Message)
		WriteError(w, http.StatusBadGateway, "attestation_service_error",
			fmt.Sprintf("attestation service returned %d: %s", apiErr.Status, apiErr.Response.Message))

	case errors.As(err, &unexpErr):
		slog.Warn("unexpected response from attestation service",
			"status", unexpErr.Status, "body", unexpErr.Text)
		WriteError(w, http.StatusBadGateway, "attestation_service_error",
			fmt.Sprintf("attestation service returned %d: %s", unexpErr.Status, unexpErr.Text))

	default:
		slog.Warn("attestation service unreachable", "error", err)
		WriteError(w, http.StatusBadGateway, "attestation_service_unreachable",
			fmt.Sprintf("failed to reach attestation service: %s", err))
	}
}

// WriteError writes a JSON error response in the c8s error-envelope shape.
func WriteError(w http.ResponseWriter, status int, code, message string) {
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
