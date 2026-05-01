package attestation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/lunal-dev/c8s/internal/certissuerclient"
	"github.com/lunal-dev/c8s/internal/ear"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
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

// HandleAttest handles POST /attest - verifies evidence and returns a signed certificate.
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

	// Serialise evidence for embedding in the EAR token
	evidenceJSON, err := json.Marshal(req.Evidence)
	if err != nil {
		evidenceJSON = []byte("null")
	}

	// Verify the evidence with the attestation service
	reportData := types.NewBase64Bytes(challengeBytes)
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
	earToken, err := h.EarIssuer.Issue(json.RawMessage(evidenceJSON))
	if err != nil {
		slog.Error("failed to issue EAR token", "error", err)
		writeError(w, http.StatusInternalServerError, "ear_issuance_failed",
			fmt.Sprintf("failed to issue EAR token: %s", err))
		return
	}

	// Forward the caller's CSR to the cert-issuer with the EAR token
	certPEM, err := h.CertIssuer.SignCSR(r.Context(), earToken, req.CSR, h.CertTTL)
	if err != nil {
		h.handleCertIssuerError(w, err)
		return
	}

	slog.Info("certificate issued successfully")

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write([]byte(certPEM))
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
