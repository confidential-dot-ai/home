package cds

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lunal-dev/c8s/internal/attestation"
	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/types"
)

// AttestHandler serves POST /attest by verifying TEE evidence and signing
// the requester's CSR in-process — no EAR JWT round-trip, since cds is both
// the former assam and former cert-issuer in one binary.
//
// THREAT MODEL: the measurement check is the only thing standing between an
// attacker who controls a TEE workload and a CA-signed leaf for any subject
// they choose. Empty Measurements skips this check (UNSAFE outside dev).
type AttestHandler struct {
	Challenges        *attestation.ChallengeStore
	AttestationClient attestationclient.Client
	CA                *issuer.CA
	CAChainPEM        []byte
	CertTTL           time.Duration

	// RequestTimeout caps how long /attest may spend on attestation
	// verification + signing. Zero = no timeout.
	RequestTimeout time.Duration

	// Measurements is the flat allowlist of SHA-384 launch digests permitted
	// to obtain a signed leaf. Empty = no measurement pinning.
	Measurements map[string]bool

	// Policy enforces SAN/CN constraints on the CSR before signing. Without
	// this, an attestation-passing workload could mint a leaf for any
	// subject — see THREAT MODEL on issuer.CA.SignCSR.
	Policy issuer.CSRPolicy

	// SANValidation, when true, binds Policy.SourceIP to the request's
	// RemoteAddr at handler time. When false, Policy.SourceIP stays empty and
	// ValidateCSR rejects any CSR carrying IP SANs.
	SANValidation bool
}

func (h AttestHandler) HandleAttest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.RequestTimeout)
		defer cancel()
	}

	var req types.AttestRequestBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
		return
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge, "invalid or expired challenge")
		return
	}
	if !h.Challenges.Consume(challengeBytes) {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge, "invalid or expired challenge")
		return
	}

	csr, err := attestation.ParseAndVerifyCSR(req.CSR)
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
		return
	}
	csrPubKey, err := attestation.ECDSAPublicKeyFromCSR(csr)
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
		return
	}
	expectedReportData, err := ratls.ReportDataForKey(csrPubKey, challengeBytes)
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
		return
	}

	evidenceJSON, err := json.Marshal(req.Evidence)
	if err != nil {
		attestation.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest,
			fmt.Sprintf("invalid evidence: %s", err))
		return
	}

	reportData := types.NewBase64Bytes(expectedReportData[:sha512.Size384])
	verifyReq := types.VerifyRequest{
		Evidence: req.Evidence,
		Params: &types.VerifyParams{
			ExpectedReportData: &reportData,
		},
		IssueToken: new(bool),
	}
	verifyResp, err := h.AttestationClient.Verify(ctx, verifyReq)
	if err != nil {
		slog.Warn("attestation service error", "error", err)
		attestation.WriteError(w, http.StatusBadGateway, types.ErrorCodeAttestationServiceUnreachable,
			fmt.Sprintf("failed to reach attestation service: %s", err))
		return
	}
	if !verifyResp.Result.SignatureValid {
		slog.Warn("attestation signature invalid")
		attestation.WriteError(w, http.StatusUnauthorized, types.ErrorCodeVerificationFailed, "attestation signature invalid")
		return
	}
	if verifyResp.Result.ReportDataMatch == nil || !*verifyResp.Result.ReportDataMatch {
		slog.Warn("challenge did not match attestation evidence")
		attestation.WriteError(w, http.StatusUnauthorized, types.ErrorCodeVerificationFailed, "challenge mismatch in attestation evidence")
		return
	}

	if len(h.Measurements) > 0 {
		digest := strings.ToLower(verifyResp.Result.Claims.LaunchDigest)
		if !h.Measurements[digest] {
			slog.Warn("measurement not in allowlist", "launch_digest", digest)
			attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeMeasurementDenied, "launch measurement not allowed")
			return
		}
	}

	policy := h.Policy
	if h.SANValidation {
		policy.SourceIP = issuer.SourceIPFromRemoteAddr(r.RemoteAddr)
	}
	if err := issuer.ValidateCSR(csr, policy); err != nil {
		slog.Warn("CSR validation failed", "error", err, "remote_addr", r.RemoteAddr)
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, err.Error())
		return
	}

	if ctx.Err() != nil {
		attestation.WriteError(w, http.StatusGatewayTimeout, types.ErrorCodeTimeout, "request timeout")
		return
	}

	certPEM, _, err := h.CA.SignCSR(issuer.SignCSRParams{
		CSR:      csr,
		TTL:      issuer.CapTTL(h.CertTTL, issuer.MaxLeafTTL),
		Evidence: evidenceJSON,
	})
	if err != nil {
		slog.Error("in-process sign failed", "error", err)
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeSignFailed, err.Error())
		return
	}
	caChainPEM := h.caChainPEM()
	if len(caChainPEM) == 0 {
		slog.Error("in-process sign failed: CA chain unavailable")
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeSignFailed, "CA chain unavailable")
		return
	}

	slog.Info("certificate issued (in-process)", "cn", csr.Subject.CommonName)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(slices.Concat(certPEM, caChainPEM))
}

func (h AttestHandler) caChainPEM() []byte {
	if len(h.CAChainPEM) > 0 {
		return h.CAChainPEM
	}
	if h.CA == nil || h.CA.Cert == nil {
		return nil
	}
	return certutil.EncodeCertPEM(h.CA.Cert.Raw)
}
