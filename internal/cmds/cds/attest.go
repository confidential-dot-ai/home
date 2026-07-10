package cds

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// AttestHandler serves POST /attest by verifying TEE evidence and signing the
// requester's CSR in-process — attestation and mesh-CA signing live in the same
// binary, so there is no EAR JWT round-trip to a separate signer.
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
	verifyReq := types.VerifyReportData(req.Evidence, reportData)
	verifyResp, err := h.AttestationClient.VerifyEnforced(ctx, verifyReq)
	if err != nil {
		status, code, msg := classifyVerifyError(err)
		slog.Warn("attestation verification failed", "status", status, "error", err)
		attestation.WriteError(w, status, code, msg)
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

	// Embed the just-verified attestation as OID .1.1 in the issued leaf so a
	// downstream ratls-mode verifier (e.g. secret-broker --peer-verify=ratls)
	// sees the same evidence CDS accepted. RATLSEvidence extracts the
	// platform-appropriate payload: raw SNP report for bare-metal SNP, or the
	// full evidence envelope for TDX / other platforms (see pkg/ratls docs on
	// the on-cert format). Failure here does not deny issuance — the mesh cert
	// remains valid for CA-chain-verified peers; only ratls-mode verification
	// on downstream services degrades.
	var ratlsAtt *ratls.Attestation
	if att, err := buildAttestationExtension(req.Evidence); err == nil {
		ratlsAtt = att
	} else {
		slog.Warn("skipping .1.1 attestation embed", "error", err)
	}

	certPEM, _, err := h.CA.SignCSR(issuer.SignCSRParams{
		CSR:         csr,
		TTL:         issuer.CapTTL(h.CertTTL, issuer.MaxLeafTTL),
		Evidence:    evidenceJSON,
		Attestation: ratlsAtt,
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

// classifyVerifyError maps a VerifyEnforced error to (HTTP status, error code,
// message). A rejected verdict — bad signature, REPORTDATA mismatch, or a 4xx
// the attestation-api returns for malformed/unacceptable evidence — is the
// caller's fault and must not be reported as attestation_api_unreachable.
// Only a transport failure or a 5xx/garbage upstream response is a real outage.
func classifyVerifyError(err error) (int, string, string) {
	switch {
	case errors.Is(err, attestationclient.ErrSignatureInvalid):
		return http.StatusUnauthorized, types.ErrorCodeVerificationFailed, "attestation signature invalid"
	case errors.Is(err, attestationclient.ErrReportDataMismatch):
		return http.StatusUnauthorized, types.ErrorCodeVerificationFailed, "challenge mismatch in attestation evidence"
	}
	var apiErr *attestationclient.APIError
	if errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 {
		return http.StatusUnprocessableEntity, types.ErrorCodeVerificationFailed, "attestation evidence rejected by attestation-api"
	}
	return http.StatusBadGateway, types.ErrorCodeAttestationApiUnreachable,
		fmt.Sprintf("failed to reach attestation-api: %s", err)
}

// buildAttestationExtension packages the request's already-verified evidence
// into the ratls.Attestation the leaf's OID .1.1 extension wants. The
// platform-appropriate on-cert form is delegated to
// attestclient.RATLSEvidence — bare-metal SNP carries the raw SNP report bytes;
// TDX and other platforms carry the JSON evidence envelope stripped to the
// fields the /verify endpoint needs.
func buildAttestationExtension(evidence types.AttestationEvidence) (*ratls.Attestation, error) {
	var teeType ratls.TEEType
	switch evidence.Platform {
	case string(types.PlatformSnp), string(types.PlatformAzSnp), string(types.PlatformGcpSnp):
		teeType = ratls.TEETypeSEVSNP
	case string(types.PlatformTdx):
		teeType = ratls.TEETypeTDX
	default:
		return nil, fmt.Errorf("unsupported platform %q", evidence.Platform)
	}
	report, err := attestclient.RATLSEvidence(types.AttestResponse(evidence))
	if err != nil {
		return nil, fmt.Errorf("extract RA-TLS evidence: %w", err)
	}
	return &ratls.Attestation{TEEType: teeType, Report: []byte(report)}, nil
}
