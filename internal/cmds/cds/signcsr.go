package cds

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lunal-dev/c8s/internal/attestation"
	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/pkg/issuerapi"
	"github.com/lunal-dev/c8s/pkg/types"
)

// SignCSRHandler serves POST /sign-csr for external callers that hold an
// EAR JWT. See the THREAT MODEL on issuer.(*CA).SignCSR for the full
// caller-responsibility contract this handler enforces.
type SignCSRHandler struct {
	CA          *issuer.CA
	CAChainPEM  []byte
	MaxTTL      time.Duration
	KeyProvider issuer.KeyProvider

	// ExpectedIssuer, when non-empty, requires the EAR JWT issuer claim to
	// equal this value.
	ExpectedIssuer string

	// RequestTimeout caps how long /sign-csr may spend on validation +
	// signing. Zero disables.
	RequestTimeout time.Duration

	// Measurements is the flat allowlist of SHA-384 launch digests permitted
	// to obtain a signed leaf. Empty disables pinning.
	Measurements map[string]bool

	// Policy enforces SAN/CN constraints on the CSR before signing.
	Policy issuer.CSRPolicy

	// SANValidation, when true, binds Policy.SourceIP to the request's
	// RemoteAddr at handler time.
	SANValidation bool
}

func (h SignCSRHandler) HandleSignCSR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.RequestTimeout)
		defer cancel()
	}

	var req issuerapi.SignCSRRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		msg := "invalid request"
		if strings.Contains(err.Error(), "issuerapi: duration") {
			msg = "invalid TTL"
		} else if strings.Contains(err.Error(), "issuerapi: no valid PEM") {
			msg = "invalid CSR"
		}
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, msg)
		return
	}
	if req.EAR == "" {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "missing 'ear' field")
		return
	}
	if req.CSR.DER() == nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "missing 'csr' field")
		return
	}

	claims, err := issuer.ValidateEARToken(req.EAR, h.KeyProvider, h.ExpectedIssuer)
	if err != nil {
		var tve *issuer.TokenValidationError
		if errors.As(err, &tve) {
			slog.Warn("EAR token rejected", "reason", tve.Reason, "error", err)
		} else {
			slog.Warn("EAR token rejected", "error", err)
		}
		attestation.WriteError(w, http.StatusUnauthorized, types.ErrorCodeInvalidToken, "invalid attestation token")
		return
	}

	if err := issuer.CheckMeasurement(claims, h.Measurements, "sign-csr"); err != nil {
		slog.Warn("measurement check failed", "error", err)
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeMeasurementDenied, "launch measurement not allowed")
		return
	}

	csr, err := x509.ParseCertificateRequest(req.CSR.DER())
	if err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, "invalid CSR")
		return
	}
	if err := csr.CheckSignature(); err != nil {
		attestation.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, "CSR signature invalid")
		return
	}
	if err := issuer.VerifyKeyBinding(csr, claims); err != nil {
		slog.Warn("key binding failed", "error", err, "remote_addr", r.RemoteAddr)
		attestation.WriteError(w, http.StatusForbidden, types.ErrorCodeKeyBinding, "CSR key does not match attested key")
		return
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
		TTL:      issuer.CapTTL(req.TTL.Duration, h.MaxTTL),
		Evidence: claims.RawEvidence,
	})
	if err != nil {
		slog.Error("sign-csr failed", "error", err)
		attestation.WriteError(w, http.StatusInternalServerError, types.ErrorCodeSignFailed, "signing failed")
		return
	}

	resp := issuerapi.SignCSRResponse{
		Certificate:   issuerapi.MustPEMData(certPEM),
		CACertificate: issuerapi.MustPEMData(h.CAChainPEM),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("encode sign-csr response failed", "error", err)
	}
}
