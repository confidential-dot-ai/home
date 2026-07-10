package attestationclient

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Sentinel errors for the enforced verification paths, matchable via
// [errors.Is]. Transport and API failures keep their existing typed errors
// ([RequestError], [APIError], [UnexpectedError]).
var (
	// ErrSignatureInvalid: the attestation-api reported the hardware
	// signature chain does not verify.
	ErrSignatureInvalid = errors.New("attestationclient: attestation signature invalid")

	// ErrReportDataMismatch: the evidence does not bind the expected
	// REPORTDATA (absent or false report_data_match verdict).
	ErrReportDataMismatch = errors.New("attestationclient: REPORTDATA mismatch in attestation evidence")

	// ErrMeasurementNotAllowed: the verified launch measurement is absent or
	// not in the caller's allowed set while an allowed set is pinned.
	ErrMeasurementNotAllowed = errors.New("attestationclient: launch measurement not allowed")

	// ErrInvalidLaunchDigest: the /verify response carried a launch digest
	// that is not hex or not measurement-sized — a malformed result, distinct
	// from a policy miss.
	ErrInvalidLaunchDigest = errors.New("attestationclient: launch digest malformed")

	// ErrUnsupportedPlatform: [Client.VerifyEvidence] has no verification
	// rules for the envelope's platform and fails closed.
	ErrUnsupportedPlatform = errors.New("attestationclient: unsupported platform for evidence verification")
)

// snpMeasurementSize is the size of an SEV-SNP launch measurement (SHA-384).
const snpMeasurementSize = 48

// VerifyEnforced posts req to /verify and fails closed on the verdict
// ([EnforceVerdict]). Every caller that trusts a /verify response must gate on
// the verdict fields; doing it here keeps the nil-tolerant fail-open bug out
// of call sites.
func (c Client) VerifyEnforced(ctx context.Context, req types.VerifyRequest) (types.VerifyResponse, error) {
	resp, err := c.Verify(ctx, req)
	if err != nil {
		return types.VerifyResponse{}, err
	}
	if err := EnforceVerdict(req, resp); err != nil {
		return types.VerifyResponse{}, err
	}
	return resp, nil
}

// EnforceVerdict fails closed on a /verify response's verdict: the hardware
// signature must be valid, and when req carried an expected REPORTDATA the
// report_data_match verdict must be affirmatively true. For callers holding a
// response obtained through a fakeable Verify interface; callers with a
// concrete Client use [Client.VerifyEnforced].
func EnforceVerdict(req types.VerifyRequest, resp types.VerifyResponse) error {
	if !resp.Result.SignatureValid {
		return ErrSignatureInvalid
	}
	if req.Params != nil && req.Params.ExpectedReportData != nil {
		if resp.Result.ReportDataMatch == nil || !*resp.Result.ReportDataMatch {
			return ErrReportDataMismatch
		}
	}
	return nil
}

// EvidencePolicy is the verification policy for [Client.VerifyEvidence].
type EvidencePolicy struct {
	// ExpectedReportData is the full 64-byte REPORTDATA the evidence must
	// bind (SHA-384 in bytes 0-47, zero-padded). The platform-specific wire
	// form is derived from it: the Azure TPM-nonce platforms (az-snp, az-tdx)
	// compare the exact 48-byte digest, the native platforms (snp, gcp-snp,
	// tdx) zero-pad whatever is sent and compare all 64 bytes.
	ExpectedReportData [64]byte

	// AllowDebug controls whether debug-mode guests are accepted.
	AllowDebug bool

	// MinTcb, when set, is the minimum platform TCB. Sent on the SNP paths
	// only: the attestation-api's TDX verifier has no minimum-TCB parameter.
	MinTcb *types.MinTcb

	// Measurements is the set of acceptable launch measurements; empty
	// accepts any (callers are expected to warn). Enforced on the SNP paths
	// only — the TDX verifier does not surface a launch measurement, so a
	// pinned set is silently ignored for tdx. Wire that through before
	// relying on TDX in a measurement-pinned deployment.
	Measurements [][]byte
}

// VerifyEvidence verifies an attestation evidence envelope against policy via
// /verify, enforcing the verdict ([Client.VerifyEnforced]) plus the launch
// measurement allowlist. Platforms without verification rules here fail
// closed with [ErrUnsupportedPlatform] rather than being approved under
// another platform's rules.
func (c Client) VerifyEvidence(ctx context.Context, evidence types.AttestationEvidence, policy EvidencePolicy) (types.VerifyResponse, error) {
	switch evidence.Platform {
	case string(types.PlatformSnp), string(types.PlatformAzSnp), string(types.PlatformGcpSnp):
		return c.verifySNPEvidence(ctx, evidence, policy)
	case string(types.PlatformTdx):
		return c.verifyTDXEvidence(ctx, evidence, policy)
	default:
		return types.VerifyResponse{}, fmt.Errorf("%w: %q", ErrUnsupportedPlatform, evidence.Platform)
	}
}

func (c Client) verifySNPEvidence(ctx context.Context, evidence types.AttestationEvidence, policy EvidencePolicy) (types.VerifyResponse, error) {
	// az-snp binds the key through a TPM quote whose nonce is the 48-byte
	// SHA-384 digest — it must receive exactly those 48 bytes. snp and
	// gcp-snp carry the native 64-byte REPORTDATA field and compare all 64.
	reportData := policy.ExpectedReportData[:]
	if evidence.Platform == string(types.PlatformAzSnp) {
		reportData = policy.ExpectedReportData[:sha512.Size384]
	}

	resp, err := c.VerifyEnforced(ctx, verifyRequest(evidence, reportData, policy.AllowDebug, policy.MinTcb))
	if err != nil {
		return types.VerifyResponse{}, err
	}

	if resp.Result.Claims.LaunchDigest != "" {
		measurement, err := hex.DecodeString(resp.Result.Claims.LaunchDigest)
		if err != nil {
			return types.VerifyResponse{}, fmt.Errorf("%w: launch digest is not hex: %w", ErrInvalidLaunchDigest, err)
		}
		if len(measurement) != snpMeasurementSize {
			return types.VerifyResponse{}, fmt.Errorf("%w: launch digest is %d bytes, expected %d", ErrInvalidLaunchDigest, len(measurement), snpMeasurementSize)
		}
		if len(policy.Measurements) > 0 && !measurementAllowed(measurement, policy.Measurements) {
			return types.VerifyResponse{}, fmt.Errorf("%w: launch measurement not in allowed set", ErrMeasurementNotAllowed)
		}
	} else if len(policy.Measurements) > 0 {
		return types.VerifyResponse{}, fmt.Errorf("%w: launch measurement missing", ErrMeasurementNotAllowed)
	}

	return resp, nil
}

func (c Client) verifyTDXEvidence(ctx context.Context, evidence types.AttestationEvidence, policy EvidencePolicy) (types.VerifyResponse, error) {
	// No MinTcb (the TDX verifier has no such parameter) and no measurement
	// enforcement (no launch measurement surfaced) — see EvidencePolicy.
	return c.VerifyEnforced(ctx, verifyRequest(evidence, policy.ExpectedReportData[:], policy.AllowDebug, nil))
}

// verifyRequest builds the /verify request: expected REPORTDATA bound, token
// issuance off (c8s callers mint their own EAR after verifying).
func verifyRequest(evidence types.AttestationEvidence, reportData []byte, allowDebug bool, minTcb *types.MinTcb) types.VerifyRequest {
	expected := types.NewBase64Bytes(reportData)
	return types.NewVerifyRequest(evidence, &types.VerifyParams{
		ExpectedReportData: &expected,
		AllowDebug:         &allowDebug,
		MinTcb:             minTcb,
	}, false)
}

// measurementAllowed reports whether measurement byte-equals one of allowed.
func measurementAllowed(measurement []byte, allowed [][]byte) bool {
	for _, m := range allowed {
		if bytes.Equal(measurement, m) {
			return true
		}
	}
	return false
}
