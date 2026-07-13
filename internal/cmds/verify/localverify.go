package verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/go-sev-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// verifyInProcess verifies already-gathered evidence with attestation-go — the
// Go port of the attestation-rs engine the cluster runs (same self-describing
// envelope, same VerifyParams/VerificationResult/Claims). It auto-detects the
// platform (SEV-SNP incl. Zen4c Siena/Bergamo, TDX, az-snp, az-tdx) from the
// envelope tag, so no product line is supplied by hand and no container is
// launched.
func verifyInProcess(ev *evidence, policy *ratls.VerifyPolicy, minTCB *teetypes.SnpTcb) (*teetypes.VerificationResult, error) {
	params := teetypes.VerifyParams{
		ExpectedReportData: ev.erd,
		AllowDebug:         policy.AllowDebug,
		MinTCB:             minTCB,
	}

	res, err := runAttestationGo(ev, params)
	if err != nil {
		// attestation-go returns an error (not a false verdict) on a bad
		// signature, chain, policy, or REPORTDATA mismatch — all of which are a
		// reachable-but-rejected outcome, i.e. a security verdict (exit 2).
		return nil, &securityError{err: err}
	}
	// Defense in depth: a nil error already implies these, but never report a
	// success the result contradicts.
	if !res.SignatureValid {
		return nil, &securityError{err: fmt.Errorf("verifier returned signature_valid=false")}
	}
	if params.ExpectedReportData != nil && (res.ReportDataMatch == nil || !*res.ReportDataMatch) {
		return nil, &securityError{err: fmt.Errorf("REPORTDATA does not match the expected binding (report_data_match not true)")}
	}
	return res, nil
}

// runAttestationGo dispatches evidence to attestation-go. The envelope path
// (teeverify.Verify) verifies offline and is used whenever the VCEK is already
// inline (a discovery doc or endpoint response). A bare RA-TLS serving cert
// carries the SNP report but no VCEK, and the envelope path requires it inline
// (attestation-go does no KDS fetch there); for that case we drop to
// snp.VerifyReport with a KDS Getter — it resolves the product from the report
// (Zen4c/Siena-aware) and fetches the VCEK from AMD KDS itself.
func runAttestationGo(ev *evidence, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
	if mayMissVCEK(ev.platform) {
		var se snp.SnpEvidence
		if err := json.Unmarshal(ev.rawEvidence, &se); err != nil {
			return nil, fmt.Errorf("parse snp evidence: %w", err)
		}
		if se.CertChain == nil || se.CertChain.Vcek == "" {
			report, err := base64.StdEncoding.DecodeString(se.AttestationReport)
			if err != nil {
				return nil, fmt.Errorf("decode attestation_report: %w", err)
			}
			// nil VCEK + a Getter ⇒ go-sev-guest fetches the VCEK from AMD KDS,
			// using the product attestation-go resolves from the report.
			return snp.VerifyReport(report, nil, params,
				teetypes.PlatformType(ev.platform), snp.MinReportVersion,
				snp.Options{Getter: trust.DefaultHTTPSGetter()})
		}
	}

	envelope, err := json.Marshal(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformType(ev.platform),
		Evidence: ev.rawEvidence,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal evidence envelope: %w", err)
	}
	return teeverify.Verify(envelope, params)
}

// mayMissVCEK reports whether evidence for this platform might lack the VCEK the
// bare-cert path needs (so we fetch it from AMD KDS). True for bare-metal/GCP
// SEV-SNP, whose {attestation_report, cert_chain?} object can omit it. az-snp
// always ships the VCEK inside its HCL-report envelope, and TDX has no VCEK —
// both verify through the envelope path (teeverify.Verify) directly.
func mayMissVCEK(platform string) bool {
	return platform == "snp" || platform == "gcp-snp"
}
