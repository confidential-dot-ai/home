package ratls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/types"
)

// VerifyPolicy defines what attestation claims are acceptable.
type VerifyPolicy struct {
	// Measurements is the set of acceptable launch measurements (48 bytes each).
	// If empty, any measurement is accepted (UNSAFE — use only for development).
	Measurements [][]byte

	// MinTCBVersion is the minimum acceptable platform TCB version.
	// This is a packed uint64 where each byte represents a component
	// (bootloader, TEE, reserved, snp, microcode, etc.) — each component
	// of the current TCB must be >= the corresponding minimum.
	// If zero, any TCB version is accepted.
	MinTCBVersion uint64

	// AllowDebug controls whether debug-mode guests are accepted.
	// Default: false (reject debug guests).
	AllowDebug bool

	// RequireSMT requires the SNP guest policy to allow SMT
	// (Simultaneous Multi-Threading).
	// SMT is otherwise allowed by default, matching the upstream SEV-SNP
	// verifier's guest-policy model and common CVM cloud behavior.
	RequireSMT bool

	// Nonce, when set, is verified against the attestation report's REPORTDATA.
	// REPORTDATA must equal hash(pubkey || nonce). Use when both sides agree on
	// a pre-shared nonce for additional freshness guarantees. If nil, no nonce
	// check is performed (TLS 1.3 already provides replay protection).
	Nonce []byte

	// AttestationServiceURL enables online verification for evidence formats
	// that cannot be verified from the SNP report alone. AKS az-snp binds the
	// caller nonce through the TPM quote, so verifiers must call the local
	// attestation-service /verify endpoint for those RA-TLS extensions.
	//
	// SECURITY: the /verify response is currently not signed; the verifier
	// trusts whatever this URL returns. Operators MUST point this at an
	// attestation service inside the same TCB (e.g. a same-node DaemonSet
	// fronted by a Service with internalTrafficPolicy=Local, or a loopback
	// sidecar). A response-signing scheme would lift this constraint.
	AttestationServiceURL string

	// AttestationVerifyTimeout bounds online attestation-service verification.
	// If unset, a conservative default is used.
	AttestationVerifyTimeout time.Duration
}

// VerifyResult contains the verified attestation claims extracted from the cert.
type VerifyResult struct {
	// TEEType is the platform type.
	TEEType TEEType
	// ReportData is the 64-byte REPORTDATA field from the attestation report.
	ReportData [64]byte
	// Measurement is the 48-byte launch measurement.
	Measurement [48]byte
	// GuestPolicy is the SNP guest policy flags.
	GuestPolicy uint64
	// CurrentTCB is the platform's current TCB version (packed uint64).
	CurrentTCB uint64
	// PlatformInfo contains platform-specific metadata.
	PlatformInfo []byte
}

// CheckKeyBinding verifies that the attestation report's REPORTDATA matches
// hash(pub || nonce), proving the key was generated inside this TEE.
// Unlike [VerifyAttestation], this does NOT verify the hardware signature
// chain — it only checks the cryptographic binding between key and report.
func CheckKeyBinding(pub crypto.PublicKey, att *Attestation, nonce []byte) error {
	expected, err := ReportDataForKey(pub, nonce)
	if err != nil {
		return fmt.Errorf("ratls: compute expected REPORTDATA: %w", err)
	}

	switch att.TEEType {
	case TEETypeSEVSNP:
		_, err := checkSEVSNPBinding(att.Report, expected)
		return err
	case TEETypeTDX:
		return fmt.Errorf("%w: TDX binding check not yet implemented", ErrUnsupportedTEE)
	default:
		return fmt.Errorf("%w: TEE type %d", ErrUnsupportedTEE, att.TEEType)
	}
}

// VerifyAttestation verifies a raw attestation report against a public key:
//  1. Parses the attestation report (once).
//  2. Checks that REPORTDATA == hash(pub || nonce), proving the key was
//     generated inside the TEE (and the report is fresh if nonce is set).
//  3. Verifies the attestation report signature against the AMD VCEK chain
//     (or Intel equivalent for TDX).
//  4. Validates measurements and policy against the provided VerifyPolicy.
func VerifyAttestation(pub crypto.PublicKey, att *Attestation, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	if policy == nil {
		policy = &VerifyPolicy{}
	}

	expectedReportData, err := ReportDataForKey(pub, nonce)
	if err != nil {
		return nil, fmt.Errorf("ratls: compute expected REPORTDATA: %w", err)
	}

	return verifyReport(att, policy, expectedReportData)
}

// VerifyCert verifies an RA-TLS certificate:
//  1. Extracts the TEE attestation extension from the cert.
//  2. Checks that REPORTDATA == hash(cert.PublicKey || nonce), proving the key
//     was generated inside the TEE (and the report is fresh if nonce is set).
//  3. Verifies the attestation report signature against the AMD VCEK chain
//     (or Intel equivalent for TDX).
//  4. Validates measurements and policy against the provided VerifyPolicy.
//
// Trust comes from the hardware attestation chain (AMD ARK → ASK → VCEK),
// not from any certificate authority signature.
func VerifyCert(cert *x509.Certificate, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	att, err := extractAttestation(cert)
	if err != nil {
		return nil, err
	}

	pub, err := publicKeyFromCert(cert)
	if err != nil {
		return nil, fmt.Errorf("ratls: extract public key: %w", err)
	}

	return VerifyAttestation(pub, att, policy, nonce)
}

// extractAttestation finds and parses the RA-TLS extension from a certificate.
func extractAttestation(cert *x509.Certificate) (*Attestation, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDRATLSAttestation) {
			return UnmarshalExtension(ext.Value)
		}
	}
	return nil, fmt.Errorf("%w (OID %s)", ErrNotAttested, OIDRATLSAttestation)
}

// verifyReport parses the attestation report once, checks key binding,
// verifies the hardware signature, and validates policy.
func verifyReport(att *Attestation, policy *VerifyPolicy, expectedReportData [64]byte) (*VerifyResult, error) {
	switch att.TEEType {
	case TEETypeSEVSNP:
		return verifySEVSNP(att, policy, expectedReportData)
	case TEETypeTDX:
		return nil, fmt.Errorf("%w: TDX verification not yet implemented", ErrUnsupportedTEE)
	default:
		return nil, fmt.Errorf("%w: TEE type %d", ErrUnsupportedTEE, att.TEEType)
	}
}

// checkSEVSNPBinding parses the raw SNP report and verifies that REPORTDATA
// matches the expected value. Returns the parsed report proto for reuse.
func checkSEVSNPBinding(rawReport []byte, expected [64]byte) (*spb.Report, error) {
	rawReport, err := NormalizeSEVSNPReport(rawReport)
	if err != nil {
		return nil, err
	}
	report, err := sabi.ReportToProto(rawReport)
	if err != nil {
		return nil, fmt.Errorf("ratls: parse SNP report: %w", err)
	}
	if len(report.ReportData) != 64 {
		return nil, fmt.Errorf("ratls: SNP report has %d-byte REPORTDATA, expected 64", len(report.ReportData))
	}
	if !bytes.Equal(report.ReportData, expected[:]) {
		return nil, fmt.Errorf("%w — key was not generated in this TEE", ErrKeyBinding)
	}
	return report, nil
}

const defaultAttestationVerifyTimeout = 10 * time.Second

// unpackSNPMinTcb maps a packed AMD SEV-SNP TCB uint64 onto the components
// the attestation service understands. Layout matches the SEV-SNP ABI
// TcbVersion: byte 0 = bootloader, byte 1 = tee, bytes 2-5 reserved,
// byte 6 = snp, byte 7 = microcode.
func unpackSNPMinTcb(packed uint64) types.MinTcb {
	return types.MinTcb{
		Bootloader: byte(packed),
		Tee:        byte(packed >> 8),
		Snp:        byte(packed >> 48),
		Microcode:  byte(packed >> 56),
	}
}

func verifySEVSNPOnline(evidence *types.AttestationEvidence, policy *VerifyPolicy, expectedReportData [64]byte) (*VerifyResult, error) {
	// Only az-snp is wired end-to-end through this verifier today. az-tdx and
	// any future platform would need their own measurement semantics and
	// result population; fail closed rather than approve under SNP rules.
	if evidence.Platform != string(types.PlatformAzSnp) {
		return nil, fmt.Errorf("%w: online verification not implemented for platform %q", ErrUnsupportedTEE, evidence.Platform)
	}
	if policy == nil || policy.AttestationServiceURL == "" {
		return nil, fmt.Errorf("%w: attestation service URL is required for %s evidence", ErrInvalidReport, evidence.Platform)
	}
	if policy.RequireSMT {
		// The attestation-service /verify API has no SMT parameter, so we
		// cannot enforce this constraint online without extending the wire
		// protocol. Fail closed so the policy is never silently ignored.
		return nil, fmt.Errorf("%w: RequireSMT is not enforceable for online (%s) verification", ErrPolicyViolation, evidence.Platform)
	}

	timeout := policy.AttestationVerifyTimeout
	if timeout <= 0 {
		timeout = defaultAttestationVerifyTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	expected := types.NewBase64Bytes(expectedReportData[:sha512.Size384])
	allowDebug := policy.AllowDebug
	issueToken := false
	params := &types.VerifyParams{
		ExpectedReportData: &expected,
		AllowDebug:         &allowDebug,
	}
	if policy.MinTCBVersion != 0 {
		minTcb := unpackSNPMinTcb(policy.MinTCBVersion)
		params.MinTcb = &minTcb
	}
	resp, err := attestationclient.NewClient(policy.AttestationServiceURL).Verify(ctx, types.VerifyRequest{
		Evidence:   *evidence,
		Params:     params,
		IssueToken: &issueToken,
	})
	if err != nil {
		return nil, fmt.Errorf("ratls: online attestation verify: %w", err)
	}
	if !resp.Result.SignatureValid {
		return nil, ErrSignatureInvalid
	}
	if resp.Result.ReportDataMatch == nil || !*resp.Result.ReportDataMatch {
		return nil, fmt.Errorf("%w — key was not generated in this TEE", ErrKeyBinding)
	}

	result := &VerifyResult{TEEType: TEETypeSEVSNP}
	if len(resp.Result.Claims.PlatformData) > 0 && !bytes.Equal(resp.Result.Claims.PlatformData, []byte("null")) {
		result.PlatformInfo = resp.Result.Claims.PlatformData
	}
	copy(result.ReportData[:], expectedReportData[:])

	if resp.Result.Claims.LaunchDigest != "" {
		measurement, err := hex.DecodeString(resp.Result.Claims.LaunchDigest)
		if err != nil {
			return nil, fmt.Errorf("%w: launch digest is not hex: %w", ErrInvalidReport, err)
		}
		if len(measurement) != SNPMeasurementSize {
			return nil, fmt.Errorf("%w: launch digest is %d bytes, expected %d", ErrInvalidReport, len(measurement), SNPMeasurementSize)
		}
		copy(result.Measurement[:], measurement)
		if len(policy.Measurements) > 0 && !measurementAllowed(measurement, policy.Measurements) {
			return nil, fmt.Errorf("%w: launch measurement not in allowed set", ErrPolicyViolation)
		}
	} else if len(policy.Measurements) > 0 {
		return nil, fmt.Errorf("%w: launch measurement missing", ErrPolicyViolation)
	}

	return result, nil
}

// verifySEVSNP performs full verification: key binding, AMD signature chain,
// and policy validation. The report is parsed once and reused.
func verifySEVSNP(att *Attestation, policy *VerifyPolicy, expectedReportData [64]byte) (*VerifyResult, error) {
	if att.embedded != nil {
		return verifySEVSNPOnline(att.embedded, policy, expectedReportData)
	}

	report, err := checkSEVSNPBinding(att.Report, expectedReportData)
	if err != nil {
		return nil, err
	}

	// Build the attestation protobuf with certificate chain.
	snpAttestation := &spb.Attestation{Report: report}
	if len(att.CertChain) > 0 {
		certs, err := parseSEVCertChain(att.CertChain)
		if err != nil {
			return nil, fmt.Errorf("ratls: parse VCEK cert chain: %w", err)
		}
		snpAttestation.CertificateChain = certs
	}

	// Verify the report signature against the AMD VCEK chain.
	if err := verify.SnpAttestation(snpAttestation, &verify.Options{}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}

	// Validate report fields against policy. go-sev-guest treats each true
	// GuestPolicy field as an allowed capability, not as a required property.
	// SMT-enabled CVMs are common, so allow SMT by default and enforce
	// RequireSMT explicitly below when callers ask for it.
	validateOpts := snpValidateOptions(policy)
	if err := validate.SnpAttestation(snpAttestation, validateOpts); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPolicyViolation, err)
	}
	if err := enforceSNPRequiredPolicy(report, policy); err != nil {
		return nil, err
	}

	// Validate measurement length before comparison.
	if len(report.Measurement) != SNPMeasurementSize {
		return nil, fmt.Errorf("%w: measurement is %d bytes, expected %d", ErrInvalidReport, len(report.Measurement), SNPMeasurementSize)
	}

	// Check measurement against allowed list.
	if len(policy.Measurements) > 0 {
		if !measurementAllowed(report.Measurement, policy.Measurements) {
			return nil, fmt.Errorf("%w: launch measurement not in allowed set", ErrPolicyViolation)
		}
	}

	// Check TCB version against minimum.
	if policy.MinTCBVersion != 0 {
		if !tcbAtLeast(report.CurrentTcb, policy.MinTCBVersion) {
			return nil, fmt.Errorf("%w: platform TCB 0x%016x is below minimum 0x%016x", ErrPolicyViolation, report.CurrentTcb, policy.MinTCBVersion)
		}
	}

	result := &VerifyResult{
		TEEType:     TEETypeSEVSNP,
		GuestPolicy: report.Policy,
		CurrentTCB:  report.CurrentTcb,
	}
	copy(result.ReportData[:], report.ReportData)
	copy(result.Measurement[:], report.Measurement)
	return result, nil
}

func snpValidateOptions(policy *VerifyPolicy) *validate.Options {
	if policy == nil {
		policy = &VerifyPolicy{}
	}
	return &validate.Options{
		GuestPolicy: sabi.SnpPolicy{
			SMT:   true,
			Debug: policy.AllowDebug,
		},
	}
}

func enforceSNPRequiredPolicy(report *spb.Report, policy *VerifyPolicy) error {
	if policy == nil || !policy.RequireSMT {
		return nil
	}
	guestPolicy, err := sabi.ParseSnpPolicy(report.Policy)
	if err != nil {
		return fmt.Errorf("%w: parse SNP guest policy: %w", ErrInvalidReport, err)
	}
	if !guestPolicy.SMT {
		return fmt.Errorf("%w: SMT is required but not enabled", ErrPolicyViolation)
	}
	return nil
}

// parseSEVCertChain parses concatenated DER-encoded certificates into the
// protobuf CertificateChain format expected by go-sev-guest.
func parseSEVCertChain(chainDER []byte) (*spb.CertificateChain, error) {
	certs, err := x509.ParseCertificates(chainDER)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificates: %w", err)
	}

	chain := &spb.CertificateChain{}
	for i, cert := range certs {
		switch i {
		case 0:
			chain.VcekCert = cert.Raw
		case 1:
			chain.AskCert = cert.Raw
		case 2:
			chain.ArkCert = cert.Raw
		}
	}
	return chain, nil
}

func measurementAllowed(measurement []byte, allowed [][]byte) bool {
	for _, m := range allowed {
		if bytes.Equal(measurement, m) {
			return true
		}
	}
	return false
}

// tcbAtLeast returns true if every byte component of current is >= the
// corresponding byte in minimum. The TCB version is a packed uint64 where
// each byte represents a versioned component (bootloader, TEE, SNP,
// microcode, etc.) — all must individually meet the minimum.
func tcbAtLeast(current, minimum uint64) bool {
	for i := 0; i < 8; i++ {
		shift := uint(i * 8)
		cur := byte(current >> shift)
		min := byte(minimum >> shift)
		if cur < min {
			return false
		}
	}
	return true
}
