package ratls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// VerifyPolicy defines what attestation claims are acceptable.
type VerifyPolicy struct {
	// Measurements is the set of acceptable launch measurements (48 bytes each).
	// If empty, any measurement is accepted (UNSAFE — use only for development).
	// For SNP this pins LAUNCH_DIGEST; for TDX it pins MRTD. TDX RTMRs are not
	// covered by this policy; see the TDX measurement note in docs/GAPS.md.
	Measurements [][]byte

	// MinTCBVersion is the minimum acceptable platform TCB version.
	// This is a packed uint64 where each byte represents a component
	// (bootloader, TEE, reserved, snp, microcode, etc.) — each component
	// of the current TCB must be >= the corresponding minimum.
	// If zero, any TCB version is accepted.
	// Enforced on the SNP path only; dropped for TDX (see
	// attestationclient.EvidencePolicy).
	MinTCBVersion uint64

	// AllowDebug controls whether debug-mode guests are accepted.
	// Default: false (reject debug guests).
	AllowDebug bool

	// Nonce, when set, is verified against the attestation report's REPORTDATA.
	// REPORTDATA must equal hash(pubkey || nonce). Use when both sides agree on
	// a pre-shared nonce for additional freshness guarantees. If nil, no nonce
	// check is performed (TLS 1.3 already provides replay protection).
	Nonce []byte

	// Config-claims pins (docs/ratls.md). When set, the
	// certificate must carry a config-claims extension whose corresponding
	// digest byte-equals the pinned value:
	//   OperatorKeysDigest — operatorauth.KeySetDigest of the expected set
	//   SeedDigest         — allowlist.CanonicalDigest of the expected seed
	//   WorkloadDigest     — canonical workload image-only role hash
	//   WorkloadArgsDigest — canonical (image, argv) role hash
	// ratls.UnsetDigest() pins "not applicable". Empty = claims are folded
	// into the REPORTDATA check when present but that field is not enforced.
	// Only [VerifyCert] can enforce these (claims ride the certificate);
	// [VerifyAttestation] fails closed when any is set.
	OperatorKeysDigest []byte
	SeedDigest         []byte
	WorkloadDigest     []byte
	WorkloadArgsDigest []byte

	// AttestationApiURL is the attestation-api whose /verify endpoint performs
	// all evidence verification: hardware signature chain, REPORTDATA key
	// binding, debug policy, and minimum TCB. Required: there is no
	// in-process verification path; verification without it fails closed.
	//
	// SECURITY: the /verify response is currently not signed; the verifier
	// trusts whatever this URL returns. Operators MUST point this at an
	// attestation-api inside the same TCB (e.g. a same-node DaemonSet
	// fronted by a Service with internalTrafficPolicy=Local, or a loopback
	// sidecar). A response-signing scheme would lift this constraint.
	AttestationApiURL string

	// AttestationVerifyTimeout bounds online attestation-api verification.
	// If unset, a conservative default is used.
	AttestationVerifyTimeout time.Duration
}

// VerifyResult contains the verified attestation claims extracted from the cert.
type VerifyResult struct {
	// TEEType is the platform type.
	TEEType TEEType
	// ReportData is the 64-byte expected REPORTDATA that the attestation-api
	// confirmed the report is bound to (the api returns only a match verdict,
	// not the report bytes, so this echoes the verified expectation).
	ReportData [64]byte
	// Measurement is the 48-byte launch measurement reported by the
	// attestation-api: LAUNCH_DIGEST for SNP or MRTD for TDX.
	Measurement [48]byte
	// PlatformInfo contains platform-specific metadata from the
	// attestation-api response. Only set on the SNP path.
	PlatformInfo []byte
	// ConfigClaims is the parsed config-claims extension the certificate
	// carried and the evidence bound, or nil when it carried none. Set only by
	// VerifyCert; VerifyAttestation has no certificate to read.
	ConfigClaims *ConfigClaims
}

// VerifyAttestation verifies a raw attestation report against a public key by
// forwarding the evidence to the attestation-api /verify endpoint
// (policy.AttestationApiURL, required):
//  1. The attestation-api verifies the hardware signature chain and that
//     REPORTDATA == hash(pub || nonce), proving the key was generated inside
//     the TEE (and the report is fresh if nonce is set), plus the debug and
//     minimum-TCB policy.
//  2. The launch measurement it returns is checked against
//     policy.Measurements here.
func VerifyAttestation(pub crypto.PublicKey, att *Attestation, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	if policy == nil {
		policy = &VerifyPolicy{}
	}
	if policy.AttestationApiURL == "" {
		return nil, fmt.Errorf("%w: attestation-api URL is required", ErrInvalidReport)
	}
	if len(policy.OperatorKeysDigest) > 0 || len(policy.SeedDigest) > 0 || len(policy.WorkloadDigest) > 0 || len(policy.WorkloadArgsDigest) > 0 {
		// Claims ride the certificate, which this path never sees.
		return nil, fmt.Errorf("%w: config-claims pins require VerifyCert", ErrPolicyViolation)
	}

	expectedReportData, err := ReportDataForKey(pub, nonce)
	if err != nil {
		return nil, fmt.Errorf("ratls: compute expected REPORTDATA: %w", err)
	}

	return verifyReport(att, policy, expectedReportData)
}

// VerifyCert verifies an RA-TLS certificate: it extracts the TEE attestation
// extension and verifies it against the cert's public key. A config-claims
// extension, when carried, is folded into the expected REPORTDATA (the
// evidence binds it) and checked against the policy's config-claims pins
// (docs/ratls.md).
//
// Trust comes from the hardware attestation chain (AMD ARK → ASK → VCEK, or
// Intel equivalent for TDX) as verified by the same-TCB attestation-api, not
// from any certificate authority signature.
func VerifyCert(cert *x509.Certificate, policy *VerifyPolicy, nonce []byte) (*VerifyResult, error) {
	if policy == nil {
		policy = &VerifyPolicy{}
	}

	att, err := ExtractAttestation(cert)
	if err != nil {
		return nil, err
	}

	pub, err := publicKeyFromCert(cert)
	if err != nil {
		return nil, fmt.Errorf("ratls: extract public key: %w", err)
	}

	if policy.AttestationApiURL == "" {
		return nil, fmt.Errorf("%w: attestation-api URL is required", ErrInvalidReport)
	}

	claimsBytes := ExtractConfigClaimsBytes(cert)
	if err := checkClaimsPins(claimsBytes, policy); err != nil {
		return nil, err
	}

	expectedReportData, err := ReportDataForKeyAndClaims(pub, claimsBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("ratls: compute expected REPORTDATA: %w", err)
	}

	result, err := verifyReport(att, policy, expectedReportData)
	if err != nil {
		return nil, err
	}
	if len(claimsBytes) > 0 {
		claims, err := UnmarshalConfigClaims(claimsBytes)
		if err != nil {
			return nil, fmt.Errorf("ratls: parse config-claims: %w", err)
		}
		result.ConfigClaims = claims
	}
	return result, nil
}

// checkClaimsPins enforces the policy's config-claims pins against the raw
// claims extension bytes. INVARIANT: a pin can only reject; acceptance still
// requires the evidence to bind claimsBytes (the REPORTDATA check downstream).
func checkClaimsPins(claimsBytes []byte, policy *VerifyPolicy) error {
	pins := []struct {
		name     string
		expected []byte
		attested func(*ConfigClaims) []byte
	}{
		{"operator-keys", policy.OperatorKeysDigest, func(c *ConfigClaims) []byte { return c.OperatorKeysDigest }},
		{"allowlist-seed", policy.SeedDigest, func(c *ConfigClaims) []byte { return c.SeedDigest }},
		{"workload", policy.WorkloadDigest, func(c *ConfigClaims) []byte { return c.WorkloadDigest }},
		{"workload-args", policy.WorkloadArgsDigest, func(c *ConfigClaims) []byte { return c.WorkloadArgsDigest }},
	}
	anyPinned := false
	for _, p := range pins {
		anyPinned = anyPinned || len(p.expected) > 0
	}
	if !anyPinned {
		return nil
	}
	if len(claimsBytes) == 0 {
		return fmt.Errorf("%w: config-claims pin set but certificate carries no config-claims extension", ErrPolicyViolation)
	}
	claims, err := UnmarshalConfigClaims(claimsBytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyViolation, err)
	}
	for _, p := range pins {
		if len(p.expected) > 0 && !bytes.Equal(p.attested(claims), p.expected) {
			return fmt.Errorf("%w: attested %s digest %x does not match pinned %x", ErrPolicyViolation, p.name, p.attested(claims), p.expected)
		}
	}
	return nil
}

// ExtractAttestation finds and parses the RA-TLS extension from a certificate.
func ExtractAttestation(cert *x509.Certificate) (*Attestation, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDRATLSAttestation) {
			return UnmarshalExtension(ext.Value)
		}
	}
	return nil, fmt.Errorf("%w (OID %s)", ErrNotAttested, OIDRATLSAttestation)
}

// verifyReport normalizes the attestation into an evidence envelope and hands
// it to the attestation-api enforced verifier. The extension's TEE type must
// match the envelope's platform family — fail closed rather than approve one
// platform's evidence under another's rules.
func verifyReport(att *Attestation, policy *VerifyPolicy, expectedReportData [64]byte) (*VerifyResult, error) {
	evidence := att.embedded
	switch att.TEEType {
	case TEETypeSEVSNP:
		// Envelope platforms (az-snp) embed their evidence in the
		// extension directly; bare-metal SNP carries the raw report,
		// which is wrapped in the "snp" evidence envelope here.
		if evidence == nil {
			var err error
			if evidence, err = snpEvidence(att.Report); err != nil {
				return nil, err
			}
		}
		switch evidence.Platform {
		case string(types.PlatformSnp), string(types.PlatformAzSnp), string(types.PlatformGcpSnp):
		default:
			return nil, fmt.Errorf("%w: online verification not implemented for platform %q", ErrUnsupportedTEE, evidence.Platform)
		}
	case TEETypeTDX:
		// TDX always carries a JSON envelope in the RA-TLS extension (see
		// extension.go's UnmarshalExtension). We do NOT ship an in-process
		// TDX quote parser — delegating keeps the heavy Intel dependencies
		// out of every c8s Go binary.
		if evidence == nil {
			return nil, fmt.Errorf("%w: TDX RA-TLS extension missing evidence envelope", ErrInvalidReport)
		}
		switch evidence.Platform {
		case string(types.PlatformTdx), string(types.PlatformAzTdx):
		default:
			return nil, fmt.Errorf("%w: online verification not implemented for platform %q", ErrUnsupportedTEE, evidence.Platform)
		}
	default:
		return nil, fmt.Errorf("%w: TEE type %d", ErrUnsupportedTEE, att.TEEType)
	}
	return verifyEnvelopeOnline(evidence, policy, expectedReportData)
}

const defaultAttestationVerifyTimeout = 10 * time.Second

// unpackSNPMinTcb maps a packed AMD SEV-SNP TCB uint64 onto the components
// the attestation-api understands. Layout matches the SEV-SNP ABI
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

// verifyEnvelopeOnline forwards the envelope to the attestation-api enforced
// verifier ([attestationclient.Client.VerifyEvidence] — verdict gate,
// platform-specific REPORTDATA wire form, measurement allowlist) and maps its
// verdicts onto this package's sentinels.
func verifyEnvelopeOnline(evidence *types.AttestationEvidence, policy *VerifyPolicy, expectedReportData [64]byte) (*VerifyResult, error) {
	timeout := policy.AttestationVerifyTimeout
	if timeout <= 0 {
		timeout = defaultAttestationVerifyTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var minTcb *types.MinTcb
	if policy.MinTCBVersion != 0 {
		m := unpackSNPMinTcb(policy.MinTCBVersion)
		minTcb = &m
	}
	resp, err := attestationclient.NewClient(policy.AttestationApiURL).VerifyEvidence(ctx, *evidence, attestationclient.EvidencePolicy{
		ExpectedReportData: expectedReportData,
		AllowDebug:         policy.AllowDebug,
		MinTcb:             minTcb,
		Measurements:       policy.Measurements,
	})
	if err != nil {
		return nil, mapVerifyError(evidence.Platform, err)
	}

	teeType := TEETypeSEVSNP
	if evidence.Platform == string(types.PlatformTdx) || evidence.Platform == string(types.PlatformAzTdx) {
		teeType = TEETypeTDX
	}
	result := &VerifyResult{TEEType: teeType}
	if teeType == TEETypeSEVSNP && len(resp.Result.Claims.PlatformData) > 0 && !bytes.Equal(resp.Result.Claims.PlatformData, []byte("null")) {
		result.PlatformInfo = resp.Result.Claims.PlatformData
	}
	copy(result.ReportData[:], expectedReportData[:])
	if resp.Result.Claims.LaunchDigest != "" {
		// Hex validity and length were enforced by VerifyEvidence.
		measurement, _ := hex.DecodeString(resp.Result.Claims.LaunchDigest)
		copy(result.Measurement[:], measurement)
	}
	return result, nil
}

// mapVerifyError translates attestationclient verdict sentinels onto this
// package's error surface, preserving the pre-consolidation sentinels callers
// match with errors.Is.
func mapVerifyError(platform string, err error) error {
	switch {
	case errors.Is(err, attestationclient.ErrSignatureInvalid):
		return ErrSignatureInvalid
	case errors.Is(err, attestationclient.ErrReportDataMismatch):
		return fmt.Errorf("%w — key was not generated in this TEE", ErrKeyBinding)
	case errors.Is(err, attestationclient.ErrMeasurementNotAllowed):
		return fmt.Errorf("%w: %v", ErrPolicyViolation, err)
	case errors.Is(err, attestationclient.ErrInvalidLaunchDigest):
		return fmt.Errorf("%w: %v", ErrInvalidReport, err)
	case errors.Is(err, attestationclient.ErrUnsupportedPlatform):
		return fmt.Errorf("%w: online verification not implemented for platform %q", ErrUnsupportedTEE, platform)
	default:
		return fmt.Errorf("ratls: online %s attestation verify: %w", platform, err)
	}
}

// snpEvidence wraps a raw SEV-SNP attestation report in the attestation-api's
// bare-metal "snp" evidence envelope for POST /verify. Only bare-metal SNP
// carries raw report bytes in the RA-TLS extension; every other platform
// carries the full envelope directly, so no wrapping is needed for them
// (att.embedded is populated by UnmarshalExtension in that case).
func snpEvidence(rawReport []byte) (*types.AttestationEvidence, error) {
	inner, err := json.Marshal(struct {
		AttestationReport string `json:"attestation_report"`
	}{base64.StdEncoding.EncodeToString(rawReport)})
	if err != nil {
		return nil, fmt.Errorf("ratls: build snp evidence: %w", err)
	}
	return &types.AttestationEvidence{
		Platform: string(types.PlatformSnp),
		Evidence: inner,
	}, nil
}

// MeasurementAllowed reports whether measurement byte-equals one of the allowed
// launch digests (an empty allowed set means "no pin" and is handled by callers).
func MeasurementAllowed(measurement []byte, allowed [][]byte) bool {
	for _, m := range allowed {
		if bytes.Equal(measurement, m) {
			return true
		}
	}
	return false
}
