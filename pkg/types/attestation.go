package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// ChallengeResponse is the response body for POST /authenticate.
type ChallengeResponse struct {
	Challenge string `json:"challenge"`
}

// AttestRequestBody is the request body for POST /attest.
type AttestRequestBody struct {
	Challenge string              `json:"challenge"`
	Evidence  AttestationEvidence `json:"evidence"`
	CSR       string              `json:"csr"`

	// WorkloadClaims is the standard-base64 DER of the RA-TLS config-claims
	// extension (ratls.ConfigClaims) the requester bound into its evidence
	// REPORTDATA, when it attests a workload digest (docs/ratls.md).
	// Empty when the requester binds no claims. CDS folds these exact bytes
	// into the expected REPORTDATA, so a tampered value fails verification.
	WorkloadClaims string `json:"workload_claims,omitempty"`
	// InitContainers and Containers are the (image digest, argv) tuples of
	// the pod's non-injected init and main containers. CDS re-derives BOTH
	// the image-only WorkloadDigest and the (image, argv) WorkloadArgsDigest
	// from these lists and requires both to match the values in
	// WorkloadClaims — so neither list, nor the init/main split, nor a
	// per-container argv can be swapped — and that each image is
	// allowlisted, then issues (docs/ratls.md).
	InitContainers []AttestedContainer `json:"init_containers,omitempty"`
	Containers     []AttestedContainer `json:"containers,omitempty"`
}

// AttestedContainer is one (image, argv) tuple in an attestation request:
// the image digest a workload claims to run and the merged argv that will be
// exec'd for it. CDS treats both as untrusted proposal — the tuple only
// matters after it hashes to the evidence-bound WorkloadArgsDigest and the
// image is allowlisted (docs/ratls.md).
type AttestedContainer struct {
	Image string   `json:"image"`
	Args  []string `json:"args,omitempty"`
}

// AttestKeyRequestBody is the request body for POST /attest-key. Used by
// in-cluster c8s components (CDS for its own handoff signer key) that need a
// CDS-issued EAR bound to a TEE-attested ECDSA public key, without going
// through the full cert-issuance flow that /attest does.
type AttestKeyRequestBody struct {
	Challenge string              `json:"challenge"`
	Evidence  AttestationEvidence `json:"evidence"`
	// PublicKey is the standard-base64-encoded PKIX DER of the ECDSA public
	// key the caller wants attested. The TEE evidence's REPORTDATA must be
	// SHA-384(this key) — the server verifies this binding before issuing
	// the EAR.
	PublicKey string `json:"public_key"`
	// OperatorKeysHash is the canonical hash of the CDS operator public-key
	// set. When present, it is included in REPORTDATA alongside PublicKey and
	// Challenge and copied into the issued EAR, so handoff peers can require
	// the same allowlist-write policy on both replicas.
	OperatorKeysHash string `json:"operator_keys_hash,omitempty"`
}

// AttestKeyResponseBody is the response body for POST /attest-key.
type AttestKeyResponseBody struct {
	// EAR is a signed JWT whose tee_public_key claim equals PublicKey from
	// the request. Verifiers re-check the JWT signature against CDS's
	// JWKS and re-derive the binding before trusting it for any action.
	EAR string `json:"ear"`
}

// AttestationEvidence carries platform-specific attestation evidence.
type AttestationEvidence struct {
	Platform string          `json:"platform"`
	Evidence json.RawMessage `json:"evidence"`
}

// --- attestation-api types ---

// Base64Bytes wraps a byte slice that serialises to/from standard base64 in JSON.
type Base64Bytes struct {
	data []byte
}

// NewBase64Bytes creates a Base64Bytes from raw bytes.
func NewBase64Bytes(data []byte) Base64Bytes {
	return Base64Bytes{data: data}
}

// Bytes returns the underlying byte slice.
func (b Base64Bytes) Bytes() []byte {
	return b.data
}

func (b Base64Bytes) MarshalJSON() ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(b.data)
	return json.Marshal(encoded)
}

func (b *Base64Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	b.data = decoded
	return nil
}

// Platform represents a TEE platform type.
type Platform string

const (
	PlatformAuto   Platform = "auto"
	PlatformSnp    Platform = "snp"
	PlatformTdx    Platform = "tdx"
	PlatformAzSnp  Platform = "az-snp"
	PlatformAzTdx  Platform = "az-tdx"
	PlatformGcpSnp Platform = "gcp-snp"
)

// AttestRequest is the request body for the attestation-api POST /attest.
type AttestRequest struct {
	ReportData Base64Bytes `json:"report_data"`
	Platform   Platform    `json:"platform"`
}

// AttestResponse is the response from the attestation-api POST /attest.
//
// Evidence is the platform-specific evidence object (e.g. SnpEvidence,
// TdxEvidence) emitted directly by the attestation-api. Callers that
// need to forward evidence to /verify must wrap it in an AttestationEvidence
// envelope keyed by Platform.
type AttestResponse struct {
	Platform string          `json:"platform"`
	Evidence json.RawMessage `json:"evidence"`
}

// VerifyRequest is sent to the attestation-api POST /verify. The attestation-api
// expects the platform at the top level and Evidence to be the platform-specific
// evidence object (not an AttestationEvidence envelope) — build it via
// NewVerifyRequest / VerifyReportData, which split an AttestationEvidence.
type VerifyRequest struct {
	Platform   string          `json:"platform"`
	Evidence   json.RawMessage `json:"evidence"`
	Params     *VerifyParams   `json:"params,omitempty"`
	IssueToken *bool           `json:"issue_token,omitempty"`
}

// NewVerifyRequest splits an AttestationEvidence envelope into the top-level
// platform + platform-specific evidence shape attestation-api's /verify wants.
func NewVerifyRequest(evidence AttestationEvidence, params *VerifyParams, issueToken bool) VerifyRequest {
	return VerifyRequest{
		Platform:   evidence.Platform,
		Evidence:   evidence.Evidence,
		Params:     params,
		IssueToken: &issueToken,
	}
}

// VerifyReportData builds a VerifyRequest that checks the evidence binds
// expectedReportData and explicitly does not ask the attestation-api to
// issue a token. c8s callers mint their own EAR after verifying, so token
// issuance is always off; setting IssueToken here keeps that intent in one
// place instead of every call site spelling out new(bool).
func VerifyReportData(evidence AttestationEvidence, expectedReportData Base64Bytes) VerifyRequest {
	return NewVerifyRequest(evidence, &VerifyParams{ExpectedReportData: &expectedReportData}, false)
}

// VerifyParams contains optional verification parameters.
type VerifyParams struct {
	ExpectedReportData   *Base64Bytes `json:"expected_report_data,omitempty"`
	ExpectedInitDataHash *Base64Bytes `json:"expected_init_data_hash,omitempty"`
	AllowDebug           *bool        `json:"allow_debug,omitempty"`
	MinTcb               *MinTcb      `json:"min_tcb,omitempty"`
}

// MinTcb specifies minimum TCB version requirements.
type MinTcb struct {
	Bootloader uint8 `json:"bootloader"`
	Tee        uint8 `json:"tee"`
	Snp        uint8 `json:"snp"`
	Microcode  uint8 `json:"microcode"`
}

// VerifyResponse is the response from the attestation-api POST /verify.
type VerifyResponse struct {
	Result VerificationResult `json:"result"`
	Token  *string            `json:"token"`
}

// VerificationResult contains the verification outcome.
type VerificationResult struct {
	Platform        string          `json:"platform"`
	SignatureValid  bool            `json:"signature_valid"`
	Claims          Claims          `json:"claims"`
	ReportDataMatch *bool           `json:"report_data_match"`
	InitDataMatch   *bool           `json:"init_data_match"`
	TcbStatus       json.RawMessage `json:"tcb_status,omitempty"`
}

// Claims are normalised claims extracted from attestation evidence.
type Claims struct {
	LaunchDigest string          `json:"launch_digest"`
	ReportData   string          `json:"report_data"`
	SignedData   string          `json:"signed_data"`
	InitData     string          `json:"init_data"`
	Tcb          json.RawMessage `json:"tcb"`
	PlatformData json.RawMessage `json:"platform_data"`
}

// HealthResponse is the response from the attestation-api GET /health.
type HealthResponse struct {
	Status      string     `json:"status"`
	Platform    *string    `json:"platform,omitempty"`
	Cache       CacheStats `json:"cache"`
	TokenIssuer bool       `json:"token_issuer"`
}

// CacheStats holds cache statistics from the attestation-api.
type CacheStats struct {
	VcekEntries    uint64  `json:"vcek_entries"`
	ChainEntries   uint64  `json:"chain_entries"`
	LastCrlRefresh *string `json:"last_crl_refresh"`
}

// ErrorResponse is a standard error response from external services.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// SignCsrRequest is sent to CDS POST /sign-csr.
type SignCsrRequest struct {
	Ear string `json:"ear"`
	Csr string `json:"csr"`
	Ttl string `json:"ttl"`
}

// SignCsrResponse is the response from CDS POST /sign-csr.
type SignCsrResponse struct {
	Certificate   string `json:"certificate"`
	CACertificate string `json:"ca_certificate"`
}

// SignedCert validates the response certificate fields and returns the PEM leaf
// plus CA bundle in the order expected by TLS clients.
func (r SignCsrResponse) SignedCert() (string, error) {
	certPEM := strings.TrimSpace(r.Certificate)
	if certPEM == "" {
		return "", fmt.Errorf("certificate is required")
	}
	certs, err := certutil.ParsePEMCertificates([]byte(certPEM))
	if err != nil {
		return "", fmt.Errorf("certificate must be PEM-encoded X.509: %w", err)
	}
	if len(certs) != 1 {
		return "", fmt.Errorf("certificate must contain exactly one CERTIFICATE block, got %d", len(certs))
	}

	caPEM := strings.TrimSpace(r.CACertificate)
	if caPEM == "" {
		return certPEM + "\n", nil
	}
	if _, err := certutil.ParsePEMCertificates([]byte(caPEM)); err != nil {
		return "", fmt.Errorf("ca_certificate must be PEM-encoded X.509: %w", err)
	}
	return certPEM + "\n" + caPEM + "\n", nil
}
