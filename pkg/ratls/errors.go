package ratls

import "errors"

// Sentinel errors for programmatic error handling via [errors.Is].
// These cover the verification pipeline stages — callers can distinguish
// between different failure modes without string matching.
var (
	// ErrKeyBinding indicates that the attestation report's REPORTDATA
	// does not match hash(publicKey), meaning the key was not generated
	// inside the claimed TEE.
	ErrKeyBinding = errors.New("ratls: REPORTDATA does not match key")

	// ErrNotAttested indicates that a certificate does not contain
	// the RA-TLS attestation extension (OID 1.3.6.1.4.1.59888.1.1).
	ErrNotAttested = errors.New("ratls: certificate missing RA-TLS extension")

	// ErrSignatureInvalid indicates that the hardware attestation report's
	// signature could not be verified against the platform certificate chain
	// (e.g., AMD VCEK → ASK → ARK).
	ErrSignatureInvalid = errors.New("ratls: hardware signature verification failed")

	// ErrPolicyViolation indicates that the verified launch measurement is not
	// in the [VerifyPolicy] allowlist. Debug and minimum-TCB policy are
	// enforced by the attestation-api; those rejections surface as the
	// attestation-api error or [ErrSignatureInvalid], not this sentinel.
	ErrPolicyViolation = errors.New("ratls: attestation policy check failed")

	// ErrUnsupportedTEE indicates an unrecognized TEE platform type.
	ErrUnsupportedTEE = errors.New("ratls: unsupported TEE platform")

	// ErrInvalidReport indicates a structurally invalid attestation report
	// (e.g., wrong size for the platform, truncated, or corrupt).
	ErrInvalidReport = errors.New("ratls: invalid attestation report")
)
