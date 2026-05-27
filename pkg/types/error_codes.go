package types

// Stable HTTP error codes returned in the c8s error-envelope shape. Clients
// parse these wire-format identifiers; don't rename without a migration plan.
const (
	ErrorCodeInvalidRequest                = "invalid_request"
	ErrorCodeInvalidChallenge              = "invalid_challenge"
	ErrorCodeInvalidCSR                    = "invalid_csr"
	ErrorCodeInvalidToken                  = "invalid_token"
	ErrorCodeVerificationFailed            = "verification_failed"
	ErrorCodeMeasurementDenied             = "measurement_denied"
	ErrorCodeKeyBinding                    = "key_binding"
	ErrorCodeCSRDenied                     = "csr_denied"
	ErrorCodeSignFailed                    = "sign_failed"
	ErrorCodeTimeout                       = "timeout"
	ErrorCodeAttestationServiceUnreachable = "attestation_service_unreachable"
)
