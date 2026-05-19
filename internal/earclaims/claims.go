package earclaims

const (
	EATProfile               = "eat_profile"
	Issuer                   = "iss"
	IssuedAt                 = "iat"
	ExpiresAt                = "exp"
	EARVerifierID            = "ear_verifier_id"
	Submods                  = "submods"
	EARStatus                = "ear_status"
	EARTrustworthinessVector = "ear_trustworthiness_vector"
	InstanceIdentity         = "instance-identity"
	EARRawEvidence           = "ear_raw_evidence"
	LaunchDigest             = "launch_digest"
	TEEPublicKey             = "tee_public_key"
	Developer                = "developer"
	Build                    = "build"
	SubmodAttester           = "attester"

	// PayloadBodyHash binds an EAR token to a specific request body. The
	// value is base64url(SHA-256(canonicalized request body)). Verifiers MUST
	// reject tokens whose claim does not match the body they receive — this
	// is what stops a captured EAR from being replayed against a different
	// payload within its TTL.
	PayloadBodyHash = "pbh"
)
