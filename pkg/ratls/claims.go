// Config-claims: digests of host-supplied configuration, carried on an RA-TLS
// certificate and bound into its attestation evidence, so verifiers can pin
// them the way they pin launch measurements. Normative spec, trust semantics,
// and audit map: docs/ratls.md.

package ratls

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// OIDRATLSConfigClaims identifies the config-claims extension (see
// extension.go for the 1.3.6.1.4.1.59888 arc; .1.2 is taken by
// certutil.OIDAttestationDigest):
//
//	1.3.6.1.4.1.59888.1.3 - RA-TLS config-claims extension
var OIDRATLSConfigClaims = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1, 3}

// configClaimsVersion is the only claims version this package emits or parses.
const configClaimsVersion = 1

// claimsDomainSep tags the config-claims REPORTDATA transcript
// (ReportDataForKeyAndClaims), keeping it disjoint from a plain key+nonce
// binding (SHA-384(pubkey ‖ nonce)). The transcript is domain-separated AND
// length-framed, so the binding is unambiguous without relying on any field's
// length or the nonce's provenance (docs/ratls.md, Config-claims).
var claimsDomainSep = []byte("c8s/config-claims/v1\x00")

// ClaimsDigestSize is the size of each digest carried in ConfigClaims
// (SHA-256).
const ClaimsDigestSize = 32

// unsetDigest marks a claims field that does not apply to the certificate's
// role. All-zero is unreachable as a real SHA-256 output, so a verifier
// pinning a real value can never be satisfied by a sentinel.
var unsetDigest = make([]byte, ClaimsDigestSize)

// UnsetDigest returns the "not applicable" sentinel for a claims field, as a
// fresh copy so callers cannot corrupt the sentinel.
func UnsetDigest() []byte {
	return append([]byte(nil), unsetDigest...)
}

// ConfigClaims is configuration the attesting workload vouches for
// (docs/ratls.md). Every field is always present; a field that does
// not apply carries UnsetDigest. The evidence binds the marshaled claims, so
// they carry the same trust as the launch measurement — a statement by
// measured code about the configuration it actually loaded.
type ConfigClaims struct {
	// OperatorKeysDigest is the canonical digest of the operator public-key
	// set authorized to mutate the allowlist (operatorauth.KeySetDigest). The
	// empty key set is a defined digest, distinct from the sentinel, so "writes
	// disabled" is attestable. Set by CDS.
	OperatorKeysDigest []byte
	// SeedDigest is the canonical digest of the allowlist seed loaded at
	// startup (allowlist.CanonicalDigest), or UnsetDigest when no seed was
	// configured. Set by CDS.
	SeedDigest []byte
	// WorkloadDigest is the canonical digest of the pod's non-injected
	// container image digests. Set by the workload (get-cert via
	// workloadclaims.BuildConfigClaims), not by CDS.
	WorkloadDigest []byte
}

// configClaimsASN1 is the ASN.1 DER encoding structure (docs/ratls.md,
// Config-claims).
//
//	C8SConfigClaims ::= SEQUENCE {
//	    version             INTEGER,
//	    operatorKeysDigest  OCTET STRING,
//	    seedDigest          OCTET STRING,
//	    workloadDigest      OCTET STRING
//	}
type configClaimsASN1 struct {
	Version            int
	OperatorKeysDigest []byte
	SeedDigest         []byte
	WorkloadDigest     []byte
}

// MarshalExtension encodes the claims as a DER-encoded X.509 extension.
// asn1.Marshal is deterministic, so the bytes the provider folds into
// REPORTDATA and the bytes CreateAttestedCert embeds are identical — the
// binding covers exactly what the certificate carries (docs/ratls.md).
func (c *ConfigClaims) MarshalExtension() (pkix.Extension, error) {
	for _, f := range []struct {
		name string
		d    []byte
	}{
		{"operator-keys", c.OperatorKeysDigest},
		{"seed", c.SeedDigest},
		{"workload", c.WorkloadDigest},
	} {
		if len(f.d) != ClaimsDigestSize {
			return pkix.Extension{}, fmt.Errorf("ratls: %s claims digest must be %d bytes, got %d", f.name, ClaimsDigestSize, len(f.d))
		}
	}
	value, err := asn1.Marshal(configClaimsASN1{
		Version:            configClaimsVersion,
		OperatorKeysDigest: c.OperatorKeysDigest,
		SeedDigest:         c.SeedDigest,
		WorkloadDigest:     c.WorkloadDigest,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ratls: marshal config claims: %w", err)
	}
	return pkix.Extension{Id: OIDRATLSConfigClaims, Critical: false, Value: value}, nil
}

// UnmarshalConfigClaims decodes a DER-encoded config-claims extension value.
// It fails closed on an unknown version or a wrong-size digest: a verifier
// that cannot interpret the claims must not enforce policy against them
// (binding verification never needs to parse — docs/ratls.md).
func UnmarshalConfigClaims(der []byte) (*ConfigClaims, error) {
	var raw configClaimsASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("ratls: unmarshal config claims: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("ratls: %d trailing bytes after config-claims extension", len(rest))
	}
	if raw.Version != configClaimsVersion {
		return nil, fmt.Errorf("ratls: unsupported config-claims version %d (supported: %d)", raw.Version, configClaimsVersion)
	}
	for _, d := range [][]byte{raw.OperatorKeysDigest, raw.SeedDigest, raw.WorkloadDigest} {
		if len(d) != ClaimsDigestSize {
			return nil, fmt.Errorf("ratls: config-claims digest is %d bytes, want %d", len(d), ClaimsDigestSize)
		}
	}
	// encoding/asn1 tolerates extra elements inside the SEQUENCE and
	// non-minimal encodings; requiring the input to round-trip byte-exactly
	// keeps "parses as v1" equivalent to "is the one v1 encoding", so no two
	// distinct extension values yield the same ConfigClaims.
	reencoded, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("ratls: re-encode config claims: %w", err)
	}
	if !bytes.Equal(reencoded, der) {
		return nil, fmt.Errorf("ratls: config-claims extension is not the exact v%d encoding (%d bytes, canonical is %d)", configClaimsVersion, len(der), len(reencoded))
	}
	return &ConfigClaims{
		OperatorKeysDigest: raw.OperatorKeysDigest,
		SeedDigest:         raw.SeedDigest,
		WorkloadDigest:     raw.WorkloadDigest,
	}, nil
}

// HasSeed reports whether the claims attest a configured allowlist seed.
func (c *ConfigClaims) HasSeed() bool {
	return !bytes.Equal(c.SeedDigest, unsetDigest)
}

// HasWorkload reports whether the claims attest a workload digest.
func (c *ConfigClaims) HasWorkload() bool {
	return !bytes.Equal(c.WorkloadDigest, unsetDigest)
}

// ExtractConfigClaimsBytes returns the raw config-claims extension value from
// the certificate, or nil when the certificate carries none. The raw bytes are
// what the REPORTDATA preimage folds in — verification hashes exactly what the
// certificate carries, then parses only when claims semantics are needed.
func ExtractConfigClaimsBytes(cert *x509.Certificate) []byte {
	value, _ := configClaimsExtension(cert)
	return value
}

// configClaimsExtension returns the config-claims extension value and whether
// the extension is present at all. The distinction matters to VerifyCert: a
// present-but-empty extension is rejected there rather than silently treated
// as claims-free, so extension presence always implies a bound value.
func configClaimsExtension(cert *x509.Certificate) ([]byte, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDRATLSConfigClaims) {
			return ext.Value, true
		}
	}
	return nil, false
}
