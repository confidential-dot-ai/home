// Package ratls implements RA-TLS (Remote Attestation TLS) for AMD SEV-SNP
// and Intel TDX. It provides X.509 certificate extensions that embed hardware
// attestation evidence, binding a TLS public key to a genuine TEE.
//
// The core idea: REPORTDATA in the attestation report contains hash(publicKey),
// cryptographically proving the key was generated inside the TEE. The full
// attestation report and VCEK certificate chain are embedded as a custom X.509
// extension, making the certificate verifiable against the hardware root of trust
// (AMD ARK → ASK → VCEK).
package ratls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// DefaultCertTTL is the default certificate lifetime used by both
// [CertOptions] and [ServerConfig] when no TTL is specified.
const DefaultCertTTL = 24 * time.Hour

const (
	// SNPReportSize is the exact size of an AMD SEV-SNP attestation report
	// (ATTESTATION_REPORT structure per AMD SEV-SNP ABI Specification).
	SNPReportSize = 0x4A0 // 1184 bytes

	// SNPMeasurementSize is the size of an SEV-SNP launch measurement
	// (SHA-384 digest = 48 bytes).
	SNPMeasurementSize = 48
)

// OID arc: 1.3.6.1.4.1.59888 is a placeholder PEN (Private Enterprise Number).
// Replace with an IANA-registered PEN when available.
//
//	1.3.6.1.4.1.59888.1   - Confidential TEE attestation arc
//	1.3.6.1.4.1.59888.1.1 - RA-TLS attestation extension
//	1.3.6.1.4.1.59888.1.2 - attestation-evidence audit digest (certutil)
//	1.3.6.1.4.1.59888.1.3 - RA-TLS config-claims extension (claims.go)
var (
	OIDConfidentialTEE  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1}
	OIDRATLSAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1, 1}
)

// TEEType identifies the confidential computing platform.
type TEEType int

const (
	// TEETypeSEVSNP identifies AMD SEV-SNP (Secure Encrypted Virtualization —
	// Secure Nested Paging) confidential VMs.
	TEETypeSEVSNP TEEType = 1

	// TEETypeTDX identifies Intel TDX (Trust Domain Extensions) confidential VMs.
	TEETypeTDX TEEType = 2
)

func (t TEEType) String() string {
	switch t {
	case TEETypeSEVSNP:
		return "AMD SEV-SNP"
	case TEETypeTDX:
		return "Intel TDX"
	default:
		return fmt.Sprintf("unknown(%d)", int(t))
	}
}

// Attestation holds TEE attestation evidence for embedding in an X.509 extension.
type Attestation struct {
	// TEEType identifies the platform (SEV-SNP or TDX).
	TEEType TEEType
	// Report is the raw hardware attestation report.
	// For SEV-SNP: 1184 bytes (AMD ATTESTATION_REPORT structure).
	// For TDX: variable-length TDREPORT/Quote.
	Report []byte
	// CertChain is the DER-encoded certificate chain.
	// For SEV-SNP: VCEK || ASK || ARK (concatenated DER certificates).
	// Not read by [VerifyAttestation], which delegates to the attestation-api;
	// the c8s verify CLI forwards an inline VCEK to its in-process verifier
	// instead of fetching it from AMD KDS when present.
	CertChain []byte

	// embedded is the parsed attestation-api envelope when Report carries a
	// full evidence envelope (e.g. az-snp, tdx). Populated by
	// UnmarshalExtension; nil means Report holds a raw bare-metal SNP report,
	// which verifyReport wraps in the "snp" envelope for /verify.
	embedded *types.AttestationEvidence
}

// attestationASN1 is the ASN.1 DER encoding structure.
//
//	TEEAttestation ::= SEQUENCE {
//	    teeType     INTEGER,
//	    report      OCTET STRING,
//	    certChain   OCTET STRING
//	}
type attestationASN1 struct {
	TEEType   int
	Report    []byte
	CertChain []byte
}

// MarshalExtension encodes the attestation as a DER-encoded X.509 extension.
func (a *Attestation) MarshalExtension() (pkix.Extension, error) {
	raw := attestationASN1{
		TEEType:   int(a.TEEType),
		Report:    a.Report,
		CertChain: a.CertChain,
	}

	value, err := asn1.Marshal(raw)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ratls: marshal attestation: %w", err)
	}

	return pkix.Extension{
		Id:       OIDRATLSAttestation,
		Critical: false,
		Value:    value,
	}, nil
}

// UnmarshalExtension decodes a DER-encoded attestation extension.
func UnmarshalExtension(der []byte) (*Attestation, error) {
	var raw attestationASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("ratls: unmarshal attestation: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("ratls: %d trailing bytes after attestation extension", len(rest))
	}

	teeType := TEEType(raw.TEEType)
	if teeType != TEETypeSEVSNP && teeType != TEETypeTDX {
		return nil, fmt.Errorf("%w: TEE type %d", ErrUnsupportedTEE, raw.TEEType)
	}

	att := &Attestation{
		TEEType:   teeType,
		Report:    raw.Report,
		CertChain: raw.CertChain,
	}

	// Auto-detect the JSON evidence envelope. SEV-SNP may carry either a
	// full envelope (az-snp) or raw report bytes (bare-metal), so probe
	// first and only normalize the raw SNP report shape when no envelope is
	// present; verification wraps the raw report in the "snp" envelope for
	// attestation-api /verify. TDX has no raw-bytes shape (no in-process Go
	// parser is carried; see verifyReport in verify.go), so an envelope
	// is required.
	embedded, err := parseEmbeddedEvidence(raw.Report)
	if err != nil {
		return nil, err
	}
	switch {
	case embedded != nil:
		att.embedded = embedded
	case teeType == TEETypeSEVSNP:
		report, err := NormalizeSEVSNPReport(raw.Report)
		if err != nil {
			return nil, err
		}
		att.Report = report
	case teeType == TEETypeTDX:
		return nil, fmt.Errorf("%w: TDX RA-TLS extension must carry a JSON attestation-api envelope; got raw bytes", ErrInvalidReport)
	}

	return att, nil
}

// EmbeddedEvidence returns the parsed attestation-api envelope (platform +
// platform-specific evidence) embedded in the certificate, and true, when the
// Report carries a JSON envelope rather than a raw hardware report (e.g. az-snp,
// where verification forwards the envelope to the attestation-api). It returns
// false when the Report holds a raw hardware report, which verification wraps
// in the "snp" envelope before forwarding.
func (a *Attestation) EmbeddedEvidence() (types.AttestationEvidence, bool) {
	if a.embedded == nil {
		return types.AttestationEvidence{}, false
	}
	return *a.embedded, true
}

// snpReportDataOffset is the byte offset of the 64-byte REPORTDATA field in an
// AMD SEV-SNP ATTESTATION_REPORT.
const snpReportDataOffset = 0x50

// ReportData returns the 64-byte REPORTDATA the attestation report commits, and
// true, for shapes c8s parses in-process (a raw SEV-SNP report). It returns
// (nil, false) for JSON-envelope evidence (az-snp, TDX), which c8s deliberately
// does not parse in-process (see verifyReport) — for those the REPORTDATA
// binding is proven by the attestation-api. Lets a caller fail fast when a
// report does not bind an expected REPORTDATA, without an attestation-api call.
func (a *Attestation) ReportData() ([]byte, bool) {
	if a.embedded != nil || a.TEEType != TEETypeSEVSNP || len(a.Report) < snpReportDataOffset+64 {
		return nil, false
	}
	return a.Report[snpReportDataOffset : snpReportDataOffset+64], true
}

// parseEmbeddedEvidence returns the parsed attestation-api envelope when
// raw is a JSON-encoded types.AttestationEvidence, or nil when raw is a raw
// hardware report. Callers use the non-nil return as a signal to take the
// online verification path instead of parsing raw as an SNP report.
func parseEmbeddedEvidence(raw []byte) (*types.AttestationEvidence, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, nil
	}
	var envelope types.AttestationEvidence
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return nil, fmt.Errorf("ratls: parse embedded attestation evidence: %w", err)
	}
	if envelope.Platform == "" || len(envelope.Evidence) == 0 {
		return nil, fmt.Errorf("%w: embedded attestation evidence missing platform or evidence", ErrInvalidReport)
	}
	return &envelope, nil
}

// ReportDataForKey computes the REPORTDATA value for binding a public key
// (and optional nonce) to a TEE attestation report. Uses SHA-384 (48 bytes),
// zero-padded to 64 bytes (the REPORTDATA field size for both SEV-SNP and TDX).
//
// If nonce is non-nil, REPORTDATA = SHA-384(pubkey || nonce), which prevents
// replay of attestation reports from previous sessions.
func ReportDataForKey(pub crypto.PublicKey, nonce []byte) ([64]byte, error) {
	var reportData [64]byte
	keyBytes, err := marshalPublicKey(pub)
	if err != nil {
		return reportData, fmt.Errorf("ratls: marshal public key: %w", err)
	}
	h := sha512.New384()
	h.Write(keyBytes)
	if len(nonce) > 0 {
		h.Write(nonce)
	}
	copy(reportData[:], h.Sum(nil))
	return reportData, nil
}

// ReportDataForKeyAndClaims computes the REPORTDATA value binding a public key
// plus a config-claims extension to a TEE attestation report (docs/ratls.md).
//
// With empty claims it is exactly [ReportDataForKey] — a claims-free cert stays
// byte-identical to a plain RA-TLS cert. With claims it is a domain-separated,
// length-framed transcript:
//
//	SHA-384(claimsDomainSep || framed(pubkey) || framed(claims) || framed(nonce))
//	  where framed(x) = uint64-BE(len(x)) || x
//
// The length framing (same construction as [ReportDataForKeyWithContext]) makes
// the preimage unambiguous: no two distinct (key, claims, nonce) triples can
// share a preimage, regardless of field lengths, so binding safety does not rest
// on any field being fixed-length or on the nonce's provenance. claims is the
// raw DER extension value exactly as carried on the certificate.
func ReportDataForKeyAndClaims(pub crypto.PublicKey, claims, nonce []byte) ([64]byte, error) {
	if len(claims) == 0 {
		return ReportDataForKey(pub, nonce)
	}

	var reportData [64]byte
	keyBytes, err := marshalPublicKey(pub)
	if err != nil {
		return reportData, fmt.Errorf("ratls: marshal public key: %w", err)
	}

	h := sha512.New384()
	h.Write(claimsDomainSep)
	for _, field := range [][]byte{keyBytes, claims, nonce} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		h.Write(size[:])
		h.Write(field)
	}
	copy(reportData[:], h.Sum(nil))
	return reportData, nil
}

// ReportDataForKeyWithContext binds an additional protocol context to a key
// and nonce. A non-empty context uses a domain-separated, length-framed
// transcript so fields cannot be re-split into an equivalent byte stream. An
// empty context deliberately preserves ReportDataForKey's established wire
// format.
func ReportDataForKeyWithContext(pub crypto.PublicKey, nonce, context []byte) ([64]byte, error) {
	if len(context) == 0 {
		return ReportDataForKey(pub, nonce)
	}

	var reportData [64]byte
	keyBytes, err := marshalPublicKey(pub)
	if err != nil {
		return reportData, fmt.Errorf("ratls: marshal public key: %w", err)
	}

	h := sha512.New384()
	h.Write([]byte("c8s-report-data-context-v1\x00"))
	for _, field := range [][]byte{keyBytes, nonce, context} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		h.Write(size[:])
		h.Write(field)
	}
	copy(reportData[:], h.Sum(nil))
	return reportData, nil
}

// marshalPublicKey encodes a public key to bytes for hashing into REPORTDATA.
// Supports ECDSA (PKIX DER) and ed25519 (raw 32 bytes).
func marshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return x509.MarshalPKIXPublicKey(k)
	case ed25519.PublicKey:
		return []byte(k), nil
	default:
		return nil, fmt.Errorf("ratls: unsupported key type: %T", pub)
	}
}

// publicKeyFromCert extracts and validates the public key from a certificate.
func publicKeyFromCert(cert *x509.Certificate) (crypto.PublicKey, error) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() {
			return nil, fmt.Errorf("ratls: unsupported ECDSA curve: %s", pub.Curve.Params().Name)
		}
		return pub, nil
	case ed25519.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("ratls: unsupported key type in certificate: %T", pub)
	}
}
