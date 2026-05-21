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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
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
//	1.3.6.1.4.1.59888.1   - Lunal TEE attestation arc
//	1.3.6.1.4.1.59888.1.1 - RA-TLS attestation extension
var (
	OIDLunalTEE         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1}
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
	// CertChain is the DER-encoded certificate chain for offline verification.
	// For SEV-SNP: VCEK || ASK || ARK (concatenated DER certificates).
	// If empty, the verifier must fetch certificates from AMD KDS online.
	CertChain []byte
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

	if teeType == TEETypeSEVSNP {
		_, hasEmbeddedEvidence, err := embeddedEvidence(raw.Report)
		if err != nil {
			return nil, err
		}
		if !hasEmbeddedEvidence {
			report, err := NormalizeSEVSNPReport(raw.Report)
			if err != nil {
				return nil, err
			}
			raw.Report = report
		}
	}

	return &Attestation{
		TEEType:   teeType,
		Report:    raw.Report,
		CertChain: raw.CertChain,
	}, nil
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
	hash := h.Sum(nil)
	copy(reportData[:], hash)
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
