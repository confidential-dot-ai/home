package getkubeconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// operatorPub is a throwaway operator public key PEM for the tests.
func operatorPub(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicKeyPEMFromPrivate(mustKeyPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func mustKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// attestedCert builds a genuine RA-TLS TDX cert carrying the given evidence
// envelope, bound to the cert's own key (as the real serving path does).
func attestedCert(t *testing.T, envelope types.AttestationEvidence) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	report, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeTDX, Report: report}
	der, err := ratls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// stubVerify replaces the in-process attestation-go verifier with one that
// returns the given result/error. Lets the tests drive verifyServerCert's
// post-verification logic deterministically without real hardware.
func stubVerify(t *testing.T, res *teetypes.VerificationResult, err error) {
	t.Helper()
	orig := verifyEnvelope
	verifyEnvelope = func([]byte, teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
		return res, err
	}
	t.Cleanup(func() { verifyEnvelope = orig })
}

// verifiedResult builds a passing VerificationResult carrying the given rtmr_3.
func verifiedResult(rtmr3 string) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformTDX,
		ReportDataMatch: teetypes.Ptr(true),
		Claims: teetypes.Claims{
			PlatformData: map[string]any{"rtmr_3": rtmr3},
		},
	}
}

func TestVerifyServerCertNoExtension(t *testing.T) {
	// A plain (non-RA-TLS) cert must be rejected before any verification.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	err = verifyServerCert(cert, operatorPub(t))
	if err == nil || !strings.Contains(err.Error(), "ratls:") {
		t.Fatalf("want RA-TLS extraction error, got %v", err)
	}
}

func TestVerifyServerCertRejectsBadReportData(t *testing.T) {
	// The verifier reports the quote is valid but report_data isn't bound to
	// the cert key — a MITM presenting someone else's quote. Must fail closed.
	res := verifiedResult("aa")
	res.ReportDataMatch = teetypes.Ptr(false)
	stubVerify(t, res, nil)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	err := verifyServerCert(cert, operatorPub(t))
	if err == nil || !strings.Contains(err.Error(), "report_data") {
		t.Fatalf("want report_data binding failure, got %v", err)
	}
}

func TestVerifyServerCertRejectsWrongRTMR3(t *testing.T) {
	// Genuine, key-bound quote, but rtmr_3 doesn't equal H(op_pub): the node
	// wasn't launched to trust this operator. Must fail closed.
	stubVerify(t, verifiedResult("00"), nil)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	err := verifyServerCert(cert, operatorPub(t))
	if err == nil || !strings.Contains(err.Error(), "RTMR[3] mismatch") {
		t.Fatalf("want RTMR[3] mismatch, got %v", err)
	}
}

func TestVerifyServerCertAccepts(t *testing.T) {
	// Genuine quote, bound to the cert key, rtmr_3 == H(op_pub): accept.
	pub := operatorPub(t)
	stubVerify(t, verifiedResult(expectedRTMR3(pub)), nil)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	if err := verifyServerCert(cert, pub); err != nil {
		t.Fatalf("want accept, got %v", err)
	}
}
