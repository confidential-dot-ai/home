package ratls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// fakeSNPReport creates a minimal fake SEV-SNP attestation report (1184 bytes)
// with the given reportData at the correct offset. This is for testing only —
// real reports are signed by AMD hardware.
func fakeSNPReport(reportData [64]byte) []byte {
	// AMD SEV-SNP report is exactly 0x4A0 (1184) bytes.
	// REPORT_DATA is at offset 0x50, 64 bytes.
	// MEASUREMENT is at offset 0x90, 48 bytes.
	// See: AMD SEV-SNP ABI Specification, Table 21.
	report := make([]byte, SNPReportSize)

	// Version (offset 0x00): must be >= 2 for SNP
	report[0] = 0x02

	// POLICY (offset 0x08): 8 bytes, little-endian
	// Bit 16 = SMT allowed; bit 17 = reserved/must-be-one. Minimum: 0x30000
	// (ABI major=0, minor=0, SMT=1)
	report[0x08] = 0x00
	report[0x09] = 0x00
	report[0x0A] = 0x03 // SMT bit set

	// REPORT_DATA (offset 0x50): 64 bytes
	copy(report[0x50:0x90], reportData[:])

	// MEASUREMENT (offset 0x90): 48 bytes
	for i := 0; i < 48; i++ {
		report[0x90+i] = byte(i) // deterministic fake measurement
	}

	return report
}

// fakeHCLEnvelope builds the AKS Hyper-V HCL envelope around a raw SNP report.
func fakeHCLEnvelope(report []byte, trailing int) []byte {
	env := make([]byte, 32+len(report)+trailing)
	copy(env[:4], "HCLA")
	binary.LittleEndian.PutUint32(env[4:8], 1)
	binary.LittleEndian.PutUint32(env[8:12], uint32(len(report)+trailing))
	copy(env[32:], report)
	return env
}

// testKeyAndAttestation generates a keypair and matching attestation for tests.
func testKeyAndAttestation(t *testing.T) (*ecdsa.PrivateKey, *Attestation) {
	t.Helper()
	key, reportData, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	att := &Attestation{
		TEEType: TEETypeSEVSNP,
		Report:  fakeSNPReport(reportData),
	}
	return key, att
}

// testAttestedCert generates a keypair, attestation, and parsed certificate.
func testAttestedCert(t *testing.T, opts *CertOptions) (*ecdsa.PrivateKey, *Attestation, *x509.Certificate) {
	t.Helper()
	key, att := testKeyAndAttestation(t)
	certDER, err := CreateAttestedCert(key, att, opts)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return key, att, cert
}

// requireRATLSExtension asserts that the certificate contains the RA-TLS
// attestation extension.
func requireRATLSExtension(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDRATLSAttestation) {
			return
		}
	}
	t.Error("RA-TLS attestation extension not found in certificate")
}

func TestExtensionMarshalUnmarshal(t *testing.T) {
	reportData := [64]byte{1, 2, 3, 4}
	report := fakeSNPReport(reportData)
	certChain := []byte("fake-cert-chain")

	att := &Attestation{
		TEEType:   TEETypeSEVSNP,
		Report:    report,
		CertChain: certChain,
	}

	ext, err := att.MarshalExtension()
	if err != nil {
		t.Fatalf("MarshalExtension: %v", err)
	}

	if !ext.Id.Equal(OIDRATLSAttestation) {
		t.Errorf("OID = %v, want %v", ext.Id, OIDRATLSAttestation)
	}
	if ext.Critical {
		t.Error("extension should not be critical")
	}

	got, err := UnmarshalExtension(ext.Value)
	if err != nil {
		t.Fatalf("UnmarshalExtension: %v", err)
	}

	if got.TEEType != TEETypeSEVSNP {
		t.Errorf("TEEType = %d, want %d", got.TEEType, TEETypeSEVSNP)
	}
	if !bytes.Equal(got.Report, report) {
		t.Error("Report mismatch")
	}
	if !bytes.Equal(got.CertChain, certChain) {
		t.Error("CertChain mismatch")
	}
}

func TestUnmarshalExtensionInvalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"garbage", []byte{0xFF, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalExtension(tt.data)
			if err == nil {
				t.Error("expected error for invalid data")
			}
		})
	}
}

func TestUnmarshalUnknownTEEType(t *testing.T) {
	att := &attestationASN1{
		TEEType:   99,
		Report:    []byte("report"),
		CertChain: []byte("chain"),
	}
	data, err := marshalASN1(att)
	if err != nil {
		t.Fatal(err)
	}

	_, err = UnmarshalExtension(data)
	if err == nil {
		t.Error("expected error for unknown TEE type")
	}
}

func TestReportDataForKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rd1, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Should be deterministic.
	rd2, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rd1 != rd2 {
		t.Error("ReportDataForKey not deterministic")
	}

	// First 48 bytes should be SHA-384, rest should be zero.
	keyBytes, _ := marshalPublicKey(&key.PublicKey)
	expected := sha512.Sum384(keyBytes)
	if !bytes.Equal(rd1[:48], expected[:]) {
		t.Error("REPORTDATA does not match SHA-384 of public key")
	}
	for i := 48; i < 64; i++ {
		if rd1[i] != 0 {
			t.Errorf("REPORTDATA[%d] = %d, want 0 (padding)", i, rd1[i])
		}
	}
}

func TestReportDataForKeyWithNonce(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	nonce := []byte("test-nonce-32-bytes-of-randomnes")

	rdWithNonce, err := ReportDataForKey(&key.PublicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}

	rdWithoutNonce, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	if rdWithNonce == rdWithoutNonce {
		t.Error("nonce did not change REPORTDATA")
	}

	// Same nonce should produce same result.
	rdWithNonce2, err := ReportDataForKey(&key.PublicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if rdWithNonce != rdWithNonce2 {
		t.Error("same nonce produced different REPORTDATA")
	}

	// Different nonce should produce different result.
	rdDiffNonce, err := ReportDataForKey(&key.PublicKey, []byte("different-nonce-32bytes-of-rand!"))
	if err != nil {
		t.Fatal(err)
	}
	if rdWithNonce == rdDiffNonce {
		t.Error("different nonces produced same REPORTDATA")
	}
}

func TestReportDataForKeyWithContext(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("challenge")
	contextA := []byte("operator-key-set-a")

	legacy, err := ReportDataForKey(&key.PublicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := ReportDataForKeyWithContext(&key.PublicKey, nonce, nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty != legacy {
		t.Fatal("empty context changed the established REPORTDATA format")
	}

	withA, err := ReportDataForKeyWithContext(&key.PublicKey, nonce, contextA)
	if err != nil {
		t.Fatal(err)
	}
	withAAgain, err := ReportDataForKeyWithContext(&key.PublicKey, nonce, contextA)
	if err != nil {
		t.Fatal(err)
	}
	if withA != withAAgain {
		t.Fatal("contextual REPORTDATA is not deterministic")
	}
	if withA == legacy {
		t.Fatal("non-empty context did not change REPORTDATA")
	}
	withB, err := ReportDataForKeyWithContext(&key.PublicKey, nonce, []byte("operator-key-set-b"))
	if err != nil {
		t.Fatal(err)
	}
	if withA == withB {
		t.Fatal("different contexts produced the same REPORTDATA")
	}
	for i := sha512.Size384; i < len(withA); i++ {
		if withA[i] != 0 {
			t.Fatalf("REPORTDATA[%d] = %d, want zero padding", i, withA[i])
		}
	}
}

func TestGenerateKeyPair(t *testing.T) {
	key, reportData, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if key == nil {
		t.Fatal("key is nil")
	}

	expected, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reportData != expected {
		t.Error("reportData does not match key")
	}
}

func TestCreateAttestedCert(t *testing.T) {
	_, _, cert := testAttestedCert(t, &CertOptions{
		TTL:      1 * time.Hour,
		DNSNames: []string{"test.local"},
	})

	requireRATLSExtension(t, cert)

	if cert.Subject.CommonName != "RA-TLS Workload" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "RA-TLS Workload")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "test.local" {
		t.Errorf("DNSNames = %v, want [test.local]", cert.DNSNames)
	}
}

func TestCreateAttestedCertDefaultOpts(t *testing.T) {
	_, _, cert := testAttestedCert(t, nil)

	actualDuration := cert.NotAfter.Sub(cert.NotBefore)
	if actualDuration < DefaultCertTTL-time.Minute || actualDuration > DefaultCertTTL+time.Minute {
		t.Errorf("cert duration = %v, want ~%v", actualDuration, DefaultCertTTL)
	}
}

func TestTEETypeString(t *testing.T) {
	tests := []struct {
		t    TEEType
		want string
	}{
		{TEETypeSEVSNP, "AMD SEV-SNP"},
		{TEETypeTDX, "Intel TDX"},
		{TEEType(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.t.String(); got != tt.want {
			t.Errorf("TEEType(%d).String() = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestSentinelErrors(t *testing.T) {
	t.Run("ErrNotAttested", func(t *testing.T) {
		// Certificate without RA-TLS extension.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatal(err)
		}

		_, err = VerifyCert(cert, nil, nil)
		if !errors.Is(err, ErrNotAttested) {
			t.Errorf("got %v, want errors.Is ErrNotAttested", err)
		}
	})

	t.Run("ErrUnsupportedTEE", func(t *testing.T) {
		att := &attestationASN1{
			TEEType:   99,
			Report:    []byte("report"),
			CertChain: []byte("chain"),
		}
		data, err := marshalASN1(att)
		if err != nil {
			t.Fatal(err)
		}

		_, err = UnmarshalExtension(data)
		if !errors.Is(err, ErrUnsupportedTEE) {
			t.Errorf("got %v, want errors.Is ErrUnsupportedTEE", err)
		}
	})

	t.Run("ErrUnsupportedTEE_parseTEEType", func(t *testing.T) {
		_, err := parseTEEType("unknown-platform")
		if !errors.Is(err, ErrUnsupportedTEE) {
			t.Errorf("got %v, want errors.Is ErrUnsupportedTEE", err)
		}
	})
}

// marshalASN1 helper for tests.
func marshalASN1(v *attestationASN1) ([]byte, error) {
	return asn1.Marshal(*v)
}

func TestNormalizeSEVSNPReportHCLEnvelope(t *testing.T) {
	reportData := [64]byte{1, 2, 3}
	report := fakeSNPReport(reportData)
	envelope := fakeHCLEnvelope(report, 128)

	normalized, err := NormalizeSEVSNPReport(envelope)
	if err != nil {
		t.Fatalf("NormalizeSEVSNPReport failed: %v", err)
	}
	if !bytes.Equal(normalized, report) {
		t.Fatal("normalized report mismatch")
	}
}

func TestUnmarshalExtensionHCLEnvelope(t *testing.T) {
	reportData := [64]byte{1, 2, 3}
	report := fakeSNPReport(reportData)
	att := &attestationASN1{
		TEEType: int(TEETypeSEVSNP),
		Report:  fakeHCLEnvelope(report, 128),
	}
	data, err := marshalASN1(att)
	if err != nil {
		t.Fatal(err)
	}

	result, err := UnmarshalExtension(data)
	if err != nil {
		t.Fatalf("UnmarshalExtension failed for HCL envelope: %v", err)
	}
	if !bytes.Equal(result.Report, report) {
		t.Fatal("unmarshaled report mismatch")
	}
}

func TestUnmarshalExtensionReportSize(t *testing.T) {
	t.Run("truncated SNP report", func(t *testing.T) {
		att := &attestationASN1{
			TEEType: int(TEETypeSEVSNP),
			Report:  make([]byte, 100), // way too short
		}
		data, err := marshalASN1(att)
		if err != nil {
			t.Fatal(err)
		}
		_, err = UnmarshalExtension(data)
		if !errors.Is(err, ErrInvalidReport) {
			t.Errorf("got %v, want errors.Is ErrInvalidReport", err)
		}
	})

	t.Run("oversized SNP report", func(t *testing.T) {
		att := &attestationASN1{
			TEEType: int(TEETypeSEVSNP),
			Report:  make([]byte, SNPReportSize+1),
		}
		data, err := marshalASN1(att)
		if err != nil {
			t.Fatal(err)
		}
		_, err = UnmarshalExtension(data)
		if !errors.Is(err, ErrInvalidReport) {
			t.Errorf("got %v, want errors.Is ErrInvalidReport", err)
		}
	})

	t.Run("correct size SNP report", func(t *testing.T) {
		reportData := [64]byte{1, 2, 3}
		att := &attestationASN1{
			TEEType: int(TEETypeSEVSNP),
			Report:  fakeSNPReport(reportData),
		}
		data, err := marshalASN1(att)
		if err != nil {
			t.Fatal(err)
		}
		result, err := UnmarshalExtension(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Report) != SNPReportSize {
			t.Errorf("report size = %d, want %d", len(result.Report), SNPReportSize)
		}
	})

	t.Run("TDX raw bytes are rejected", func(t *testing.T) {
		// TDX extensions carry the full attestation-api evidence
		// envelope (JSON), not raw quote bytes — verifyEnvelopeOnline
		// reads the envelope back and forwards it to attestation-api. Refuse
		// raw bytes at parse time so a wire-format regression fails
		// loudly instead of silently taking the "empty embedded" path.
		att := &attestationASN1{
			TEEType: int(TEETypeTDX),
			Report:  []byte("variable-length-tdx-quote"),
		}
		data, err := marshalASN1(att)
		if err != nil {
			t.Fatal(err)
		}
		_, err = UnmarshalExtension(data)
		if !errors.Is(err, ErrInvalidReport) {
			t.Errorf("got %v, want errors.Is ErrInvalidReport", err)
		}
	})

	t.Run("TDX evidence envelope is accepted", func(t *testing.T) {
		// The TDX shape: RA-TLS extension Report field carries a JSON
		// AttestationEvidence produced by RATLSEvidence(resp) for a
		// platform="tdx" AttestResponse.
		att := &attestationASN1{
			TEEType: int(TEETypeTDX),
			Report:  []byte(`{"platform":"tdx","evidence":{"quote":"AAAA"}}`),
		}
		data, err := marshalASN1(att)
		if err != nil {
			t.Fatal(err)
		}
		result, err := UnmarshalExtension(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.TEEType != TEETypeTDX {
			t.Errorf("TEEType = %v, want TDX", result.TEEType)
		}
		embedded, ok := result.EmbeddedEvidence()
		if !ok || embedded.Platform != "tdx" {
			t.Errorf("EmbeddedEvidence() ok=%v platform=%q, want ok=true platform=tdx", ok, embedded.Platform)
		}
	})
}

func TestSNPReportSizeConstant(t *testing.T) {
	if SNPReportSize != 0x4A0 {
		t.Errorf("SNPReportSize = 0x%X, want 0x4A0", SNPReportSize)
	}
	if SNPReportSize != 1184 {
		t.Errorf("SNPReportSize = %d, want 1184", SNPReportSize)
	}
}

func TestSNPMeasurementSizeConstant(t *testing.T) {
	if SNPMeasurementSize != 48 {
		t.Errorf("SNPMeasurementSize = %d, want 48", SNPMeasurementSize)
	}
}

// embeddedEnvelopeCert builds an RA-TLS certificate whose attestation extension
// carries an AttestationEvidence envelope for the given platform. Returns the
// parsed cert and the SHA-384(pubkey) that the attestation-api would expect to
// see bound through the report.
func embeddedEnvelopeCert(t *testing.T, platform types.Platform, evidence json.RawMessage) (*x509.Certificate, [64]byte) {
	t.Helper()
	key, expectedReportData, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := json.Marshal(types.AttestationEvidence{Platform: string(platform), Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	teeType := TEETypeSEVSNP
	if platform == types.PlatformTdx {
		teeType = TEETypeTDX
	}
	certDER, err := CreateAttestedCert(key, &Attestation{TEEType: teeType, Report: embedded}, nil)
	if err != nil {
		t.Fatalf("CreateAttestedCert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, expectedReportData
}

// embeddedAzureCert builds an RA-TLS certificate whose attestation extension
// carries an az-snp envelope (the post-PR-98 wire shape).
func embeddedAzureCert(t *testing.T) (*x509.Certificate, [64]byte) {
	t.Helper()
	return embeddedEnvelopeCert(t, types.PlatformAzSnp, json.RawMessage(`{"hcl_report":"fake","tpm_quote":{"message":"fake"}}`))
}

// verifyResponse is a minimal builder for an attestation-api /verify
// response. Tests mutate the returned map then JSON-encode it.
func verifyResponse(measurement []byte) map[string]any {
	result := map[string]any{
		"platform":          string(types.PlatformAzSnp),
		"signature_valid":   true,
		"report_data_match": true,
		"claims":            map[string]any{},
	}
	if measurement != nil {
		result["claims"] = map[string]any{
			"launch_digest": hex.EncodeToString(measurement),
		}
	}
	return map[string]any{"result": result}
}

// newMockedVerifySrv returns a mocked attestation-api whose /verify always
// responds with body.
func newMockedVerifySrv(t *testing.T, body any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
}

func TestVerifyCertEmbeddedAzureEvidenceUsesAttestationApi(t *testing.T) {
	key, expectedReportData, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	evidenceJSON := json.RawMessage(`{"hcl_report":"fake","tpm_quote":{"message":"fake"}}`)
	embedded, err := json.Marshal(types.AttestationEvidence{
		Platform: string(types.PlatformAzSnp),
		Evidence: evidenceJSON,
	})
	if err != nil {
		t.Fatal(err)
	}

	certDER, err := CreateAttestedCert(key, &Attestation{TEEType: TEETypeSEVSNP, Report: embedded}, nil)
	if err != nil {
		t.Fatalf("CreateAttestedCert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	var sawVerify bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			t.Fatalf("path = %s, want /verify", r.URL.Path)
		}
		var req types.VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode verify request: %v", err)
		}
		sawVerify = true
		// attestation-api wants platform at the top level and Evidence as the
		// platform-specific evidence, not a nested AttestationEvidence envelope.
		if req.Platform != string(types.PlatformAzSnp) {
			t.Fatalf("platform = %q, want az-snp", req.Platform)
		}
		if string(req.Evidence) != string(evidenceJSON) {
			t.Fatalf("evidence = %s, want the platform-specific evidence %s (not a nested envelope)", req.Evidence, evidenceJSON)
		}
		if req.Params == nil || req.Params.ExpectedReportData == nil {
			t.Fatal("missing expected report data")
		}
		// az-snp binds via a TPM quote whose nonce is the 48-byte SHA-384
		// digest, so exactly those 48 bytes must be sent — not the zero-padded
		// 64-byte form, which fails attestation-api with a nonce-length error.
		if got := req.Params.ExpectedReportData.Bytes(); !bytes.Equal(got, expectedReportData[:sha512.Size384]) {
			t.Fatalf("expected_report_data = %x (%d bytes), want %x (%d bytes)", got, len(got), expectedReportData[:sha512.Size384], sha512.Size384)
		}

		resp := map[string]any{
			"result": map[string]any{
				"platform":          string(types.PlatformAzSnp),
				"signature_valid":   true,
				"report_data_match": true,
				"claims": map[string]any{
					"launch_digest": hex.EncodeToString(measurement),
					"platform_data": map[string]any{"source": "test"},
				},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	result, err := VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL: srv.URL,
		Measurements:      [][]byte{measurement},
	}, nil)
	if err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	if !sawVerify {
		t.Fatal("attestation-api /verify was not called")
	}
	if !bytes.Equal(result.ReportData[:], expectedReportData[:]) {
		t.Fatalf("ReportData = %x, want %x", result.ReportData, expectedReportData)
	}
	if !bytes.Equal(result.Measurement[:], measurement) {
		t.Fatalf("Measurement = %x, want %x", result.Measurement, measurement)
	}
}

func TestVerifyCertEmbeddedTDXEvidenceEnforcesMRTD(t *testing.T) {
	cert, expectedReportData := embeddedEnvelopeCert(t, types.PlatformTdx, json.RawMessage(`{"quote":"fake"}`))
	mrtd := bytes.Repeat([]byte{0x42}, sha512.Size384)

	var observed types.VerifyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&observed); err != nil {
			t.Fatalf("decode verify request: %v", err)
		}
		resp := verifyResponse(mrtd)
		resp["result"].(map[string]any)["platform"] = string(types.PlatformTdx)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	result, err := VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL: srv.URL,
		Measurements:      [][]byte{mrtd},
		MinTCBVersion:     1,
	}, nil)
	if err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	if observed.Platform != string(types.PlatformTdx) {
		t.Fatalf("platform = %q, want tdx", observed.Platform)
	}
	if observed.Params == nil || observed.Params.ExpectedReportData == nil {
		t.Fatal("missing expected report data")
	}
	if got := observed.Params.ExpectedReportData.Bytes(); !bytes.Equal(got, expectedReportData[:]) {
		t.Fatalf("expected_report_data = %x, want %x", got, expectedReportData)
	}
	if observed.Params.MinTcb != nil {
		t.Fatal("min_tcb must not be sent on the TDX path")
	}
	if result.TEEType != TEETypeTDX {
		t.Fatalf("TEEType = %v, want TDX", result.TEEType)
	}
	if !bytes.Equal(result.ReportData[:], expectedReportData[:]) {
		t.Fatalf("ReportData = %x, want %x", result.ReportData, expectedReportData)
	}
	if !bytes.Equal(result.Measurement[:], mrtd) {
		t.Fatalf("Measurement = %x, want MRTD %x", result.Measurement, mrtd)
	}

	wrongMRTD := bytes.Repeat([]byte{0x99}, sha512.Size384)
	_, err = VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL: srv.URL,
		Measurements:      [][]byte{wrongMRTD},
	}, nil)
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("wrong MRTD: got %v, want ErrPolicyViolation", err)
	}
}

// TestVerifyCertEmbeddedGcpSnpEvidenceUsesAttestationApi mirrors the az-snp
// online path for GKE SEV-SNP: a gcp-snp evidence envelope passes the platform
// gate and is forwarded to the attestation-api /verify endpoint, not rejected
// as an unsupported TEE. (Evidence unwrapping is covered by the az-snp test.)
func TestVerifyCertEmbeddedGcpSnpEvidenceUsesAttestationApi(t *testing.T) {
	cert, _ := embeddedEnvelopeCert(t, types.PlatformGcpSnp, json.RawMessage(`{"attestation_report":"fake"}`))

	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	var observed types.VerifyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&observed); err != nil {
			t.Fatalf("decode verify request: %v", err)
		}
		if err := json.NewEncoder(w).Encode(verifyResponse(measurement)); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	if _, err := VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL: srv.URL,
		Measurements:      [][]byte{measurement},
	}, nil); err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	if observed.Platform != string(types.PlatformGcpSnp) {
		t.Fatalf("platform = %q, want gcp-snp", observed.Platform)
	}
}

// TestVerifyCertEmbeddedAzureNegativePaths covers the online-verification
// failure modes. Each case mutates either the policy or the mocked /verify
// response and asserts that the verifier maps it to the expected sentinel
// error. A bug that flipped any of these to a "pass" would be silent
// downgrade of the attestation policy.
func TestVerifyCertEmbeddedAzureNegativePaths(t *testing.T) {
	cert, _ := embeddedAzureCert(t)
	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	allowedMeasurements := [][]byte{measurement}

	t.Run("signature_valid=false maps to ErrSignatureInvalid", func(t *testing.T) {
		resp := verifyResponse(measurement)
		resp["result"].(map[string]any)["signature_valid"] = false
		srv := newMockedVerifySrv(t, resp)
		defer srv.Close()
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: allowedMeasurements}, nil)
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("got %v, want ErrSignatureInvalid", err)
		}
	})

	t.Run("report_data_match=nil maps to ErrKeyBinding", func(t *testing.T) {
		resp := verifyResponse(measurement)
		delete(resp["result"].(map[string]any), "report_data_match")
		srv := newMockedVerifySrv(t, resp)
		defer srv.Close()
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: allowedMeasurements}, nil)
		if !errors.Is(err, ErrKeyBinding) {
			t.Fatalf("got %v, want ErrKeyBinding", err)
		}
	})

	t.Run("report_data_match=false maps to ErrKeyBinding", func(t *testing.T) {
		resp := verifyResponse(measurement)
		resp["result"].(map[string]any)["report_data_match"] = false
		srv := newMockedVerifySrv(t, resp)
		defer srv.Close()
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: allowedMeasurements}, nil)
		if !errors.Is(err, ErrKeyBinding) {
			t.Fatalf("got %v, want ErrKeyBinding", err)
		}
	})

	t.Run("empty attestation-api URL rejects embedded evidence", func(t *testing.T) {
		_, err := VerifyCert(cert, &VerifyPolicy{Measurements: allowedMeasurements}, nil)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("got %v, want ErrInvalidReport", err)
		}
	})

	t.Run("launch_digest missing with pinned measurements is rejected", func(t *testing.T) {
		srv := newMockedVerifySrv(t, verifyResponse(nil))
		defer srv.Close()
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: allowedMeasurements}, nil)
		if !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("got %v, want ErrPolicyViolation", err)
		}
	})

	t.Run("launch_digest not in allowed set is rejected", func(t *testing.T) {
		other := bytes.Repeat([]byte{0x99}, SNPMeasurementSize)
		srv := newMockedVerifySrv(t, verifyResponse(other))
		defer srv.Close()
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: allowedMeasurements}, nil)
		if !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("got %v, want ErrPolicyViolation", err)
		}
	})

	t.Run("launch_digest not hex is rejected", func(t *testing.T) {
		resp := verifyResponse(measurement)
		resp["result"].(map[string]any)["claims"] = map[string]any{"launch_digest": "not-hex"}
		srv := newMockedVerifySrv(t, resp)
		defer srv.Close()
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: allowedMeasurements}, nil)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("got %v, want ErrInvalidReport", err)
		}
	})

	t.Run("launch_digest wrong length is rejected", func(t *testing.T) {
		resp := verifyResponse(measurement)
		resp["result"].(map[string]any)["claims"] = map[string]any{
			"launch_digest": hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		}
		srv := newMockedVerifySrv(t, resp)
		defer srv.Close()
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: allowedMeasurements}, nil)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("got %v, want ErrInvalidReport", err)
		}
	})

	t.Run("attestation-api HTTP 500 surfaces an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: allowedMeasurements}, nil)
		if err == nil {
			t.Fatal("expected error from 500 response")
		}
	})

	t.Run("AttestationVerifyTimeout bounds the call", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(verifyResponse(measurement))
		}))
		defer srv.Close()
		start := time.Now()
		_, err := VerifyCert(cert, &VerifyPolicy{
			AttestationApiURL:        srv.URL,
			Measurements:             allowedMeasurements,
			AttestationVerifyTimeout: 25 * time.Millisecond,
		}, nil)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("expected timeout error")
		}
		if elapsed > 150*time.Millisecond {
			t.Fatalf("verify took %s, expected <150ms (timeout not enforced)", elapsed)
		}
	})

	t.Run("MinTCBVersion is forwarded as unpacked components", func(t *testing.T) {
		var observed types.VerifyRequest
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(&observed); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(verifyResponse(measurement))
		}))
		defer srv.Close()
		// Packed layout: bootloader=0x11, tee=0x22, snp=0x33 (byte 6),
		// microcode=0x44 (byte 7). Reserved bytes stay zero.
		packed := uint64(0x44_33_00_00_00_00_22_11)
		_, err := VerifyCert(cert, &VerifyPolicy{
			AttestationApiURL: srv.URL,
			Measurements:      allowedMeasurements,
			MinTCBVersion:     packed,
		}, nil)
		if err != nil {
			t.Fatalf("VerifyCert: %v", err)
		}
		if observed.Params == nil || observed.Params.MinTcb == nil {
			t.Fatal("MinTcb was not forwarded to /verify")
		}
		want := types.MinTcb{Bootloader: 0x11, Tee: 0x22, Snp: 0x33, Microcode: 0x44}
		if *observed.Params.MinTcb != want {
			t.Fatalf("MinTcb = %+v, want %+v", *observed.Params.MinTcb, want)
		}
	})

	t.Run("az-tdx evidence is rejected by online verifier", func(t *testing.T) {
		key, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := json.Marshal(types.AttestationEvidence{
			Platform: string(types.PlatformAzTdx),
			Evidence: json.RawMessage(`{"any":"shape"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		certDER, err := CreateAttestedCert(key, &Attestation{TEEType: TEETypeSEVSNP, Report: embedded}, nil)
		if err != nil {
			t.Fatalf("CreateAttestedCert: %v", err)
		}
		tdxCert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		srv := newMockedVerifySrv(t, verifyResponse(measurement))
		defer srv.Close()
		_, err = VerifyCert(tdxCert, &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: allowedMeasurements}, nil)
		if !errors.Is(err, ErrUnsupportedTEE) {
			t.Fatalf("got %v, want ErrUnsupportedTEE", err)
		}
	})
}

// TestVerifyCertBareSNPUsesAttestationApi covers the bare-metal SNP shape:
// the RA-TLS extension carries a raw report, which the verifier must wrap in
// the "snp" evidence envelope for attestation-api /verify. There is no
// in-process verification, so without an AttestationApiURL the verifier must
// fail closed rather than fall back.
func TestVerifyCertBareSNPUsesAttestationApi(t *testing.T) {
	key, att, cert := testAttestedCert(t, nil)
	expectedReportData, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := att.Report
	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)

	t.Run("raw report is wrapped in the snp envelope", func(t *testing.T) {
		var observed types.VerifyRequest
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(&observed); err != nil {
				t.Fatalf("decode verify request: %v", err)
			}
			resp := verifyResponse(measurement)
			resp["result"].(map[string]any)["platform"] = string(types.PlatformSnp)
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Fatalf("encode response: %v", err)
			}
		}))
		defer srv.Close()

		result, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: [][]byte{measurement}}, nil)
		if err != nil {
			t.Fatalf("VerifyCert: %v", err)
		}
		if observed.Platform != string(types.PlatformSnp) {
			t.Fatalf("platform = %q, want snp", observed.Platform)
		}
		var inner struct {
			AttestationReport string `json:"attestation_report"`
		}
		if err := json.Unmarshal(observed.Evidence, &inner); err != nil {
			t.Fatalf("decode snp evidence: %v", err)
		}
		sent, err := base64.StdEncoding.DecodeString(inner.AttestationReport)
		if err != nil {
			t.Fatalf("decode attestation_report: %v", err)
		}
		if !bytes.Equal(sent, report) {
			t.Fatal("attestation_report does not round-trip the raw report")
		}
		if observed.Params == nil || observed.Params.ExpectedReportData == nil {
			t.Fatal("missing expected report data")
		}
		if got := observed.Params.ExpectedReportData.Bytes(); !bytes.Equal(got, expectedReportData[:]) {
			t.Fatalf("expected_report_data = %x, want %x", got, expectedReportData[:])
		}
		if !bytes.Equal(result.Measurement[:], measurement) {
			t.Fatalf("Measurement = %x, want %x", result.Measurement, measurement)
		}
	})

	t.Run("no attestation-api URL fails closed", func(t *testing.T) {
		_, err := VerifyCert(cert, &VerifyPolicy{Measurements: [][]byte{measurement}}, nil)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("got %v, want ErrInvalidReport", err)
		}
	})
}
