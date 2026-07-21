package ratls

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func testClaims(t *testing.T) (*ConfigClaims, []byte) {
	t.Helper()
	claims := &ConfigClaims{
		OperatorKeysDigest: bytes.Repeat([]byte{0xAB}, ClaimsDigestSize),
		SeedDigest:         bytes.Repeat([]byte{0xCD}, ClaimsDigestSize),
		WorkloadDigest:     UnsetDigest(),
		WorkloadArgsDigest: UnsetDigest(),
	}
	ext, err := claims.MarshalExtension()
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return claims, ext.Value
}

// newCapturingVerifySrv mocks the attestation-api /verify with a passing
// verdict for measurement, recording the expected_report_data each request
// carried into erd.
func newCapturingVerifySrv(t *testing.T, measurement []byte, erd *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode verify request: %v", err)
		}
		if req.Params != nil && req.Params.ExpectedReportData != nil {
			*erd = req.Params.ExpectedReportData.Bytes()
		}
		resp := verifyResponse(measurement)
		resp["result"].(map[string]any)["platform"] = string(types.PlatformSnp)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
}

func TestConfigClaimsMarshalUnmarshal(t *testing.T) {
	claims, value := testClaims(t)

	got, err := UnmarshalConfigClaims(value)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(got.OperatorKeysDigest, claims.OperatorKeysDigest) ||
		!bytes.Equal(got.SeedDigest, claims.SeedDigest) ||
		!bytes.Equal(got.WorkloadDigest, claims.WorkloadDigest) {
		t.Fatalf("round trip mismatch: %+v != %+v", got, claims)
	}
	if !got.HasSeed() {
		t.Fatal("HasSeed = false for a real seed digest")
	}
	if got.HasWorkload() {
		t.Fatal("HasWorkload = true for the unset sentinel")
	}

	// The provider hashes one marshal and CreateAttestedCert embeds another;
	// they are only interchangeable if marshaling is deterministic (audit
	// invariant 1 in docs/ratls.md).
	ext2, err := claims.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, ext2.Value) {
		t.Fatal("MarshalExtension is not deterministic")
	}
}

func TestConfigClaimsSentinels(t *testing.T) {
	claims := &ConfigClaims{
		OperatorKeysDigest: bytes.Repeat([]byte{1}, ClaimsDigestSize),
		SeedDigest:         UnsetDigest(),
		WorkloadDigest:     UnsetDigest(),
		WorkloadArgsDigest: UnsetDigest(),
	}
	ext, err := claims.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalConfigClaims(ext.Value)
	if err != nil {
		t.Fatal(err)
	}
	if got.HasSeed() || got.HasWorkload() {
		t.Fatal("sentinel digests reported as set")
	}

	// The sentinel must be corruption-proof: mutating a returned copy must
	// not change what later callers receive.
	mutated := UnsetDigest()
	mutated[0] = 0xFF
	if !bytes.Equal(UnsetDigest(), make([]byte, ClaimsDigestSize)) {
		t.Fatal("UnsetDigest sentinel was corrupted through a returned copy")
	}
}

func TestConfigClaimsMarshalRejectsWrongDigestSize(t *testing.T) {
	full := bytes.Repeat([]byte{1}, ClaimsDigestSize)
	for name, c := range map[string]*ConfigClaims{
		"operator-keys":  {OperatorKeysDigest: []byte{1, 2}, SeedDigest: full, WorkloadDigest: full, WorkloadArgsDigest: full},
		"seed":           {OperatorKeysDigest: full, SeedDigest: []byte{1, 2}, WorkloadDigest: full, WorkloadArgsDigest: full},
		"workload":       {OperatorKeysDigest: full, SeedDigest: full, WorkloadDigest: []byte{1, 2}, WorkloadArgsDigest: full},
		"workload-args":  {OperatorKeysDigest: full, SeedDigest: full, WorkloadDigest: full, WorkloadArgsDigest: []byte{1, 2}},
	} {
		if _, err := c.MarshalExtension(); err == nil {
			t.Errorf("%s: marshal accepted a wrong-size digest", name)
		}
	}
}

func TestUnmarshalConfigClaimsInvalid(t *testing.T) {
	_, value := testClaims(t)

	full := bytes.Repeat([]byte{1}, ClaimsDigestSize)
	wrongVersion, err := asn1.Marshal(configClaimsASN1{Version: configClaimsVersion + 1, OperatorKeysDigest: full, SeedDigest: full, WorkloadDigest: full, WorkloadArgsDigest: full})
	if err != nil {
		t.Fatal(err)
	}
	shortDigest, err := asn1.Marshal(configClaimsASN1{Version: configClaimsVersion, OperatorKeysDigest: []byte{1, 2}, SeedDigest: full, WorkloadDigest: full, WorkloadArgsDigest: full})
	if err != nil {
		t.Fatal(err)
	}

	for name, der := range map[string][]byte{
		"garbage":        []byte("not asn1"),
		"trailing bytes": append(append([]byte{}, value...), 0x00),
		"wrong version":  wrongVersion,
		"short digest":   shortDigest,
	} {
		if _, err := UnmarshalConfigClaims(der); err == nil {
			t.Errorf("%s: unmarshal accepted invalid claims", name)
		}
	}
}

func TestReportDataForKeyAndClaims(t *testing.T) {
	key, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := &key.PublicKey
	_, claimsValue := testClaims(t)

	plain, err := ReportDataForKey(pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := ReportDataForKeyAndClaims(pub, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain != empty {
		t.Fatal("empty claims must reproduce the pre-claims binding")
	}

	folded, err := ReportDataForKeyAndClaims(pub, claimsValue, nil)
	if err != nil {
		t.Fatal(err)
	}
	if folded == plain {
		t.Fatal("claims did not change the binding")
	}

	// Domain separation (docs/ratls.md): evidence bound to nonce == claimsValue
	// must not verify as a claims binding.
	asNonce, err := ReportDataForKey(pub, claimsValue)
	if err != nil {
		t.Fatal(err)
	}
	if folded == asNonce {
		t.Fatal("claims binding collides with a nonce binding over the same bytes")
	}
}

func TestCreateAttestedCertWithClaims(t *testing.T) {
	claims, wantValue := testClaims(t)
	key, att := testKeyAndAttestation(t)
	certDER, err := CreateAttestedCert(key, att, &CertOptions{ConfigClaims: claims})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	requireRATLSExtension(t, cert)
	got := ExtractConfigClaimsBytes(cert)
	if !bytes.Equal(got, wantValue) {
		t.Fatalf("carried claims = %x, want %x", got, wantValue)
	}
}

func TestExtractConfigClaimsBytesAbsent(t *testing.T) {
	_, _, cert := testAttestedCert(t, nil)
	if got := ExtractConfigClaimsBytes(cert); got != nil {
		t.Fatalf("claims bytes = %x on a claims-free cert, want nil", got)
	}
}

// TestSelfSignedProviderBindsClaims proves the provisioning side folds the
// exact carried claims bytes into the REPORTDATA the attester is asked to
// bind — the whole scheme rests on this equality (docs/ratls.md).
func TestSelfSignedProviderBindsClaims(t *testing.T) {
	claims, _ := testClaims(t)
	var boundHex string
	p := &SelfSignedProvider{
		Platform: "sev-snp",
		AttestFunc: func(_ context.Context, customData string) (string, error) {
			boundHex = customData
			return string(fakeSNPReport([64]byte{})), nil
		},
		Opts: &CertOptions{ConfigClaims: claims},
	}
	tlsCert, _, err := p.Provision(context.Background())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	leaf := tlsCert.Leaf
	carried := ExtractConfigClaimsBytes(leaf)
	if len(carried) == 0 {
		t.Fatal("provisioned cert carries no claims extension")
	}
	want, err := ReportDataForKeyAndClaims(leaf.PublicKey, carried, nil)
	if err != nil {
		t.Fatal(err)
	}
	if boundHex != hex.EncodeToString(want[:]) {
		t.Fatalf("attested REPORTDATA %s does not fold the carried claims (want %x)", boundHex, want[:])
	}
}

func TestVerifyCertConfigClaimsPins(t *testing.T) {
	claims, _ := testClaims(t)
	key, att := testKeyAndAttestation(t)
	certDER, err := CreateAttestedCert(key, att, &CertOptions{ConfigClaims: claims})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	_, _, bareCert := testAttestedCert(t, nil)

	// The pin checks run before any attestation-api call, so an unreachable
	// URL proves they fail closed locally (docs/ratls.md: a pin can only
	// reject).
	policy := func(opKeys, seed, workload []byte) *VerifyPolicy {
		return &VerifyPolicy{AttestationApiURL: "http://127.0.0.1:1", OperatorKeysDigest: opKeys, SeedDigest: seed, WorkloadDigest: workload}
	}
	wrong := bytes.Repeat([]byte{0xEE}, ClaimsDigestSize)

	t.Run("operator-keys pin mismatch fails closed", func(t *testing.T) {
		if _, err := VerifyCert(cert, policy(wrong, nil, nil), nil); !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("got %v, want ErrPolicyViolation", err)
		}
	})

	t.Run("seed pin mismatch fails closed", func(t *testing.T) {
		if _, err := VerifyCert(cert, policy(nil, wrong, nil), nil); !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("got %v, want ErrPolicyViolation", err)
		}
	})

	t.Run("workload pin against unset sentinel fails closed", func(t *testing.T) {
		if _, err := VerifyCert(cert, policy(nil, nil, wrong), nil); !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("got %v, want ErrPolicyViolation", err)
		}
	})

	t.Run("pin with no claims fails closed", func(t *testing.T) {
		if _, err := VerifyCert(bareCert, policy(claims.OperatorKeysDigest, nil, nil), nil); !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("got %v, want ErrPolicyViolation", err)
		}
	})

	t.Run("VerifyAttestation cannot enforce a pin", func(t *testing.T) {
		if _, err := VerifyAttestation(&key.PublicKey, att, policy(claims.OperatorKeysDigest, nil, nil), nil); !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("got %v, want ErrPolicyViolation", err)
		}
	})
}

// TestVerifyCertFoldsClaims asserts the verifier recomputes the folded
// binding for a claims-bearing cert — the expected_report_data sent to the
// attestation-api must be SHA-384(pubkey || sep || claims), not the plain key
// binding — and that matching pins pass through to verification.
func TestVerifyCertFoldsClaims(t *testing.T) {
	claims, claimsValue := testClaims(t)
	key, att := testKeyAndAttestation(t)
	certDER, err := CreateAttestedCert(key, att, &CertOptions{ConfigClaims: claims})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	want, err := ReportDataForKeyAndClaims(&key.PublicKey, claimsValue, nil)
	if err != nil {
		t.Fatal(err)
	}

	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	var observedERD []byte
	srv := newCapturingVerifySrv(t, measurement, &observedERD)
	defer srv.Close()

	_, err = VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL:  srv.URL,
		Measurements:       [][]byte{measurement},
		OperatorKeysDigest: claims.OperatorKeysDigest,
		SeedDigest:         claims.SeedDigest,
	}, nil)
	if err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	if !bytes.Equal(observedERD, want[:]) {
		t.Fatalf("expected_report_data = %x, want folded %x", observedERD, want[:])
	}
}
