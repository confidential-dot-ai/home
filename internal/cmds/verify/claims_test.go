package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

func testClaims(opKeys, seed byte) *ratls.ConfigClaims {
	return &ratls.ConfigClaims{
		OperatorKeysDigest: bytes.Repeat([]byte{opKeys}, ratls.ClaimsDigestSize),
		SeedDigest:         bytes.Repeat([]byte{seed}, ratls.ClaimsDigestSize),
		WorkloadDigest:     ratls.UnsetDigest(),
		WorkloadArgsDigest: ratls.UnsetDigest(),
	}
}

// claimsCert builds a self-signed cert carrying a (fake) SNP attestation
// extension plus a config-claims extension.
func claimsCert(t *testing.T, claims *ratls.ConfigClaims) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: make([]byte, ratls.SNPReportSize)}
	var opts *ratls.CertOptions
	if claims != nil {
		opts = &ratls.CertOptions{ConfigClaims: claims}
	}
	der, err := ratls.CreateAttestedCert(key, att, opts)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestEvidenceFromCertFoldsClaims(t *testing.T) {
	claims := testClaims(0xAB, 0xCD)
	cert := claimsCert(t, claims)

	ev, err := evidenceFromCert(cert, "test")
	if err != nil {
		t.Fatal(err)
	}
	if ev.configClaims == nil || !bytes.Equal(ev.configClaims.OperatorKeysDigest, claims.OperatorKeysDigest) || !bytes.Equal(ev.configClaims.SeedDigest, claims.SeedDigest) {
		t.Fatalf("configClaims = %+v, want %+v", ev.configClaims, claims)
	}
	if ev.claimsErr != nil {
		t.Fatalf("claimsErr = %v", ev.claimsErr)
	}

	want, err := ratls.ReportDataForKeyAndClaims(cert.PublicKey, ratls.ExtractConfigClaimsBytes(cert), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.erd, want[:48]) {
		t.Fatalf("erd = %x, want folded anchor %x", ev.erd, want[:48])
	}

	plain, err := ratls.ReportDataForKey(cert.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ev.erd, plain[:48]) {
		t.Fatal("erd ignored the claims extension")
	}
}

func TestApplyClaimsPolicy(t *testing.T) {
	claims := testClaims(0xAB, 0xCD)
	otherDigest := bytes.Repeat([]byte{0xEE}, ratls.ClaimsDigestSize)

	cases := []struct {
		name         string
		ev           *evidence
		policy       *ratls.VerifyPolicy
		opKeys       operatorKeysReport
		wantVerified bool
	}{
		{"claims, no pins", &evidence{configClaims: claims}, &ratls.VerifyPolicy{}, operatorKeysReport{}, true},
		{"both pins match", &evidence{configClaims: claims}, &ratls.VerifyPolicy{OperatorKeysDigest: claims.OperatorKeysDigest, SeedDigest: claims.SeedDigest}, operatorKeysReport{}, true},
		{"operator-keys pin mismatch", &evidence{configClaims: claims}, &ratls.VerifyPolicy{OperatorKeysDigest: otherDigest}, operatorKeysReport{}, false},
		{"seed pin mismatch", &evidence{configClaims: claims}, &ratls.VerifyPolicy{SeedDigest: otherDigest}, operatorKeysReport{}, false},
		{"pin without claims", &evidence{}, &ratls.VerifyPolicy{OperatorKeysDigest: claims.OperatorKeysDigest}, operatorKeysReport{}, false},
		{"seed pin without claims", &evidence{}, &ratls.VerifyPolicy{SeedDigest: claims.SeedDigest}, operatorKeysReport{}, false},
		{"unparseable claims", &evidence{claimsErr: errTest("unsupported config-claims version 9")}, &ratls.VerifyPolicy{}, operatorKeysReport{}, false},
		{"served list matches attested", &evidence{configClaims: claims}, &ratls.VerifyPolicy{}, operatorKeysReport{digest: claims.OperatorKeysDigest}, true},
		{"served list contradicts attested", &evidence{configClaims: claims}, &ratls.VerifyPolicy{}, operatorKeysReport{digest: otherDigest}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oc := Outcome{Verified: true}
			applyClaimsPolicy(&oc, tc.ev, tc.policy, tc.opKeys)
			if oc.Verified != tc.wantVerified {
				t.Fatalf("Verified = %t (error %q), want %t", oc.Verified, oc.Error, tc.wantVerified)
			}
			if !tc.wantVerified && oc.Error == "" {
				t.Fatal("failed verdict carries no reason")
			}
			if tc.ev.configClaims != nil && (oc.OperatorKeysAttestedDigest == "" || oc.SeedAttestedDigest == "") {
				t.Fatal("attested digests not surfaced")
			}
		})
	}

	t.Run("no-seed sentinel surfaces as none", func(t *testing.T) {
		oc := Outcome{Verified: true}
		noSeed := &ratls.ConfigClaims{
			OperatorKeysDigest: claims.OperatorKeysDigest,
			SeedDigest:         ratls.UnsetDigest(),
			WorkloadDigest:     ratls.UnsetDigest(),
			WorkloadArgsDigest: ratls.UnsetDigest(),
		}
		applyClaimsPolicy(&oc, &evidence{configClaims: noSeed}, &ratls.VerifyPolicy{}, operatorKeysReport{})
		if !oc.Verified || oc.SeedAttestedDigest != "none (no seed configured)" {
			t.Fatalf("Verified=%t SeedAttestedDigest=%q", oc.Verified, oc.SeedAttestedDigest)
		}
		if oc.WorkloadAttestedDigest != "" {
			t.Fatalf("unset workload digest surfaced: %q", oc.WorkloadAttestedDigest)
		}
	})

	t.Run("never promotes a failed verdict", func(t *testing.T) {
		oc := Outcome{Verified: false, Error: "hardware chain invalid"}
		applyClaimsPolicy(&oc, &evidence{configClaims: claims}, &ratls.VerifyPolicy{OperatorKeysDigest: claims.OperatorKeysDigest}, operatorKeysReport{})
		if oc.Verified {
			t.Fatal("claims policy promoted a failed verification")
		}
		if oc.Error != "hardware chain invalid" {
			t.Fatalf("original failure reason was overwritten: %q", oc.Error)
		}
	})
}

func TestExpectedSeedDigestFlags(t *testing.T) {
	if _, err := expectedSeedDigest(config{allowlistSeed: "a", allowlistSeedDigest: "b"}); err == nil {
		t.Fatal("mutually exclusive flags accepted")
	}
	if _, err := expectedSeedDigest(config{allowlistSeedDigest: "zz"}); err == nil {
		t.Fatal("malformed hex digest accepted")
	}
	digest, err := expectedSeedDigest(config{allowlistSeedDigest: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32))})
	if err != nil || !bytes.Equal(digest, bytes.Repeat([]byte{0xAB}, 32)) {
		t.Fatalf("digest = %x, err = %v", digest, err)
	}
	if d, err := expectedSeedDigest(config{}); err != nil || d != nil {
		t.Fatalf("no flags: digest=%x err=%v, want nil/nil", d, err)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
