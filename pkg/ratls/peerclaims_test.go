package ratls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// caSignedLeafWithExt builds a leaf signed by a throwaway CA, optionally
// carrying a config-claims extension. It models the mesh steady state: a
// CDS-signed leaf whose claims are covered by the CA signature, not by a
// per-connection attestation binding.
func caSignedLeafWithExt(t *testing.T, ext []byte) *x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-mesh-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if ext != nil {
		leafTmpl.ExtraExtensions = []pkix.Extension{{Id: OIDRATLSConfigClaims, Value: ext}}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func connState(certs ...*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: certs}
}

func assertClaimsEqual(t *testing.T, got, want *ConfigClaims) {
	t.Helper()
	if got == nil {
		t.Fatal("got nil claims, want a value")
	}
	if !bytes.Equal(got.OperatorKeysDigest, want.OperatorKeysDigest) ||
		!bytes.Equal(got.SeedDigest, want.SeedDigest) ||
		!bytes.Equal(got.WorkloadDigest, want.WorkloadDigest) {
		t.Fatalf("claims mismatch:\n got  %+v\n want %+v", got, want)
	}
}

func TestPeerConfigClaims(t *testing.T) {
	claims, claimsExt := testClaims(t)

	// An RA-TLS self-attested leaf: claims folded into the evidence REPORTDATA.
	key, att := testKeyAndAttestation(t)
	ratlsDER, err := CreateAttestedCert(key, att, &CertOptions{ConfigClaims: claims})
	if err != nil {
		t.Fatal(err)
	}
	ratlsLeaf, err := x509.ParseCertificate(ratlsDER)
	if err != nil {
		t.Fatal(err)
	}

	_, _, bareLeaf := testAttestedCert(t, nil)

	t.Run("ra-tls leaf returns the bound claims", func(t *testing.T) {
		got, err := PeerConfigClaims(connState(ratlsLeaf))
		if err != nil {
			t.Fatal(err)
		}
		assertClaimsEqual(t, got, claims)
	})

	t.Run("ca-signed leaf returns the signed claims", func(t *testing.T) {
		got, err := PeerConfigClaims(connState(caSignedLeafWithExt(t, claimsExt)))
		if err != nil {
			t.Fatal(err)
		}
		assertClaimsEqual(t, got, claims)
	})

	t.Run("leaf without the extension returns nil, nil", func(t *testing.T) {
		got, err := PeerConfigClaims(connState(bareLeaf))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("want nil claims, got %+v", got)
		}
	})

	t.Run("malformed extension returns a parse error", func(t *testing.T) {
		bad := caSignedLeafWithExt(t, []byte{0x01, 0x02, 0x03})
		if _, err := PeerConfigClaims(connState(bad)); err == nil {
			t.Fatal("want a parse error, got nil")
		}
	})

	t.Run("nil connection state errors", func(t *testing.T) {
		if _, err := PeerConfigClaims(nil); err == nil {
			t.Fatal("want error, got nil")
		}
	})

	t.Run("no peer certificate errors", func(t *testing.T) {
		if _, err := PeerConfigClaims(&tls.ConnectionState{}); err == nil {
			t.Fatal("want error, got nil")
		}
	})
}
