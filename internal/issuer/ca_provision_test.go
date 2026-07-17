package issuer

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestProvisionCAGeneratesWithoutPeer(t *testing.T) {
	// The puller must never be called on the cold-start path.
	pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
		t.Fatal("puller called with no peer URL")
		return nil, nil
	}
	ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
		CommonName: "cold-start",
		Validity:   time.Hour,
	}, slog.Default(), pull)
	if err != nil {
		t.Fatalf("provisionCA: %v", err)
	}
	if adopted {
		t.Fatal("adopted=true with no peer URL; expected self-generate")
	}
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		t.Fatal("provisionCA returned no CA")
	}
	if ca.Cert.Subject.CommonName != "cold-start" {
		t.Fatalf("generated CA CN = %q, want cold-start", ca.Cert.Subject.CommonName)
	}
}

func TestProvisionCAAdoptsFromPeer(t *testing.T) {
	peerCA, err := NewCAWithCurve("peer-ca", time.Hour, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
		return &HandoffMaterial{
			CACert:           peerCA.Cert,
			CAKey:            peerCA.Key,
			AllowlistVersion: "9",
			Allowlist:        map[types.Digest]string{handoffTestDigest(): "dynamic/image"},
		}, nil
	}
	var restoredVersion string
	var restored map[types.Digest]string
	ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
		PeerURL:          "https://peer:8443",
		Measurements:     []string{"m"},
		OperatorKeysHash: handoffTestOperatorKeysHash,
		RestoreAllowlist: func(version string, digests map[types.Digest]string) error {
			restoredVersion, restored = version, digests
			return nil
		},
	}, slog.Default(), pull)
	if err != nil {
		t.Fatalf("provisionCA: %v", err)
	}
	if !adopted {
		t.Fatal("adopted=false; expected the peer's CA to be adopted")
	}
	if got, want := certutil.CertFingerprint(ca.Cert.Raw), certutil.CertFingerprint(peerCA.Cert.Raw); got != want {
		t.Fatalf("adopted CA fingerprint = %s, want peer's %s", got, want)
	}
	if !ca.Key.PublicKey.Equal(&peerCA.Key.PublicKey) {
		t.Fatal("adopted CA key does not match the peer's key")
	}
	if restoredVersion != "9" || restored[handoffTestDigest()] != "dynamic/image" {
		t.Fatalf("restored allowlist = version %q, digests %#v", restoredVersion, restored)
	}
}

func TestProvisionCAFailsClosedWhenPullErrors(t *testing.T) {
	// A configured peer that errors (unreachable past deadline, or a denial)
	// must fail closed, never self-generate.
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"unreachable", &HandoffStatusError{Status: 503}},
		{"denied", &HandoffStatusError{Status: 403}},
		{"deadline", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
				return nil, tc.err
			}
			ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
				PeerURL:          "https://peer:8443",
				Measurements:     []string{"m"},
				OperatorKeysHash: handoffTestOperatorKeysHash,
				RestoreAllowlist: func(string, map[types.Digest]string) error { return nil },
			}, slog.Default(), pull)
			if err == nil {
				t.Fatal("provisionCA succeeded despite a pull error; must fail closed")
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("error chain lost the pull cause: %v", err)
			}
			if ca != nil || adopted {
				t.Fatalf("fail-closed path returned a CA (ca=%v adopted=%v)", ca, adopted)
			}
		})
	}
}

func TestProvisionCAFailsClosedWhenAllowlistRestoreFails(t *testing.T) {
	peerCA, err := NewCA("Peer Mesh CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
		return &HandoffMaterial{
			CACert:           peerCA.Cert,
			CAKey:            peerCA.Key,
			AllowlistVersion: "9",
			Allowlist:        map[types.Digest]string{},
		}, nil
	}
	wantErr := errors.New("store unavailable")
	ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
		PeerURL:          "https://peer:8443",
		Measurements:     []string{"m"},
		OperatorKeysHash: handoffTestOperatorKeysHash,
		RestoreAllowlist: func(string, map[types.Digest]string) error { return wantErr },
	}, slog.Default(), pull)
	if !errors.Is(err, wantErr) {
		t.Fatalf("provisionCA error = %v, want %v", err, wantErr)
	}
	if ca != nil || adopted {
		t.Fatalf("failed restore returned ca=%v adopted=%v", ca, adopted)
	}
}

func TestProvisionCARejectsChainedOrMultiCertHandoff(t *testing.T) {
	// Adoption supports a single self-signed root; a parent cert or a
	// rotation bundle must be refused, not silently truncated.
	peerCA, err := NewCAWithCurve("peer-ca", time.Hour, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	otherCA, err := NewCAWithCurve("retiring-ca", time.Hour, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		material *HandoffMaterial
	}{
		{"parent cert", &HandoffMaterial{CACert: peerCA.Cert, CAKey: peerCA.Key, ParentCert: otherCA.Cert}},
		{"multi-cert bundle", &HandoffMaterial{CACert: peerCA.Cert, CAKey: peerCA.Key, Bundle: []*x509.Certificate{peerCA.Cert, otherCA.Cert}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
				return tc.material, nil
			}
			ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
				PeerURL:          "https://peer:8443",
				Measurements:     []string{"m"},
				OperatorKeysHash: handoffTestOperatorKeysHash,
				RestoreAllowlist: func(string, map[types.Digest]string) error { return nil },
			}, slog.Default(), pull)
			if err == nil {
				t.Fatal("provisionCA adopted a chained/multi-cert handoff; must refuse")
			}
			if ca != nil || adopted {
				t.Fatalf("refusal path returned a CA (ca=%v adopted=%v)", ca, adopted)
			}
		})
	}
}

func TestAdoptFromPeerRequiresMeasurements(t *testing.T) {
	// The real puller must refuse to adopt without a pinned measurement.
	_, err := adoptFromPeer(context.Background(), CAProvisionConfig{
		PeerURL:           "https://peer:8443",
		AttestationApiURL: "http://attest",
	}, slog.Default())
	if err == nil {
		t.Fatal("adoptFromPeer without measurements should error")
	}
}
