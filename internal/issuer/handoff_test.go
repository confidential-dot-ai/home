package issuer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/crypto/cryptobyte"
)

type testKeyProvider struct{ pub *ecdsa.PublicKey }

const handoffTestOperatorKeysHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func handoffTestDigest() types.Digest {
	digest, err := types.ParseDigest("sha256:" + strings.Repeat("1", 64))
	if err != nil {
		panic(err)
	}
	return digest
}

func (p testKeyProvider) PublicKey(string) (*ecdsa.PublicKey, error) {
	return p.pub, nil
}

type staticHandoffEARSource struct{ ear string }

func (s staticHandoffEARSource) Current() (string, error) {
	return strings.TrimSpace(s.ear), nil
}

func snapshotFromCA(ca *CA) func() (CASnapshot, bool) {
	return func() (CASnapshot, bool) {
		return CASnapshot{
			Cert:             ca.Cert,
			Key:              ca.Key,
			AllowlistVersion: "17",
			Allowlist: map[types.Digest]string{
				handoffTestDigest(): "registry.example/dynamic:latest",
			},
		}, true
	}
}

func TestAttestedHandoffTransfersCAKeyToAllowedReplica(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	bm := NewBundleManager(time.Hour, "", "default/mesh/ca-bundle", slog.Default())
	bm.SetInitial(ca.Cert)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Bundle:              bm,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)

	clientDeps := HandoffClientDeps{
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
	}
	material, err := RequestHandoff(context.Background(), clientDeps, srv.URL, requesterEAR, requesterHandoffKey, srv.Client())
	if err != nil {
		t.Fatalf("requestHandoff failed: %v", err)
	}

	if got, want := certutil.CertFingerprint(material.CACert.Raw), certutil.CertFingerprint(ca.Cert.Raw); got != want {
		t.Fatalf("handoff CA fingerprint = %s, want %s", got, want)
	}
	if err := ValidateCAKeyPair(material.CACert, material.CAKey); err != nil {
		t.Fatalf("handoff keypair invalid: %v", err)
	}
	if !material.CAKey.PublicKey.Equal(&ca.Key.PublicKey) {
		t.Fatalf("handoff CA key does not match active key")
	}
	if len(material.Bundle) != 1 {
		t.Fatalf("handoff bundle count = %d, want 1", len(material.Bundle))
	}
	if material.AllowlistVersion != "17" || material.Allowlist[handoffTestDigest()] != "registry.example/dynamic:latest" {
		t.Fatalf("handoff allowlist snapshot = version %q, digests %#v", material.AllowlistVersion, material.Allowlist)
	}
}

func TestHandoffBundleStartsWithHandedOffActiveCA(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	rotated, err := NewCAWithParent("Rotated Mesh CA", time.Hour, elliptic.P384(), ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the small rotation window where /ca has published the next
	// bundle before the active signer pointer is swapped.
	bm := NewBundleManager(time.Hour, "", "default/mesh/ca-bundle", slog.Default())
	bm.SetWithCurrent(rotated.Cert, []*x509.Certificate{ca.Cert})

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Bundle:              bm,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)

	clientDeps := HandoffClientDeps{
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
	}
	material, err := RequestHandoff(context.Background(), clientDeps, srv.URL, requesterEAR, requesterHandoffKey, srv.Client())
	if err != nil {
		t.Fatalf("requestHandoff failed: %v", err)
	}
	if len(material.Bundle) != 2 {
		t.Fatalf("handoff bundle count = %d, want active + published next CA", len(material.Bundle))
	}
	if !material.CACert.Equal(ca.Cert) || !material.Bundle[0].Equal(ca.Cert) {
		t.Fatalf("handoff bundle first CA must match handed-off active signer")
	}
	if !material.Bundle[1].Equal(rotated.Cert) {
		t.Fatalf("handoff bundle should retain the published next CA after active signer")
	}
}

func TestHandoffRejectsRequesterKeyNotBoundToEAR(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	attackerKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := encodeB64(priv.PublicKey().Bytes())
	sig, err := signHandoffMessage(attackerKey, mustHandoffRequestMessage(t, requesterEAR, pub))
	if err != nil {
		t.Fatal(err)
	}
	req := HandoffRequest{
		EAR:       requesterEAR,
		PublicKey: pub,
		Signature: sig,
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Post(srv.URL+"/handoff", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("handoff status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestHandoffRejectsUnallowedRequesterMeasurement(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEAR(t, tokenKey, "allowed_measurement")
	requesterHandoffKey := handoffTestKey(t)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "other_measurement", requesterHandoffKey)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := encodeB64(priv.PublicKey().Bytes())
	sig, err := signHandoffMessage(requesterHandoffKey, mustHandoffRequestMessage(t, requesterEAR, pub))
	if err != nil {
		t.Fatal(err)
	}
	req := HandoffRequest{
		EAR:       requesterEAR,
		PublicKey: pub,
		Signature: sig,
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Post(srv.URL+"/handoff", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("handoff status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestRequestHandoffRequiresMeasurementAllowlist(t *testing.T) {
	_, err := RequestHandoff(context.Background(), HandoffClientDeps{}, "http://127.0.0.1", "ear", handoffTestKey(t), http.DefaultClient)
	if err == nil {
		t.Fatal("expected missing measurement allowlist error")
	}
}

func TestRequestHandoffReturnsTypedStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	deps := HandoffClientDeps{
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
	}
	_, err := RequestHandoff(context.Background(), deps, srv.URL, "ear", handoffTestKey(t), srv.Client())
	var statusErr *HandoffStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("RequestHandoff error = %v, want *HandoffStatusError", err)
	}
	if statusErr.Status != http.StatusNotFound {
		t.Fatalf("HandoffStatusError.Status = %d, want %d", statusErr.Status, http.StatusNotFound)
	}
}

func TestUnwrapHandoffResponseRejectsBadNonceLength(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	issuerKey := handoffTestKey(t)
	requesterKey := handoffTestKey(t)
	issuerEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", issuerKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterKey)

	requesterECDH, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requesterPub := encodeB64(requesterECDH.PublicKey().Bytes())
	peerECDH, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerPub := encodeB64(peerECDH.PublicKey().Bytes())
	sig, err := signHandoffMessage(issuerKey, mustHandoffResponseMessage(t, requesterEAR, issuerEAR, requesterPub, peerPub))
	if err != nil {
		t.Fatal(err)
	}

	clientDeps := HandoffClientDeps{
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
	}
	_, err = UnwrapHandoffResponse(HandoffResponse{
		IssuerEAR:  issuerEAR,
		PublicKey:  peerPub,
		Signature:  sig,
		Nonce:      encodeB64([]byte{1, 2, 3}),
		Ciphertext: encodeB64([]byte("ciphertext")),
	}, clientDeps, requesterEAR, requesterPub, requesterECDH)
	if err == nil || !strings.Contains(err.Error(), "handoff nonce length") {
		t.Fatalf("error = %v, want nonce length validation", err)
	}
}

func TestHandoffTranscriptsAreDomainSeparated(t *testing.T) {
	transcripts := map[string][]byte{
		handoffRequestSignaturePurpose:  mustHandoffRequestMessage(t, "requester-ear", "requester-pub"),
		handoffResponseSignaturePurpose: mustHandoffResponseMessage(t, "requester-ear", "issuer-ear", "requester-pub", "issuer-pub"),
		handoffPayloadKeyPurpose:        mustHandoffTranscript(t, handoffPayloadKeyPurpose, "requester-ear", "issuer-ear"),
		handoffPayloadAADPurpose:        mustHandoffAAD(t, "requester-ear", "issuer-ear", "requester-pub", "issuer-pub"),
	}

	seen := map[string]string{}
	for purpose, transcript := range transcripts {
		components := decodeHandoffTranscript(t, transcript)
		if components[0] != handoffProtocolLabel {
			t.Fatalf("%s transcript protocol label = %q, want %q", purpose, components[0], handoffProtocolLabel)
		}
		if components[1] != purpose {
			t.Fatalf("%s transcript purpose label = %q, want %q", purpose, components[1], purpose)
		}
		key := string(transcript)
		if previous, ok := seen[key]; ok {
			t.Fatalf("%s transcript duplicates %s: %x", purpose, previous, transcript)
		}
		seen[key] = purpose
	}
}

func TestHandoffTranscriptLengthPrefixesAmbiguousFields(t *testing.T) {
	left := mustHandoffTranscript(t, "purpose", "a", "b\nc")
	right := mustHandoffTranscript(t, "purpose", "a\nb", "c")
	if bytes.Equal(left, right) {
		t.Fatalf("length-prefixed transcripts collided: %x", left)
	}

	if got := decodeHandoffTranscript(t, left); !slices.Equal(got, []string{handoffProtocolLabel, "purpose", "a", "b\nc"}) {
		t.Fatalf("left transcript components = %#v", got)
	}
}

func TestHandoffReloadsIssuerEARFromFile(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR1 := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	activeEAR2 := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	earSource := &AtomicHandoffEAR{}
	earSource.Set(activeEAR1)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: allowed,
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeHandoffKey,
		EARSource:           earSource,
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)

	if got := handoffResponseIssuerEAR(t, srv, requesterEAR, requesterHandoffKey); got != activeEAR1 {
		t.Fatalf("issuer EAR before refresh = %q, want %q", got, activeEAR1)
	}
	earSource.Set(activeEAR2)
	if got := handoffResponseIssuerEAR(t, srv, requesterEAR, requesterHandoffKey); got != activeEAR2 {
		t.Fatalf("issuer EAR after refresh = %q, want %q", got, activeEAR2)
	}
}

func handoffResponseIssuerEAR(t *testing.T, srv *httptest.Server, requesterEAR string, signer *ecdsa.PrivateKey) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := encodeB64(priv.PublicKey().Bytes())
	sig, err := signHandoffMessage(signer, mustHandoffRequestMessage(t, requesterEAR, pub))
	if err != nil {
		t.Fatal(err)
	}
	req := HandoffRequest{
		EAR:       requesterEAR,
		PublicKey: pub,
		Signature: sig,
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Post(srv.URL+"/handoff", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("handoff status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var hr HandoffResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		t.Fatal(err)
	}
	return hr.IssuerEAR
}

func decodeHandoffTranscript(t *testing.T, transcript []byte) []string {
	t.Helper()
	input := cryptobyte.String(transcript)
	var components []string
	for !input.Empty() {
		var n uint32
		if !input.ReadUint32(&n) {
			t.Fatalf("truncated transcript length prefix: %x", []byte(input))
		}
		var component []byte
		if !input.ReadBytes(&component, int(n)) {
			t.Fatalf("transcript component length %d exceeds remaining %d", n, len(input))
		}
		components = append(components, string(component))
	}
	if len(components) < 2 {
		t.Fatalf("transcript has %d components, want at least 2", len(components))
	}
	return components
}

func mustHandoffRequestMessage(t *testing.T, ear, requesterPub string) []byte {
	t.Helper()
	message, err := handoffRequestMessage(ear, requesterPub)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func mustHandoffResponseMessage(t *testing.T, requesterEAR, issuerEAR, requesterPub, issuerPub string) []byte {
	t.Helper()
	message, err := handoffResponseMessage(requesterEAR, issuerEAR, requesterPub, issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func mustHandoffAAD(t *testing.T, requesterEAR, issuerEAR, requesterPub, issuerPub string) []byte {
	t.Helper()
	aad, err := handoffAAD(requesterEAR, issuerEAR, requesterPub, issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	return aad
}

func mustHandoffTranscript(t *testing.T, purpose string, fields ...string) []byte {
	t.Helper()
	transcript, err := handoffTranscript(purpose, fields...)
	if err != nil {
		t.Fatal(err)
	}
	return transcript
}

func handoffTestEAR(t *testing.T, tokenKey *ecdsa.PrivateKey, measurement string) string {
	t.Helper()
	return handoffTestEARWithKey(t, tokenKey, measurement, nil)
}

func handoffTestEARWithKey(t *testing.T, tokenKey *ecdsa.PrivateKey, measurement string, teeKey *ecdsa.PrivateKey) string {
	t.Helper()
	now := time.Now().Unix()
	claims := map[string]any{
		earclaims.IssuedAt:         now,
		earclaims.ExpiresAt:        now + 3600,
		earclaims.OperatorKeysHash: handoffTestOperatorKeysHash,
		earclaims.Submods: map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.LaunchDigest: measurement,
			},
		},
	}
	if teeKey != nil {
		claims[earclaims.TEEPublicKey] = teePubKeyB64(t, teeKey)
	}
	return signJWT(t, tokenKey, claims)
}

func TestHandoffEARExpiryReadsExpClaim(t *testing.T) {
	tokenKey := handoffTestKey(t)
	teeKey := handoffTestKey(t)
	token := handoffTestEARWithKey(t, tokenKey, "m", teeKey)

	got, err := HandoffEARExpiry(token)
	if err != nil {
		t.Fatalf("handoffEARExpiry: %v", err)
	}
	delta := time.Until(got).Seconds()
	if delta < 3500 || delta > 3700 {
		t.Errorf("expiry delta = %.0fs, want ~3600s", delta)
	}
}

func TestHandoffEARExpiryRejectsMalformed(t *testing.T) {
	for name, token := range map[string]string{
		"two-parts":   "header.claims",
		"bad-base64":  "header.!!!.sig",
		"missing-exp": signJWT(t, handoffTestKey(t), map[string]any{earclaims.IssuedAt: time.Now().Unix()}),
		"bad-claims":  "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig",
	} {
		if _, err := HandoffEARExpiry(token); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestHandoffEARExpiryUpdaterMarksInvalidSourceNegative(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handoffEARExpirySeconds.Set(3600)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	RunHandoffEARExpiryUpdater(ctx, staticHandoffEARSource{ear: "bad.token"}, time.Hour, logger)

	if got := testutil.ToFloat64(handoffEARExpirySeconds); got >= 0 {
		t.Fatalf("handoff EAR expiry gauge = %v, want negative on invalid source", got)
	}
}

func TestNewHandoffHandlerValidatesInputs(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	bm := NewBundleManager(time.Hour, "", "ca-bundle", slog.Default())
	bm.SetInitial(ca.Cert)

	signer := handoffTestKey(t)
	src := staticHandoffEARSource{ear: "ear-token"}

	baseDeps := func(allowed map[string]bool) HandoffDeps {
		return HandoffDeps{
			Logger:              slog.Default(),
			KeyProvider:         kp,
			AllowedMeasurements: allowed,
			OperatorKeysHash:    handoffTestOperatorKeysHash,
			Bundle:              bm,
			Signer:              signer,
			EARSource:           src,
			Snapshot:            snapshotFromCA(ca),
		}
	}

	nilSigner := baseDeps(map[string]bool{"m": true})
	nilSigner.Signer = nil
	if _, err := NewHandoffHandler(nilSigner); err == nil {
		t.Error("expected error when signer key is nil")
	}
	nilSource := baseDeps(map[string]bool{"m": true})
	nilSource.EARSource = nil
	if _, err := NewHandoffHandler(nilSource); err == nil {
		t.Error("expected error when EAR source is nil")
	}

	if _, err := NewHandoffHandler(baseDeps(nil)); err == nil {
		t.Error("expected error when handoff measurement allowlist is empty")
	}
	missingPolicy := baseDeps(map[string]bool{"m": true})
	missingPolicy.OperatorKeysHash = ""
	if _, err := NewHandoffHandler(missingPolicy); err == nil {
		t.Error("expected error when operator-key policy hash is empty")
	}

	// An EAR source that hasn't bootstrapped yet is accepted at construction
	// time — the handler returns 503 at request time. This decouples
	// CDS startup from handoff EAR readiness.
	notReady := baseDeps(map[string]bool{"m": true})
	notReady.EARSource = erroringHandoffEARSource{}
	hh, err := NewHandoffHandler(notReady)
	if err != nil {
		t.Fatalf("newHandoffHandler must accept a not-yet-ready EAR source: %v", err)
	}
	if hh.signer == nil || hh.earSource == nil {
		t.Fatal("handoffHandler missing signer or EAR source")
	}

	hh, err = NewHandoffHandler(baseDeps(map[string]bool{"m": true}))
	if err != nil {
		t.Fatalf("newHandoffHandler: %v", err)
	}
	if hh.signer == nil || hh.earSource == nil {
		t.Fatal("handoffHandler missing signer or EAR source")
	}
}

func TestCheckOperatorPolicyRejectsMissingAndMismatch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims *EARClaims
	}{
		{name: "missing claim", claims: &EARClaims{}},
		{name: "malformed claim", claims: &EARClaims{OperatorKeysHash: "bad"}},
		{name: "different policy", claims: &EARClaims{OperatorKeysHash: strings.Repeat("b", 64)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkOperatorPolicy(tc.claims, handoffTestOperatorKeysHash, "requester")
			var validationErr *TokenValidationError
			if !errors.As(err, &validationErr) || validationErr.Reason != ReasonOperatorPolicy {
				t.Fatalf("error = %v, want operator-policy TokenValidationError", err)
			}
		})
	}
	if err := checkOperatorPolicy(&EARClaims{OperatorKeysHash: handoffTestOperatorKeysHash}, handoffTestOperatorKeysHash, "requester"); err != nil {
		t.Fatalf("matching operator policy rejected: %v", err)
	}
}

func TestValidateAllowlistSnapshot(t *testing.T) {
	for _, version := range []string{"", "0", "-1", "not-a-version"} {
		if err := validateAllowlistSnapshot(version, map[types.Digest]string{}); err == nil {
			t.Fatalf("validateAllowlistSnapshot accepted version %q", version)
		}
	}
	if err := validateAllowlistSnapshot("1", nil); err == nil {
		t.Fatal("validateAllowlistSnapshot accepted nil digests")
	}
	if err := validateAllowlistSnapshot("1", map[types.Digest]string{}); err != nil {
		t.Fatalf("validateAllowlistSnapshot rejected an empty snapshot: %v", err)
	}
}

type erroringHandoffEARSource struct{}

func (erroringHandoffEARSource) Current() (string, error) {
	return "", fmt.Errorf("ear source unavailable")
}

// TestHandoffReturns503BeforeBootstrap proves that a handoff handler whose
// EAR source has not bootstrapped yet returns 503 (rather than crashing,
// returning 401, or blocking the request).
func TestHandoffReturns503BeforeBootstrap(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	ca, err := NewCAWithCurve("Test Mesh CA", time.Hour, elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	bm := NewBundleManager(time.Hour, "", "ca-bundle", slog.Default())
	bm.SetInitial(ca.Cert)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"m": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Bundle:              bm,
		Signer:              handoffTestKey(t),
		EARSource:           erroringHandoffEARSource{},
		Snapshot:            snapshotFromCA(ca),
	})
	if err != nil {
		t.Fatalf("newHandoffHandler: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestHandoffReturns503ForEmptyCASnapshot(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := testKeyProvider{pub: &tokenKey.PublicKey}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	hh, err := NewHandoffHandler(HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         kp,
		AllowedMeasurements: map[string]bool{"allowed_measurement": true},
		OperatorKeysHash:    handoffTestOperatorKeysHash,
		Signer:              activeHandoffKey,
		EARSource:           staticHandoffEARSource{ear: activeEAR},
		Snapshot: func() (CASnapshot, bool) {
			return CASnapshot{}, true
		},
	})
	if err != nil {
		t.Fatalf("newHandoffHandler: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := encodeB64(priv.PublicKey().Bytes())
	sig, err := signHandoffMessage(requesterHandoffKey, mustHandoffRequestMessage(t, requesterEAR, pub))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(HandoffRequest{
		EAR:       requesterEAR,
		PublicKey: pub,
		Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func handoffTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// signJWT creates an ES256 JWT signed by the given key, adding mandatory EAR
// shape fields unless the caller provided them.
func signJWT(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	claims = validTestEARClaims(claims)
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload

	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}

	// Encode as r||s (each 32 bytes for P-256).
	keySize := 32
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func teePubKeyB64(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// validTestEARClaims fills in the mandatory EAR shape fields (profile,
// verifier id, submods) so signed test tokens pass ValidateEARToken.
func validTestEARClaims(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims)+3)
	for k, v := range claims {
		out[k] = v
	}
	if _, ok := out[earclaims.EATProfile]; !ok {
		out[earclaims.EATProfile] = earclaims.EARProfileTag
	}
	if _, ok := out[earclaims.EARVerifierID]; !ok {
		out[earclaims.EARVerifierID] = map[string]any{
			earclaims.Developer: "test",
			earclaims.Build:     "test",
		}
	}
	if !hasNonEmptyObjectClaim(out[earclaims.Submods]) {
		out[earclaims.Submods] = map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.EARStatus: 2,
			},
		}
	}
	return out
}

func hasNonEmptyObjectClaim(v any) bool {
	switch typed := v.(type) {
	case map[string]any:
		return len(typed) > 0
	case map[string]string:
		return len(typed) > 0
	case map[string]json.RawMessage:
		return len(typed) > 0
	default:
		return false
	}
}
