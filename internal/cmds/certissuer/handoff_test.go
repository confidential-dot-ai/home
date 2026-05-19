package certissuer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/internal/earclaims"
	issuerpkg "github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/crypto/cryptobyte"
)

func TestAttestedHandoffTransfersCAKeyToAllowedReplica(t *testing.T) {
	active, tokenKey := testIssuer(t)
	active.HandoffMeasurements = map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	bm := newBundleManager(active.MaxTTL, "", "default/mesh/ca-bundle", slog.Default())
	bm.setInitial(active.getBundle().caCert)

	hh := &handoffHandler{
		issuer:          active,
		bundle:          bm,
		issuerEARSource: staticHandoffEARSource{ear: activeEAR},
		signer:          activeHandoffKey,
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)

	joining := &Issuer{
		keyProvider:         active.keyProvider,
		JWTClockSkew:        30,
		Logger:              slog.Default(),
		HandoffMeasurements: map[string]bool{"allowed_measurement": true},
	}
	material, err := requestHandoff(context.Background(), srv.URL, requesterEAR, requesterHandoffKey, joining, srv.Client())
	if err != nil {
		t.Fatalf("requestHandoff failed: %v", err)
	}

	activeBundle := active.getBundle()
	if got, want := certutil.CertFingerprint(material.caCert.Raw), certutil.CertFingerprint(activeBundle.caCert.Raw); got != want {
		t.Fatalf("handoff CA fingerprint = %s, want %s", got, want)
	}
	if err := validateCAKeyPair(material.caCert, material.caKey); err != nil {
		t.Fatalf("handoff keypair invalid: %v", err)
	}
	if !material.caKey.PublicKey.Equal(&activeBundle.caKey.PublicKey) {
		t.Fatalf("handoff CA key does not match active key")
	}
	if len(material.bundle) != 1 {
		t.Fatalf("handoff bundle count = %d, want 1", len(material.bundle))
	}
}

func TestHandoffBundleStartsWithHandedOffActiveCA(t *testing.T) {
	active, tokenKey := testIssuer(t)
	active.HandoffMeasurements = map[string]bool{"allowed_measurement": true}
	activeBundle := active.getBundle()
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	rotated, err := issuerpkg.NewCAWithParent("Rotated Mesh CA", time.Hour, elliptic.P384(), activeBundle.caCert, activeBundle.caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the small rotation window where /ca has published the next
	// bundle before the active signer pointer is swapped.
	bm := newBundleManager(active.MaxTTL, "", "default/mesh/ca-bundle", slog.Default())
	bm.certs = []*x509.Certificate{rotated.Cert, activeBundle.caCert}

	hh := &handoffHandler{
		issuer:          active,
		bundle:          bm,
		issuerEARSource: staticHandoffEARSource{ear: activeEAR},
		signer:          activeHandoffKey,
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)

	joining := &Issuer{
		keyProvider:         active.keyProvider,
		JWTClockSkew:        30,
		Logger:              slog.Default(),
		HandoffMeasurements: map[string]bool{"allowed_measurement": true},
	}
	material, err := requestHandoff(context.Background(), srv.URL, requesterEAR, requesterHandoffKey, joining, srv.Client())
	if err != nil {
		t.Fatalf("requestHandoff failed: %v", err)
	}
	if len(material.bundle) != 2 {
		t.Fatalf("handoff bundle count = %d, want active + published next CA", len(material.bundle))
	}
	if !sameCert(material.caCert, activeBundle.caCert) || !sameCert(material.bundle[0], activeBundle.caCert) {
		t.Fatalf("handoff bundle first CA must match handed-off active signer")
	}
	if !sameCert(material.bundle[1], rotated.Cert) {
		t.Fatalf("handoff bundle should retain the published next CA after active signer")
	}
}

func TestHandoffRejectsRequesterKeyNotBoundToEAR(t *testing.T) {
	active, tokenKey := testIssuer(t)
	active.HandoffMeasurements = map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	attackerKey := handoffTestKey(t)
	activeEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	hh := &handoffHandler{
		issuer:          active,
		issuerEARSource: staticHandoffEARSource{ear: activeEAR},
		signer:          activeHandoffKey,
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
	active, tokenKey := testIssuer(t)
	active.HandoffMeasurements = map[string]bool{"allowed_measurement": true}
	activeEAR := handoffTestEAR(t, tokenKey, "allowed_measurement")
	requesterHandoffKey := handoffTestKey(t)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "other_measurement", requesterHandoffKey)

	hh := &handoffHandler{
		issuer:          active,
		issuerEARSource: staticHandoffEARSource{ear: activeEAR},
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
	joining := &Issuer{Logger: slog.Default()}
	_, err := requestHandoff(context.Background(), "http://127.0.0.1", "ear", handoffTestKey(t), joining, http.DefaultClient)
	if err == nil {
		t.Fatal("expected missing measurement allowlist error")
	}
}

func TestUnwrapHandoffResponseRejectsBadNonceLength(t *testing.T) {
	joining, tokenKey := testIssuer(t)
	joining.HandoffMeasurements = map[string]bool{"allowed_measurement": true}
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

	_, err = unwrapHandoffResponse(HandoffResponse{
		IssuerEAR:  issuerEAR,
		PublicKey:  peerPub,
		Signature:  sig,
		Nonce:      encodeB64([]byte{1, 2, 3}),
		Ciphertext: encodeB64([]byte("ciphertext")),
	}, requesterEAR, requesterPub, requesterECDH, joining)
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
	active, tokenKey := testIssuer(t)
	active.HandoffMeasurements = map[string]bool{"allowed_measurement": true}
	activeHandoffKey := handoffTestKey(t)
	requesterHandoffKey := handoffTestKey(t)
	activeEAR1 := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	activeEAR2 := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", activeHandoffKey)
	requesterEAR := handoffTestEARWithKey(t, tokenKey, "allowed_measurement", requesterHandoffKey)

	earSource := &atomicHandoffEAR{}
	earSource.set(activeEAR1)

	hh := &handoffHandler{
		issuer:          active,
		issuerEARSource: earSource,
		signer:          activeHandoffKey,
	}
	srv := httptest.NewServer(http.HandlerFunc(hh.HandleHandoff))
	t.Cleanup(srv.Close)

	if got := handoffResponseIssuerEAR(t, srv, requesterEAR, requesterHandoffKey); got != activeEAR1 {
		t.Fatalf("issuer EAR before refresh = %q, want %q", got, activeEAR1)
	}
	earSource.set(activeEAR2)
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
		earclaims.IssuedAt:  now,
		earclaims.ExpiresAt: now + 3600,
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

	got, err := handoffEARExpiry(token)
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
		if _, err := handoffEARExpiry(token); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestHandoffEARExpiryUpdaterMarksInvalidSourceNegative(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handoffEARExpirySeconds.Set(3600)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handoffEARExpiryUpdater(ctx, staticHandoffEARSource{ear: "bad.token"}, time.Hour, logger)

	if got := testutil.ToFloat64(handoffEARExpirySeconds); got >= 0 {
		t.Fatalf("handoff EAR expiry gauge = %v, want negative on invalid source", got)
	}
}

func TestNewHandoffHandlerValidatesInputs(t *testing.T) {
	iss, _ := testIssuer(t)
	bm := newBundleManager(iss.MaxTTL, "", "ca-bundle", slog.Default())
	bm.setInitial(iss.getBundle().caCert)

	signer := handoffTestKey(t)
	src := staticHandoffEARSource{ear: "ear-token"}

	if _, err := newHandoffHandler(iss, bm, nil, src); err == nil {
		t.Error("expected error when signer key is nil")
	}
	if _, err := newHandoffHandler(iss, bm, signer, nil); err == nil {
		t.Error("expected error when EAR source is nil")
	}

	iss.HandoffMeasurements = nil
	if _, err := newHandoffHandler(iss, bm, signer, src); err == nil {
		t.Error("expected error when handoff measurement allowlist is empty")
	}

	iss.HandoffMeasurements = map[string]bool{"m": true}
	// An EAR source that hasn't bootstrapped yet is accepted at construction
	// time — the handler returns 503 at request time. This decouples
	// cert-issuer startup from Assam reachability.
	hh, err := newHandoffHandler(iss, bm, signer, erroringHandoffEARSource{})
	if err != nil {
		t.Fatalf("newHandoffHandler must accept a not-yet-ready EAR source: %v", err)
	}
	if hh.signer == nil || hh.issuerEARSource == nil {
		t.Fatal("handoffHandler missing signer or EAR source")
	}

	hh, err = newHandoffHandler(iss, bm, signer, src)
	if err != nil {
		t.Fatalf("newHandoffHandler: %v", err)
	}
	if hh.signer == nil || hh.issuerEARSource == nil {
		t.Fatal("handoffHandler missing signer or EAR source")
	}
}

type erroringHandoffEARSource struct{}

func (erroringHandoffEARSource) Current() (string, error) {
	return "", fmt.Errorf("ear source unavailable")
}

// TestHandoffReturns503BeforeBootstrap proves that a handoff handler whose
// EAR source has not bootstrapped yet returns 503 (rather than crashing,
// returning 401, or blocking the request). This is the "Assam unreachable
// at startup" case after the non-blocking bootstrap fix.
func TestHandoffReturns503BeforeBootstrap(t *testing.T) {
	iss, _ := testIssuer(t)
	bm := newBundleManager(iss.MaxTTL, "", "ca-bundle", slog.Default())
	bm.setInitial(iss.getBundle().caCert)
	iss.HandoffMeasurements = map[string]bool{"m": true}

	hh, err := newHandoffHandler(iss, bm, handoffTestKey(t), erroringHandoffEARSource{})
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

func handoffTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
