package requesthandoff

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	testKid = "test-kid"
	// testMeasurement is a valid lowercase SHA-384 hex launch digest; it is
	// its own hex.EncodeToString form, so the pinned RA-TLS list and the EAR
	// allowlist agree on it.
	testMeasurement = "abababababababababababababababababababababababababababababababababababababababababababababababab"
)

// signJWTWithKid mints an ES256 JWT with a kid header, mirroring the CDS EAR
// wire format so the real JWKS key provider resolves the verification key.
func signJWTWithKid(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT","kid":"` + testKid + `"}`))
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// earClaimsFor builds the mandatory EAR claim shape binding teePubDER and
// operatorKeysHash for the pinned test measurement.
func earClaimsFor(teePubDER []byte, operatorKeysHash string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		earclaims.EATProfile:       earclaims.EARProfileTag,
		earclaims.IssuedAt:         now,
		earclaims.ExpiresAt:        now + 3600,
		earclaims.EARVerifierID:    map[string]any{earclaims.Developer: "test", earclaims.Build: "test"},
		earclaims.TEEPublicKey:     base64.RawURLEncoding.EncodeToString(teePubDER),
		earclaims.OperatorKeysHash: operatorKeysHash,
		earclaims.Submods: map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.LaunchDigest: testMeasurement,
			},
		},
	}
}

// staticEARSource is a fixed issuer-EAR source for the handoff handler.
type staticEARSource struct {
	ear string
	exp time.Time
}

func (s staticEARSource) Current() (string, error)      { return s.ear, nil }
func (s staticEARSource) ExpiresAt() (time.Time, error) { return s.exp, nil }

// staticJWKSProvider is the server-side key provider (verifies requester EARs
// signed by the test token key).
type staticJWKSProvider struct{ pub *ecdsa.PublicKey }

func (p staticJWKSProvider) PublicKey(string) (*ecdsa.PublicKey, error) { return p.pub, nil }

func marshalPub(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// jwksFor renders the token key's public JWK set the way CDS serves it on
// /.well-known/jwks.json.
func jwksFor(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	// Uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes) for P-256.
	raw, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	x, y := raw[1:33], raw[33:65]
	set := map[string]any{
		"keys": []map[string]any{{
			"kty": "EC",
			"crv": "P-256",
			"alg": "ES256",
			"kid": testKid,
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		}},
	}
	out, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func certPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// writeOperatorKeys writes a one-key operator PEM bundle and returns its path
// plus the canonical key-set hash CDS derives from it.
func writeOperatorKeys(t *testing.T) (string, string) {
	t.Helper()
	opKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: marshalPub(t, &opKey.PublicKey)})
	path := filepath.Join(t.TempDir(), "operator-keys.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := operatorauth.KeySetHash([]*ecdsa.PublicKey{&opKey.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	return path, hash
}

// handoffPeer is a fake CDS peer serving the full pull surface over one TLS
// listener: JWKS, /authenticate, the local attestation-api /attest, an EAR
// mint on /attest-key, the real handoff handler on /handoff, and /ca.
type handoffPeer struct {
	srv *httptest.Server
	ca  *issuer.CA
	mux *http.ServeMux
}

func newHandoffPeer(t *testing.T, operatorKeysHash string) *handoffPeer {
	t.Helper()
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := testCA(t, "handoff-e2e-ca")
	digest, err := types.ParseDigest("sha256:" + strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}

	issuerEAR := signJWTWithKid(t, tokenKey, earClaimsFor(marshalPub(t, &signerKey.PublicKey), operatorKeysHash))
	hh, err := issuer.NewHandoffHandler(issuer.HandoffDeps{
		Logger:              slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		KeyProvider:         staticJWKSProvider{pub: &tokenKey.PublicKey},
		AllowedMeasurements: map[string]bool{testMeasurement: true},
		OperatorKeysHash:    operatorKeysHash,
		Signer:              signerKey,
		EARSource:           staticEARSource{ear: issuerEAR, exp: time.Now().Add(time.Hour)},
		Snapshot: func() (issuer.CASnapshot, bool) {
			return issuer.CASnapshot{
				Cert:             ca.Cert,
				Key:              ca.Key,
				AllowlistVersion: "7",
				Allowlist:        map[types.Digest]string{digest: "registry.example/dynamic:latest"},
			}, true
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksFor(t, &tokenKey.PublicKey))
	})
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(types.ChallengeResponse{
			Challenge: base64.StdEncoding.EncodeToString([]byte("test-challenge")),
		})
	})
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(types.AttestResponse{Platform: "snp", Evidence: json.RawMessage(`{}`)})
	})
	mux.HandleFunc("/attest-key", func(w http.ResponseWriter, r *http.Request) {
		var req types.AttestKeyRequestBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pubDER, err := base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ear := signJWTWithKid(t, tokenKey, earClaimsFor(pubDER, req.OperatorKeysHash))
		_ = json.NewEncoder(w).Encode(types.AttestKeyResponseBody{EAR: ear})
	})
	mux.HandleFunc("/handoff", hh.HandleHandoff)
	mux.HandleFunc("/ca", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(certPEM(t, ca.Cert))
	})

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return &handoffPeer{srv: srv, ca: ca, mux: mux}
}

// injectPeerClient routes run's RA-TLS client construction to the peer's
// plain TLS test client for the duration of the test.
func injectPeerClient(t *testing.T, peer *handoffPeer) {
	t.Helper()
	orig := newVerifyingHTTPClient
	newVerifyingHTTPClient = func([][]byte, string) (*http.Client, error) {
		return peer.srv.Client(), nil
	}
	t.Cleanup(func() { newVerifyingHTTPClient = orig })
}

func runConfigFor(peer *handoffPeer, operatorKeysPath string) config {
	return config{
		peerURL:           peer.srv.URL,
		attestationApiURL: peer.srv.URL,
		logLevel:          "error",
		measurements:      []string{testMeasurement},
		operatorKeys:      operatorKeysPath,
		timeout:           15 * time.Second,
	}
}

func TestRunPullsAndVerifiesHandoff(t *testing.T) {
	keysPath, keysHash := writeOperatorKeys(t)
	peer := newHandoffPeer(t, keysHash)
	injectPeerClient(t, peer)

	var out, errOut bytes.Buffer
	code := run(context.Background(), runConfigFor(peer, keysPath), &out, &errOut)
	if code != exitVerified {
		t.Fatalf("run = %d, want %d (stderr: %s)", code, exitVerified, errOut.String())
	}

	var rep report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout %q is not one JSON report: %v", out.String(), err)
	}
	if !rep.ServedCAMatch {
		t.Fatal("report.ServedCAMatch = false, want true")
	}
	if rep.BundleCertCount != 1 || rep.AllowlistVersion != "7" || rep.AllowlistDigestCount != 1 {
		t.Fatalf("report = %+v, want bundle 1 / allowlist 7 / digests 1", rep)
	}
	if !strings.Contains(rep.CACertSubject, "handoff-e2e-ca") {
		t.Fatalf("CACertSubject = %q, want the handed-off CA subject", rep.CACertSubject)
	}
}

func TestRunFailsWhenServedCADiffers(t *testing.T) {
	keysPath, keysHash := writeOperatorKeys(t)
	peer := newHandoffPeer(t, keysHash)
	injectPeerClient(t, peer)

	other := testCA(t, "impostor-ca")
	peer.mux.HandleFunc("GET /ca", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(certPEM(t, other.Cert))
	})

	var out, errOut bytes.Buffer
	code := run(context.Background(), runConfigFor(peer, keysPath), &out, &errOut)
	if code != exitFailed {
		t.Fatalf("run = %d, want %d (stderr: %s)", code, exitFailed, errOut.String())
	}
	var rep report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout %q is not one JSON report: %v", out.String(), err)
	}
	if rep.ServedCAMatch {
		t.Fatal("report.ServedCAMatch = true for a bundle without the handed-off CA")
	}
}

func TestRunHandoffDisabledHint(t *testing.T) {
	keysPath, keysHash := writeOperatorKeys(t)
	peer := newHandoffPeer(t, keysHash)
	injectPeerClient(t, peer)

	peer.mux.HandleFunc("POST /handoff", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	var out, errOut bytes.Buffer
	code := run(context.Background(), runConfigFor(peer, keysPath), &out, &errOut)
	if code != exitUnavailable {
		t.Fatalf("run = %d, want %d", code, exitUnavailable)
	}
	if !strings.Contains(errOut.String(), "cds.handoff.enabled=true") {
		t.Fatalf("stderr %q lacks the /handoff-disabled hint", errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on failure", out.String())
	}
}

func TestRunAttestKeyDeniedIsVerdict(t *testing.T) {
	keysPath, keysHash := writeOperatorKeys(t)
	peer := newHandoffPeer(t, keysHash)
	injectPeerClient(t, peer)

	peer.mux.HandleFunc("POST /attest-key", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "measurement denied", http.StatusForbidden)
	})

	var out, errOut bytes.Buffer
	code := run(context.Background(), runConfigFor(peer, keysPath), &out, &errOut)
	if code != exitFailed {
		t.Fatalf("run = %d, want %d (stderr: %s)", code, exitFailed, errOut.String())
	}
	if !strings.Contains(errOut.String(), "403") {
		t.Fatalf("stderr %q does not surface the 403 denial", errOut.String())
	}
}

func TestRunUsageErrors(t *testing.T) {
	keysPath, _ := writeOperatorKeys(t)
	valid := config{
		peerURL:           "https://peer.example",
		attestationApiURL: "http://attest.example",
		logLevel:          "error",
		measurements:      []string{testMeasurement},
		operatorKeys:      keysPath,
		timeout:           time.Second,
	}

	badPEM := filepath.Join(t.TempDir(), "not-keys.pem")
	if err := os.WriteFile(badPEM, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		mutate  func(*config)
		wantErr string
	}{
		{"bad log level", func(c *config) { c.logLevel = "verbose" }, "--log-level"},
		{"unparseable peer URL", func(c *config) { c.peerURL = "https://exa mple.com" }, "--peer-url"},
		{"plaintext peer URL", func(c *config) { c.peerURL = "http://peer.example" }, "https (RA-TLS)"},
		{"invalid measurement hex", func(c *config) { c.measurements = []string{"zz"} }, "--measurements"},
		{"wrong measurement size", func(c *config) { c.measurements = []string{"abcd"} }, "--measurements"},
		{"no usable measurement", func(c *config) { c.measurements = []string{" ", ""} }, "no usable measurement"},
		{"missing operator keys file", func(c *config) { c.operatorKeys = filepath.Join(t.TempDir(), "absent.pem") }, "--operator-keys"},
		{"operator keys not PEM", func(c *config) { c.operatorKeys = badPEM }, "--operator-keys"},
		{"missing attestation-api URL", func(c *config) { c.attestationApiURL = "" }, "attestation-api URL is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			var out, errOut bytes.Buffer
			if code := run(context.Background(), cfg, &out, &errOut); code != exitUsage {
				t.Fatalf("run = %d, want %d (stderr: %s)", code, exitUsage, errOut.String())
			}
			if !strings.Contains(errOut.String(), tc.wantErr) {
				t.Fatalf("stderr %q does not contain %q", errOut.String(), tc.wantErr)
			}
			if out.Len() != 0 {
				t.Fatalf("stdout = %q, want empty on usage error", out.String())
			}
		})
	}
}

func TestFetchServedCARejectsOversizedAndMalformedBundles(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxCABundleBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big/ca":
			_, _ = w.Write(big)
		default:
			_, _ = w.Write([]byte("not a certificate bundle"))
		}
	}))
	t.Cleanup(srv.Close)

	if _, err := fetchServedCA(context.Background(), srv.Client(), srv.URL+"/big"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized bundle error = %v, want size-cap error", err)
	}
	if _, err := fetchServedCA(context.Background(), srv.Client(), srv.URL); err == nil || !strings.Contains(err.Error(), "parse served /ca bundle") {
		t.Fatalf("malformed bundle error = %v, want parse error", err)
	}
}

func TestFetchServedCATransportErrors(t *testing.T) {
	if _, err := fetchServedCA(context.Background(), http.DefaultClient, "http://\x7f"); err == nil {
		t.Fatal("expected request-construction error for a control character in the URL")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	client := srv.Client()
	url := srv.URL
	srv.Close()
	if _, err := fetchServedCA(context.Background(), client, url); err == nil {
		t.Fatal("expected transport error against a closed server")
	}
}
