package getkubeconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// tdxEnvelope is a minimal self-describing evidence envelope; the actual
// verification verdict comes from the stubbed verifyEnvelope.
const tdxEnvelope = `{"platform":"tdx","evidence":{}}`

// newAttestedTLSServer starts a TLS httptest server whose serving cert is a
// genuine RA-TLS attested cert (quote envelope embedded, self-signed), the
// same shape the cred-release endpoint serves.
func newAttestedTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeTDX, Report: []byte(tdxEnvelope)}
	der, err := ratls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// attestHandler serves POST /attest with the given status; on 200 it returns
// the TDX evidence envelope after checking the request shape.
func attestHandler(t *testing.T, status int) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("attest method = %s, want POST", r.Method)
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("attest body: %v", err)
		}
		if nonce, err := base64.StdEncoding.DecodeString(req["report_data"]); err != nil || len(nonce) != 32 {
			t.Errorf("attest report_data = %q, want base64 32-byte nonce", req["report_data"])
		}
		if status != http.StatusOK {
			http.Error(w, "attest boom", status)
			return
		}
		fmt.Fprint(w, tdxEnvelope)
	})
}

// releaseHandler serves POST /release-credential with the given status; on 200
// it checks the operator JWT + CSR shape and returns cert/ca PEMs.
func releaseHandler(t *testing.T, status int, respBody string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != releasePath {
			t.Errorf("release path = %s, want %s", r.URL.Path, releasePath)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("release Authorization = %q, want Bearer JWT", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		var req releaseRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("release body: %v", err)
		}
		if !strings.Contains(req.CSRPEM, "CERTIFICATE REQUEST") {
			t.Errorf("release csr = %q, want a CSR PEM", req.CSRPEM)
		}
		if status != http.StatusOK {
			http.Error(w, "release boom", status)
			return
		}
		fmt.Fprint(w, respBody)
	})
}

// testEnv wires up a full fake node: operator key on disk, attest endpoint,
// RA-TLS cred-release endpoint, and a stubbed verifier that accepts iff
// rtmr_3 == H(op_pub).
type testEnv struct {
	keyPath    string
	attestURL  string
	releaseURL string
	outPath    string
}

func newTestEnv(t *testing.T, attestStatus, releaseStatus int, releaseBody string) testEnv {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := mustKeyPEM(t, key)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "op.key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err := publicKeyPEMFromPrivate(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	stubVerify(t, verifiedResult(expectedRTMR3(pub)), nil)

	attest := httptest.NewServer(attestHandler(t, attestStatus))
	t.Cleanup(attest.Close)
	release := newAttestedTLSServer(t, releaseHandler(t, releaseStatus, releaseBody))

	return testEnv{
		keyPath:    keyPath,
		attestURL:  attest.URL + "/attest",
		releaseURL: release.URL,
		outPath:    filepath.Join(dir, "kubeconfig"),
	}
}

const goodRelease = `{"cert":"CERTPEM","ca":"CAPEM"}`

func (e testEnv) config() Config {
	return Config{
		AttestURL:       e.attestURL,
		ReleaseBaseURL:  e.releaseURL,
		APIServerURL:    "https://node:6443",
		OperatorKeyPath: e.keyPath,
		ContextName:     "c8s",
		TLSServerName:   "c8s-cvm",
		OutPath:         e.outPath,
		Timeout:         10 * time.Second,
	}
}

// TestRunEndToEnd drives the full client flow against fake endpoints: attest
// gate, RA-TLS dial (verified via the stub), operator-signed CSR exchange, and
// kubeconfig assembly on disk.
func TestRunEndToEnd(t *testing.T) {
	env := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease)

	if err := Run(context.Background(), env.config()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	kc, err := os.ReadFile(env.outPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"server: https://node:6443",
		"tls-server-name: c8s-cvm",
		"client-certificate-data: " + base64.StdEncoding.EncodeToString([]byte("CERTPEM")),
		"certificate-authority-data: " + base64.StdEncoding.EncodeToString([]byte("CAPEM")),
	} {
		if !strings.Contains(string(kc), want) {
			t.Errorf("kubeconfig missing %q", want)
		}
	}
}

func TestRunErrors(t *testing.T) {
	t.Run("missing key file", func(t *testing.T) {
		cfg := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease).config()
		cfg.OperatorKeyPath = filepath.Join(t.TempDir(), "nope.key")
		err := Run(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "read operator key") {
			t.Fatalf("want read-key error, got %v", err)
		}
	})

	t.Run("bad key PEM", func(t *testing.T) {
		cfg := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease).config()
		bad := filepath.Join(t.TempDir(), "bad.key")
		if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg.OperatorKeyPath = bad
		err := Run(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "derive operator public key") {
			t.Fatalf("want derive error, got %v", err)
		}
	})

	t.Run("attest gate HTTP failure", func(t *testing.T) {
		cfg := newTestEnv(t, http.StatusInternalServerError, http.StatusOK, goodRelease).config()
		err := Run(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "attestation gate") ||
			!strings.Contains(err.Error(), "attest HTTP 500") {
			t.Fatalf("want attest-gate HTTP 500 error, got %v", err)
		}
	})

	t.Run("release failure", func(t *testing.T) {
		cfg := newTestEnv(t, http.StatusOK, http.StatusForbidden, goodRelease).config()
		err := Run(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "credential release") ||
			!strings.Contains(err.Error(), "release HTTP 403") {
			t.Fatalf("want release HTTP 403 error, got %v", err)
		}
	})

	t.Run("write failure", func(t *testing.T) {
		cfg := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease).config()
		cfg.OutPath = filepath.Join(t.TempDir(), "no", "such", "dir", "kubeconfig")
		err := Run(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "write kubeconfig") {
			t.Fatalf("want write error, got %v", err)
		}
	})
}

// TestRunRejectsWrongRTMR3 covers the trust gate end to end: the node's quote
// verifies but rtmr_3 doesn't match the operator key, so Run must stop before
// ever contacting cred-release.
func TestRunRejectsWrongRTMR3(t *testing.T) {
	env := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease)
	stubVerify(t, verifiedResult("00"), nil) // overrides the env's stub

	// Count cred-release hits on a plain-HTTP server so any request — even one
	// that would fail the RA-TLS handshake — reaches the handler and is counted.
	var releaseHits atomic.Int32
	release := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		releaseHits.Add(1)
		releaseHandler(t, http.StatusOK, goodRelease).ServeHTTP(w, r)
	}))
	t.Cleanup(release.Close)
	cfg := env.config()
	cfg.ReleaseBaseURL = release.URL

	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "RTMR[3] mismatch") {
		t.Fatalf("want RTMR[3] mismatch, got %v", err)
	}
	if n := releaseHits.Load(); n != 0 {
		t.Fatalf("cred-release hits = %d, want 0 (Run must stop at the trust gate)", n)
	}
}

// TestRATLSClientRejectsPlainCert confirms the RA-TLS dial fails closed
// against a server whose cert carries no attestation envelope (a host MITM).
func TestRATLSClientRejectsPlainCert(t *testing.T) {
	env := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease)
	plain := httptest.NewTLSServer(releaseHandler(t, http.StatusOK, goodRelease))
	t.Cleanup(plain.Close)

	cfg := env.config()
	cfg.ReleaseBaseURL = plain.URL
	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "credential release") ||
		!strings.Contains(err.Error(), "ratls") ||
		!strings.Contains(err.Error(), "missing RA-TLS extension") {
		t.Fatalf("want RA-TLS handshake failure (ratls: missing RA-TLS extension), got %v", err)
	}
}

func TestRequestCredentialErrors(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := mustKeyPEM(t, key)
	id, err := newClientIdentity()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := id.csrPEM()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	ctx := context.Background()

	t.Run("bad operator key", func(t *testing.T) {
		_, err := requestCredential(ctx, client, "http://127.0.0.1:0", []byte("junk"), csr)
		if err == nil || !strings.Contains(err.Error(), "operator key") {
			t.Fatalf("want operator-key error, got %v", err)
		}
	})

	serve := func(status int, body string) *httptest.Server {
		srv := httptest.NewServer(releaseHandler(t, status, body))
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("bad response JSON", func(t *testing.T) {
		srv := serve(http.StatusOK, "not json")
		_, err := requestCredential(ctx, client, srv.URL, keyPEM, csr)
		if err == nil || !strings.Contains(err.Error(), "parse release response") {
			t.Fatalf("want parse error, got %v", err)
		}
	})

	t.Run("missing ca", func(t *testing.T) {
		srv := serve(http.StatusOK, `{"cert":"CERTPEM"}`)
		_, err := requestCredential(ctx, client, srv.URL, keyPEM, csr)
		if err == nil || !strings.Contains(err.Error(), "missing cert or ca") {
			t.Fatalf("want missing-field error, got %v", err)
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		srv := serve(http.StatusOK, goodRelease)
		srv.Close()
		_, err := requestCredential(ctx, client, srv.URL, keyPEM, csr)
		if err == nil || !strings.Contains(err.Error(), "release request") {
			t.Fatalf("want transport error, got %v", err)
		}
	})
}

func TestVerifyEvidenceErrors(t *testing.T) {
	t.Run("bad envelope JSON", func(t *testing.T) {
		_, err := verifyEvidence([]byte("not json"), nil)
		if err == nil || !strings.Contains(err.Error(), "parse evidence envelope") {
			t.Fatalf("want parse error, got %v", err)
		}
	})

	t.Run("verifier error", func(t *testing.T) {
		stubVerify(t, nil, fmt.Errorf("boom"))
		_, err := verifyEvidence([]byte(tdxEnvelope), nil)
		if err == nil || !strings.Contains(err.Error(), "verify evidence: boom") {
			t.Fatalf("want wrapped verifier error, got %v", err)
		}
	})

	t.Run("signature invalid", func(t *testing.T) {
		res := verifiedResult("aa")
		res.SignatureValid = false
		stubVerify(t, res, nil)
		_, err := verifyEvidence([]byte(tdxEnvelope), nil)
		if err == nil || !strings.Contains(err.Error(), "quote signature invalid") {
			t.Fatalf("want signature error, got %v", err)
		}
	})
}

func TestCheckRTMR3NoClaim(t *testing.T) {
	res := verifiedResult("")
	err := checkRTMR3(res, operatorPub(t))
	if err == nil || !strings.Contains(err.Error(), "no rtmr_3") {
		t.Fatalf("want no-rtmr_3 error, got %v", err)
	}
}

func TestPublicKeyPEMFromPrivateErrors(t *testing.T) {
	t.Run("not PEM", func(t *testing.T) {
		_, err := publicKeyPEMFromPrivate([]byte("garbage"))
		if err == nil || !strings.Contains(err.Error(), "not PEM") {
			t.Fatalf("want not-PEM error, got %v", err)
		}
	})

	t.Run("unsupported PEM type", func(t *testing.T) {
		blob := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})
		_, err := publicKeyPEMFromPrivate(blob)
		if err == nil || !strings.Contains(err.Error(), "unsupported key PEM type") {
			t.Fatalf("want unsupported-type error, got %v", err)
		}
	})

	t.Run("PKCS8 non-ECDSA", func(t *testing.T) {
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(edKey)
		if err != nil {
			t.Fatal(err)
		}
		blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		_, err = publicKeyPEMFromPrivate(blob)
		if err == nil || !strings.Contains(err.Error(), "want ECDSA") {
			t.Fatalf("want non-ECDSA error, got %v", err)
		}
	})

	t.Run("bad SEC1 body", func(t *testing.T) {
		blob := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}})
		if _, err := publicKeyPEMFromPrivate(blob); err == nil {
			t.Fatal("want SEC1 parse error, got nil")
		}
	})

	t.Run("bad PKCS8 body", func(t *testing.T) {
		blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})
		if _, err := publicKeyPEMFromPrivate(blob); err == nil {
			t.Fatal("want PKCS8 parse error, got nil")
		}
	})
}

func TestPostAttestErrors(t *testing.T) {
	t.Run("bad URL", func(t *testing.T) {
		_, err := postAttest(context.Background(), "http://\x7f", nil)
		if err == nil {
			t.Fatal("want request-build error, got nil")
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close()
		_, err := postAttest(context.Background(), srv.URL+"/attest", []byte("n"))
		if err == nil {
			t.Fatal("want transport error, got nil")
		}
	})
}
