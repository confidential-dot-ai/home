package cdsattest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// failingProvider always fails, to exercise the evidence-unavailable paths.
type failingProvider struct{}

func (failingProvider) Evidence(context.Context, []byte) (json.RawMessage, string, string, error) {
	return nil, "", "", errors.New("no TEE here")
}

func decodeErr(t *testing.T, resp *http.Response) types.ErrorResponse {
	t.Helper()
	defer resp.Body.Close()
	var e types.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestHealthz(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status %d", resp.StatusCode)
	}
}

func TestAttestationRejectsBadNonces(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	tests := []struct {
		name  string
		query string
	}{
		{"missing nonce", ""},
		{"nonce not base64url", "?nonce=%21%40%23"},
		{"nonce too short", "?nonce=" + b64url(make([]byte, minNonceBytes-1))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(ts.URL + "/.well-known/c8s/attestation" + tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if e := decodeErr(t, resp); e.Error != types.ErrorCodeInvalidRequest {
				t.Fatalf("error code = %q", e.Error)
			}
		})
	}
}

func TestAttestationEvidenceUnavailable(t *testing.T) {
	certPath, _ := writeTestLeaf(t)
	srv := NewServer(Config{Evidence: failingProvider{}, ServingCertFile: certPath})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)

	for _, query := range []string{
		"?nonce=" + b64url(nonce),               // over-encryption binding
		"?nonce=" + b64url(nonce) + "&pq=false", // tls-cert binding
	} {
		resp, err := http.Get(ts.URL + "/.well-known/c8s/attestation" + query)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("%s: status = %d, want 502", query, resp.StatusCode)
		}
		if e := decodeErr(t, resp); e.Error != types.ErrorCodeAttestationUnavailable {
			t.Fatalf("%s: error code = %q", query, e.Error)
		}
	}
}

func TestServingLeafSPKIErrors(t *testing.T) {
	dir := t.TempDir()
	notCert := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(notCert, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}), 0o600); err != nil {
		t.Fatal(err)
	}
	badDER := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		file string
	}{
		{"missing file", filepath.Join(dir, "nope.pem")},
		{"not a certificate PEM", notCert},
		{"garbage certificate DER", badDER},
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer(Config{Evidence: &capturingProvider{}, ServingCertFile: tc.file})
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()
			resp, err := http.Get(ts.URL + "/.well-known/c8s/attestation?nonce=" + b64url(nonce) + "&pq=false")
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusNotImplemented {
				t.Fatalf("status = %d, want 501", resp.StatusCode)
			}
			if e := decodeErr(t, resp); e.Error != types.ErrorCodeBindingUnavailable {
				t.Fatalf("error code = %q", e.Error)
			}
		})
	}
}

func TestHandshakeRejectsInvalidJSON(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/.well-known/c8s/handshake", "application/json", strings.NewReader("{nope"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Error != types.ErrorCodeInvalidRequest {
		t.Fatalf("error code = %q", e.Error)
	}
}

func TestHandshakeRejectsBadFieldEncoding(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	fetchBundle(t, ts.URL, nonce) // registers the pending nonce

	body, _ := json.Marshal(types.HandshakeRequest{
		Nonce:        b64url(nonce),
		ClientX25519: "!!!not-base64url!!!",
		MLKEMCt:      b64url(make([]byte, overenc.MLKEM768CTBytes)),
	})
	resp, err := http.Post(ts.URL+"/.well-known/c8s/handshake", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Error != types.ErrorCodeInvalidRequest {
		t.Fatalf("error code = %q", e.Error)
	}
}

func TestHandshakeRejectsBadKeyMaterial(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	fetchBundle(t, ts.URL, nonce)

	// Correct lengths, degenerate content: key agreement must fail.
	body, _ := json.Marshal(types.HandshakeRequest{
		Nonce:        b64url(nonce),
		ClientX25519: b64url(make([]byte, 32)),
		MLKEMCt:      b64url(make([]byte, overenc.MLKEM768CTBytes)),
	})
	resp, err := http.Post(ts.URL+"/.well-known/c8s/handshake", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Error != types.ErrorCodeChannelError {
		t.Fatalf("error code = %q", e.Error)
	}
}

func TestTunnelRejectsMalformedRecords(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	post := func(t *testing.T, sessionID string, body []byte) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/.well-known/c8s/tunnel", bytes.NewReader(body))
		req.Header.Set("X-C8s-Session", sessionID)
		req.Header.Set("Content-Type", "application/cbor")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	t.Run("body is not CBOR", func(t *testing.T) {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		_, sessionID := establishSession(t, ts.URL, nonce)
		resp := post(t, sessionID, []byte("notcbor"))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if e := decodeErr(t, resp); e.Error != types.ErrorCodeChannelError {
			t.Fatalf("error code = %q", e.Error)
		}
	})

	t.Run("record does not decrypt", func(t *testing.T) {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		_, sessionID := establishSession(t, ts.URL, nonce)
		garbage, _ := cbor.Marshal(overenc.Record{IV: make([]byte, 12), CT: []byte("garbage-ciphertext")})
		resp := post(t, sessionID, garbage)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if e := decodeErr(t, resp); e.Error != types.ErrorCodeChannelError {
			t.Fatalf("error code = %q", e.Error)
		}
	})

	t.Run("plaintext is not a request envelope", func(t *testing.T) {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		channel, sessionID := establishSession(t, ts.URL, nonce)
		plain, _ := cbor.Marshal(42) // decrypts fine, but is not a TunnelRequest
		rec, err := channel.Seal(plain, overenc.RequestAAD())
		if err != nil {
			t.Fatal(err)
		}
		recBody, _ := cbor.Marshal(rec)
		resp := post(t, sessionID, recBody)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if e := decodeErr(t, resp); e.Error != types.ErrorCodeChannelError {
			t.Fatalf("error code = %q", e.Error)
		}
	})
}

func TestTunnelSealsBackendErrorAs502(t *testing.T) {
	// An upstream that is already gone: Forward errors, and the sidecar must
	// seal a 502 back rather than fail the tunnel HTTP exchange.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	hb, err := NewHTTPBackend(deadURL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(Config{
		Evidence: FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA"}`), Platform: "snp", Generation: "genoa"},
		Backend:  hb,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	channel, sessionID := establishSession(t, ts.URL, nonce)

	resp := tunnel(t, ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/v1/x"})
	if resp.Status != http.StatusBadGateway {
		t.Fatalf("sealed status = %d, want 502", resp.Status)
	}
	if !strings.Contains(string(resp.Body), "backend error") {
		t.Fatalf("sealed body = %q", resp.Body)
	}
}
