package cdsattest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/fxamacker/cbor/v2"
)

const fakeCDSCert = "-----BEGIN CERTIFICATE-----\nMIIBfakefakefake\n-----END CERTIFICATE-----\n"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence: FixtureEvidenceProvider{
			Raw:        json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`),
			Platform:   "snp",
			Generation: "genoa",
		},
		CDSCertPEM:           []byte(fakeCDSCert),
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	return httptest.NewServer(srv.Handler())
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// clientChannelFromBundle does what a real client does after verifying the
// bundle: recompute the identity transcript from the served chain and derive
// the channel from it.
func clientChannelFromBundle(t *testing.T, bundle types.AttestationBundle, nonce []byte) (*overenc.Channel, overenc.Handshake) {
	t.Helper()
	x, _ := base64.RawURLEncoding.DecodeString(bundle.SessionPubKey.X25519)
	m, _ := base64.RawURLEncoding.DecodeString(bundle.SessionPubKey.MLKEM768)
	pub := overenc.PublicKey{X25519: x, MLKEM768: m}
	certs, err := certutil.ParsePEMCertificates([]byte(bundle.CDSCertPEM))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("bundle chain has %d certs, want leaf + issuing CA", len(certs))
	}
	transcript, err := overenc.IdentityTranscriptHash(pub, nonce, certs[0].Raw, certs[1].Raw)
	if err != nil {
		t.Fatal(err)
	}
	channel, hs, err := overenc.ClientAgree(pub, transcript)
	if err != nil {
		t.Fatal(err)
	}
	return channel, hs
}

func TestServesCDSCert(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/.well-known/c8s/cds-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != fakeCDSCert {
		t.Fatalf("unexpected cert body: %q", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Fatalf("content-type = %q", ct)
	}
}

func fetchBundle(t *testing.T, base string, nonce []byte) types.AttestationBundle {
	t.Helper()
	resp, err := http.Get(base + "/.well-known/c8s/attestation?nonce=" + b64url(nonce))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attestation status %d", resp.StatusCode)
	}
	var b types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

func establishSession(t *testing.T, base string, nonce []byte) (*overenc.Channel, string) {
	t.Helper()
	bundle := fetchBundle(t, base, nonce)
	channel, hs := clientChannelFromBundle(t, bundle, nonce)
	hsBody, _ := json.Marshal(types.HandshakeRequest{
		Nonce:        b64url(nonce),
		ClientX25519: b64url(hs.ClientX25519),
		MLKEMCt:      b64url(hs.MLKEMCiphertext),
	})
	hsResp, err := http.Post(base+"/.well-known/c8s/handshake", "application/json", bytes.NewReader(hsBody))
	if err != nil {
		t.Fatal(err)
	}
	defer hsResp.Body.Close()
	if hsResp.StatusCode != http.StatusOK {
		t.Fatalf("handshake status %d", hsResp.StatusCode)
	}
	var hr types.HandshakeResponse
	if err := json.NewDecoder(hsResp.Body).Decode(&hr); err != nil {
		t.Fatal(err)
	}
	if hr.SessionID == "" {
		t.Fatal("no session id")
	}
	return channel, hr.SessionID
}

func TestFullFlowOverEncryptedEcho(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	bundle := fetchBundle(t, ts.URL, nonce)

	if bundle.Version != types.ProtocolVersion || bundle.Platform != "snp" || bundle.Generation != "genoa" {
		t.Fatalf("unexpected bundle header: %+v", bundle)
	}
	if bundle.Binding != types.BindingOverEncryption || bundle.IdentityProof == nil {
		t.Fatalf("bundle is not identity-bound: %+v", bundle)
	}
	if bundle.Nonce != b64url(nonce) {
		t.Fatal("nonce not echoed")
	}

	x, _ := base64.RawURLEncoding.DecodeString(bundle.SessionPubKey.X25519)
	m, _ := base64.RawURLEncoding.DecodeString(bundle.SessionPubKey.MLKEM768)
	if len(x) != overenc.X25519PubBytes || len(m) != overenc.MLKEM768EKBytes {
		t.Fatalf("bad session pubkey sizes: %d %d", len(x), len(m))
	}

	channel, hs := clientChannelFromBundle(t, bundle, nonce)

	// handshake
	hsBody, _ := json.Marshal(types.HandshakeRequest{
		Nonce:        b64url(nonce),
		ClientX25519: b64url(hs.ClientX25519),
		MLKEMCt:      b64url(hs.MLKEMCiphertext),
	})
	hsResp, err := http.Post(ts.URL+"/.well-known/c8s/handshake", "application/json", bytes.NewReader(hsBody))
	if err != nil {
		t.Fatal(err)
	}
	var hr types.HandshakeResponse
	json.NewDecoder(hsResp.Body).Decode(&hr)
	hsResp.Body.Close()
	if hr.SessionID == "" {
		t.Fatal("no session id")
	}

	// over-encrypted tunnel: seal a full request envelope, open the response.
	resp := tunnel(t, ts.URL, channel, hr.SessionID, types.TunnelRequest{
		Method:  "POST",
		Path:    "/v1/echo",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    []byte("hi enclave"),
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("tunnel response status %d", resp.Status)
	}
	if !strings.Contains(string(resp.Body), "hi enclave") {
		t.Fatalf("echo did not round-trip: %q", resp.Body)
	}
}

// tunnel seals req, posts it to the tunnel endpoint, and opens the response.
func tunnel(t *testing.T, base string, ch *overenc.Channel, sessionID string, req types.TunnelRequest) types.TunnelResponse {
	t.Helper()
	plain, _ := cbor.Marshal(req)
	rec, err := ch.Seal(plain, overenc.RequestAAD())
	if err != nil {
		t.Fatal(err)
	}
	recBody, _ := cbor.Marshal(rec)
	httpReq, _ := http.NewRequest(http.MethodPost, base+"/.well-known/c8s/tunnel", bytes.NewReader(recBody))
	httpReq.Header.Set("X-C8s-Session", sessionID)
	httpReq.Header.Set("Content-Type", "application/cbor")
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("tunnel HTTP status %d", httpResp.StatusCode)
	}
	outBytes, _ := io.ReadAll(httpResp.Body)
	var outRec overenc.Record
	if err := cbor.Unmarshal(outBytes, &outRec); err != nil {
		t.Fatal(err)
	}
	respCBOR, err := ch.Open(outRec, overenc.ResponseAAD())
	if err != nil {
		t.Fatal(err)
	}
	var resp types.TunnelResponse
	if err := cbor.Unmarshal(respCBOR, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func postSealedTunnel(t *testing.T, base string, ch *overenc.Channel, sessionID string, req types.TunnelRequest) *http.Response {
	t.Helper()
	plain, _ := cbor.Marshal(req)
	rec, err := ch.Seal(plain, overenc.RequestAAD())
	if err != nil {
		t.Fatal(err)
	}
	recBody, _ := cbor.Marshal(rec)
	httpReq, _ := http.NewRequest(http.MethodPost, base+"/.well-known/c8s/tunnel", bytes.NewReader(recBody))
	httpReq.Header.Set("X-C8s-Session", sessionID)
	httpReq.Header.Set("Content-Type", "application/cbor")
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	return httpResp
}

func TestTunnelForwardsToUpstream(t *testing.T) {
	// A real backend the sidecar forwards decrypted traffic to.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("upstream saw: " + r.URL.Path + " / " + string(body)))
	}))
	defer backend.Close()

	hb, err := NewHTTPBackend(backend.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), Platform: "snp", Generation: "genoa"},
		CDSCertPEM:           []byte(fakeCDSCert),
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		Backend:              hb,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	bundle := fetchBundle(t, ts.URL, nonce)
	channel, hs := clientChannelFromBundle(t, bundle, nonce)
	hsBody, _ := json.Marshal(types.HandshakeRequest{Nonce: b64url(nonce), ClientX25519: b64url(hs.ClientX25519), MLKEMCt: b64url(hs.MLKEMCiphertext)})
	hsResp, _ := http.Post(ts.URL+"/.well-known/c8s/handshake", "application/json", bytes.NewReader(hsBody))
	var hr types.HandshakeResponse
	json.NewDecoder(hsResp.Body).Decode(&hr)
	hsResp.Body.Close()

	resp := tunnel(t, ts.URL, channel, hr.SessionID, types.TunnelRequest{
		Method:  "PUT",
		Path:    "/v1/data",
		Headers: map[string]string{"Authorization": "Bearer sekret"},
		Body:    []byte("payload"),
	})
	if resp.Status != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.Status)
	}
	if !strings.Contains(string(resp.Body), "upstream saw: /v1/data / payload") {
		t.Fatalf("unexpected upstream body: %q", resp.Body)
	}
	if resp.Headers["X-Echo-Method"] != "PUT" {
		t.Fatalf("method not forwarded: %q", resp.Headers["X-Echo-Method"])
	}
	if resp.Headers["X-Echo-Auth"] != "Bearer sekret" {
		t.Fatalf("Authorization not forwarded confidentially: %q", resp.Headers["X-Echo-Auth"])
	}
}

func TestHandshakeRejectsUnknownNonce(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	body, _ := json.Marshal(types.HandshakeRequest{
		Nonce:        b64url([]byte("never-issued-nonce-bytes-32xxxxx")),
		ClientX25519: b64url(make([]byte, 32)),
		MLKEMCt:      b64url(make([]byte, overenc.MLKEM768CTBytes)),
	})
	resp, err := http.Post(ts.URL+"/.well-known/c8s/handshake", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown nonce, got %d", resp.StatusCode)
	}
}

func TestHandshakeRejectsExpiredNonce(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), Platform: "snp", Generation: "genoa"},
		CDSCertPEM:           []byte(fakeCDSCert),
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		NonceTTL:             time.Millisecond,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	bundle := fetchBundle(t, ts.URL, nonce)
	time.Sleep(5 * time.Millisecond)

	_, hs := clientChannelFromBundle(t, bundle, nonce)
	body, _ := json.Marshal(types.HandshakeRequest{
		Nonce:        b64url(nonce),
		ClientX25519: b64url(hs.ClientX25519),
		MLKEMCt:      b64url(hs.MLKEMCiphertext),
	})
	resp, err := http.Post(ts.URL+"/.well-known/c8s/handshake", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired nonce, got %d", resp.StatusCode)
	}
}

func TestTunnelRejectsExpiredSession(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), Platform: "snp", Generation: "genoa"},
		CDSCertPEM:           []byte(fakeCDSCert),
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		SessionTTL:           time.Millisecond,
		// Generous nonce TTL so the handshake survives establishment; this test
		// exercises established-session idle expiry, not nonce expiry.
		NonceTTL: time.Minute,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	channel, sessionID := establishSession(t, ts.URL, nonce)
	time.Sleep(5 * time.Millisecond)

	resp := postSealedTunnel(t, ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired session, got %d", resp.StatusCode)
	}
}

func TestAppRequiresSession(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/.well-known/c8s/tunnel", "application/json", strings.NewReader(`{"iv":"AA","ct":"BB"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d", resp.StatusCode)
	}
}

func TestHTTPBackendRejectsOversizedUpstreamResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(bytes.Repeat([]byte("a"), maxUpstreamResponseBytes+1))
	}))
	defer backend.Close()

	hb, err := NewHTTPBackend(backend.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hb.Forward(context.Background(), types.TunnelRequest{Method: "GET", Path: "/"}); err == nil {
		t.Fatal("expected oversized upstream response error")
	}
}
