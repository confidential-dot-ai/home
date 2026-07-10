package lbdiscovery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// plainServingCert generates a self-signed ECDSA serving cert with NO RA-TLS
// extension — the shape a tls-lb front door presents.
func plainServingCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tls-lb"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"127.0.0.1", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// discoveryDoc builds a tls-lb discovery document embedding cert + challenge.
// mode is the public_tls.mode field; "" mimics a pre-mode-field document.
func discoveryDoc(t *testing.T, cert *x509.Certificate, challenge []byte, mode, platform string, evidence string) []byte {
	t.Helper()
	doc, err := json.Marshal(types.DiscoveryDocument{
		Version: "1",
		PublicTLS: types.PublicTLSDiscovery{
			Mode: mode,
		},
		CDSTLS: types.CDSTLSDiscovery{
			CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		},
		Attestation: types.AttestationDiscovery{
			Challenge: base64.StdEncoding.EncodeToString(challenge),
			Platform:  platform,
			Evidence:  json.RawMessage(evidence),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// fakeLB serves the discovery document plus a proxied /allowlist body over TLS
// with servingCert (no RA-TLS extension), like a tls-lb front door.
func fakeLB(t *testing.T, servingCert tls.Certificate, doc []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case DefaultPath:
			w.Header().Set("Content-Type", "application/json")
			w.Write(doc)
		case "/allowlist":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"version":"1","digests":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{servingCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// verifyResponse builds a minimal approving attestation-api /verify response.
func verifyResponse(measurement []byte) map[string]any {
	result := map[string]any{
		"platform":          string(types.PlatformAzSnp),
		"signature_valid":   true,
		"report_data_match": true,
		"claims":            map[string]any{},
	}
	if measurement != nil {
		result["claims"] = map[string]any{"launch_digest": hex.EncodeToString(measurement)}
	}
	return map[string]any{"result": result}
}

// mockedVerifySrv returns a fake attestation-api whose /verify always responds
// with body.
func mockedVerifySrv(t *testing.T, body any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestNewVerifiedHTTPClient_EndToEnd is the regression test for the tls-lb
// allowlist bug: a front door whose serving cert has no RA-TLS extension must
// be verified via its discovery document (evidence sent to the attestation-api
// bound to SHA-384(cert pubkey ‖ challenge)) and subsequent requests must
// succeed against the pinned serving cert.
func TestNewVerifiedHTTPClient_EndToEnd(t *testing.T) {
	servingCert, leaf := plainServingCert(t)
	challenge := []byte("issuance-challenge")
	doc := discoveryDoc(t, leaf, challenge, "cds", string(types.PlatformAzSnp), `{"hcl_report":"fake"}`)
	lb := fakeLB(t, servingCert, doc)

	measurement := bytes.Repeat([]byte{0x42}, ratls.SNPMeasurementSize)
	erd, err := ratls.ReportDataForKey(leaf.PublicKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	var sawVerify bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawVerify = true
		var req types.VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode verify request: %v", err)
		}
		// az-snp binds through a TPM quote whose nonce is the 48-byte digest.
		if got := req.Params.ExpectedReportData.Bytes(); !bytes.Equal(got, erd[:sha512.Size384]) {
			t.Fatalf("expected_report_data = %x, want %x", got, erd[:sha512.Size384])
		}
		json.NewEncoder(w).Encode(verifyResponse(measurement))
	}))
	defer api.Close()

	hc, err := NewVerifiedHTTPClient(context.Background(), lb.URL, [][]byte{measurement}, api.URL)
	if err != nil {
		t.Fatalf("NewVerifiedHTTPClient: %v", err)
	}
	if !sawVerify {
		t.Fatal("attestation-api /verify was not called")
	}

	// Two sequential requests: both must ride the one attested connection
	// (the client never redials).
	for i := range 2 {
		resp, err := hc.Get(lb.URL + "/allowlist")
		if err != nil {
			t.Fatalf("GET /allowlist #%d through the connection-bound client: %v", i+1, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"version"`)) {
			t.Fatalf("GET /allowlist #%d = %d %s", i+1, resp.StatusCode, body)
		}
	}
}

// TestNewVerifiedHTTPClient_NoDiscovery proves a target without a discovery
// document (a direct CDS endpoint) signals ErrNoDiscovery so the caller falls
// back to RA-TLS serving-cert verification.
func TestNewVerifiedHTTPClient_NoDiscovery(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()

	_, err := NewVerifiedHTTPClient(context.Background(), srv.URL, nil, "http://attestation-api")
	if !errors.Is(err, ErrNoDiscovery) {
		t.Fatalf("want ErrNoDiscovery, got: %v", err)
	}
}

// TestNewVerifiedHTTPClient_FailsClosed proves a discovery document that is
// present but fails verification is a hard error — NOT ErrNoDiscovery, which
// would let the caller fall back and mask an attack.
func TestNewVerifiedHTTPClient_FailsClosed(t *testing.T) {
	servingCert, leaf := plainServingCert(t)
	doc := discoveryDoc(t, leaf, []byte("challenge"), "", string(types.PlatformAzSnp), `{"hcl_report":"fake"}`)
	lb := fakeLB(t, servingCert, doc)

	cases := []struct {
		name    string
		body    func() map[string]any
		wantErr error
	}{
		{"invalid signature", func() map[string]any {
			b := verifyResponse(bytes.Repeat([]byte{0x42}, ratls.SNPMeasurementSize))
			b["result"].(map[string]any)["signature_valid"] = false
			return b
		}, attestationclient.ErrSignatureInvalid},
		{"measurement not allowed", func() map[string]any {
			return verifyResponse(bytes.Repeat([]byte{0x01}, ratls.SNPMeasurementSize))
		}, attestationclient.ErrMeasurementNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := mockedVerifySrv(t, tc.body())
			_, err := NewVerifiedHTTPClient(context.Background(), lb.URL,
				[][]byte{bytes.Repeat([]byte{0x42}, ratls.SNPMeasurementSize)}, api.URL)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got: %v", tc.wantErr, err)
			}
			if errors.Is(err, ErrNoDiscovery) {
				t.Fatal("verification failure must not signal ErrNoDiscovery (would allow fallback)")
			}
		})
	}
}

// TestNewVerifiedHTTPClient_BindsDocCertToConnection proves the bootstrap
// fails when the document attests a cert other than the leaf the connection's
// handshake presented — a MITM, or a different tls-lb replica answering
// discovery than the one that terminated TLS.
func TestNewVerifiedHTTPClient_BindsDocCertToConnection(t *testing.T) {
	servingCert, _ := plainServingCert(t)
	_, otherLeaf := plainServingCert(t)
	// The doc attests otherLeaf; the server presents servingCert.
	doc := discoveryDoc(t, otherLeaf, []byte("challenge"), "cds", string(types.PlatformAzSnp), `{"hcl_report":"fake"}`)
	lb := fakeLB(t, servingCert, doc)

	api := mockedVerifySrv(t, verifyResponse(nil))

	_, err := NewVerifiedHTTPClient(context.Background(), lb.URL, nil, api.URL)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("different tls-lb replica")) {
		t.Fatalf("want a doc-cert/connection-leaf binding failure, got: %v", err)
	}
	if errors.Is(err, ErrNoDiscovery) {
		t.Fatal("binding failure must not signal ErrNoDiscovery (would allow fallback)")
	}
}

// TestNewVerifiedHTTPClient_PublicTLSModes proves the client accepts only the
// modes whose serving cert the evidence binds: cds (and empty, a pre-mode-field
// document), rejecting webpki and unknown modes with clear errors instead of
// returning a client whose handshakes can never match.
func TestNewVerifiedHTTPClient_PublicTLSModes(t *testing.T) {
	measurement := bytes.Repeat([]byte{0x42}, ratls.SNPMeasurementSize)
	cases := []struct {
		mode    string
		wantErr string // empty = success
	}{
		{"cds", ""},
		{"", ""},
		{"webpki", "public_tls.mode=webpki is not supported"},
		{"acme", `unknown public_tls.mode "acme"`},
	}
	for _, tc := range cases {
		name := tc.mode
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			servingCert, leaf := plainServingCert(t)
			doc := discoveryDoc(t, leaf, []byte("challenge"), tc.mode, string(types.PlatformAzSnp), `{"hcl_report":"fake"}`)
			lb := fakeLB(t, servingCert, doc)
			api := mockedVerifySrv(t, verifyResponse(measurement))

			_, err := NewVerifiedHTTPClient(context.Background(), lb.URL, [][]byte{measurement}, api.URL)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewVerifiedHTTPClient: %v", err)
				}
				return
			}
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(tc.wantErr)) {
				t.Fatalf("want error containing %q, got: %v", tc.wantErr, err)
			}
			if errors.Is(err, ErrNoDiscovery) {
				t.Fatal("mode rejection must not signal ErrNoDiscovery (would allow fallback)")
			}
		})
	}
}

// TestNewVerifiedHTTPClient_FailsClosedOnReconnect proves the client never
// redials once the attested connection is gone: a new handshake could land on
// a different tls-lb replica (per-pod serving certs) that the verified
// document says nothing about.
func TestNewVerifiedHTTPClient_FailsClosedOnReconnect(t *testing.T) {
	servingCert, leaf := plainServingCert(t)
	doc := discoveryDoc(t, leaf, []byte("challenge"), "cds", string(types.PlatformAzSnp), `{"hcl_report":"fake"}`)
	lb := fakeLB(t, servingCert, doc)
	measurement := bytes.Repeat([]byte{0x42}, ratls.SNPMeasurementSize)
	api := mockedVerifySrv(t, verifyResponse(measurement))

	hc, err := NewVerifiedHTTPClient(context.Background(), lb.URL, [][]byte{measurement}, api.URL)
	if err != nil {
		t.Fatalf("NewVerifiedHTTPClient: %v", err)
	}
	resp, err := hc.Get(lb.URL + "/allowlist")
	if err != nil {
		t.Fatalf("GET on the attested connection: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	lb.CloseClientConnections()

	if _, err := hc.Get(lb.URL + "/allowlist"); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("re-run the command")) {
		t.Fatalf("want a fail-closed redial refusal, got: %v", err)
	}
}

// TestNewVerifiedHTTPClient_RequiresHTTPS proves a non-https URL is rejected
// outright: the trust model binds attestation to a TLS handshake, which
// plaintext has none of.
func TestNewVerifiedHTTPClient_RequiresHTTPS(t *testing.T) {
	_, err := NewVerifiedHTTPClient(context.Background(), "http://cds.example", nil, "http://attestation-api")
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("scheme must be https")) {
		t.Fatalf("want an https-scheme error, got: %v", err)
	}
}
