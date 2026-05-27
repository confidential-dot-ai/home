package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/internal/attestation"
	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/types"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newMockAttestationService(t *testing.T, launchDigest string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		match := true
		resp := types.VerifyResponse{
			Result: types.VerificationResult{
				Platform:        "snp",
				SignatureValid:  true,
				ReportDataMatch: &match,
				Claims:          types.Claims{LaunchDigest: launchDigest},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func generateCSR(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	return generateCSRWith(t, pkix.Name{CommonName: "test-node"}, nil, nil)
}

func generateCSRWith(t *testing.T, subject pkix.Name, dnsNames []string, ips []net.IP) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: subject, DNSNames: dnsNames, IPAddresses: ips}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

func newTestAttestHandler(t *testing.T, mockURL string, allowedMeasurements map[string]bool) AttestHandler {
	t.Helper()
	ca, err := issuer.NewCA("test ca", 2*issuer.MaxLeafTTL)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	store := attestation.NewChallengeStore(30 * time.Second)
	return AttestHandler{
		Challenges:        &store,
		AttestationClient: attestationclient.NewClient(mockURL),
		CA:                ca,
		CAChainPEM:        certutil.EncodeCertPEM(ca.Cert.Raw),
		CertTTL:           time.Hour,
		Measurements:      allowedMeasurements,
	}
}

func issueChallenge(t *testing.T, h AttestHandler) string {
	t.Helper()
	c := h.Challenges.Create()
	return base64.StdEncoding.EncodeToString(c[:])
}

func postAttest(t *testing.T, h AttestHandler, challenge, csrPEM string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence:  types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{"test":true}`)},
		CSR:       csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	return w
}

func leafFromAttestResponse(t *testing.T, w *httptest.ResponseRecorder) *x509.Certificate {
	t.Helper()
	chain, err := certutil.ParsePEMCertificates(w.Body.Bytes())
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	if len(chain) == 0 {
		t.Fatalf("empty certificate chain")
	}
	return chain[0]
}

func TestAttest_InProcessSignAndReturnsChain(t *testing.T) {
	mock := newMockAttestationService(t, "deadbeef")
	h := newTestAttestHandler(t, mock.URL, nil)
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("content-type: got %q, want application/x-pem-file", ct)
	}
	chain, err := certutil.ParsePEMCertificates(w.Body.Bytes())
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length: got %d, want leaf + CA", len(chain))
	}
	leaf := chain[0]
	ca := chain[1]
	if !bytes.Equal(ca.Raw, h.CA.Cert.Raw) {
		t.Fatalf("CA bundle cert does not match handler CA")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("leaf not signed by handler CA: %v", err)
	}
	if leaf.Subject.CommonName != "test-node" {
		t.Errorf("CN: got %q, want test-node", leaf.Subject.CommonName)
	}
}

func TestAttest_ClampsCertTTLBeforeSigning(t *testing.T) {
	mock := newMockAttestationService(t, "deadbeef")
	base := newTestAttestHandler(t, mock.URL, nil)
	for _, tc := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{"above max", issuer.MaxLeafTTL + time.Hour, issuer.MaxLeafTTL},
		{"zero", 0, issuer.DefaultLeafTTL},
		{"negative", -time.Hour, issuer.DefaultLeafTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := base
			h.CertTTL = tc.configured
			challenge := issueChallenge(t, h)
			csrPEM, _ := generateCSR(t)

			w := postAttest(t, h, challenge, csrPEM)
			if w.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
			}

			leaf := leafFromAttestResponse(t, w)
			got := leaf.NotAfter.Sub(leaf.NotBefore)
			if got < tc.want-time.Minute || got > tc.want+time.Minute {
				t.Fatalf("leaf TTL = %v, want ~%v", got, tc.want)
			}
		})
	}
}

func TestAttest_LaunchDigestAllowlistAllowed(t *testing.T) {
	mock := newMockAttestationService(t, "approved-digest")
	h := newTestAttestHandler(t, mock.URL, map[string]bool{"approved-digest": true})
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_LaunchDigestAllowlistCaseInsensitive(t *testing.T) {
	mock := newMockAttestationService(t, "DEADBEEF")
	h := newTestAttestHandler(t, mock.URL, map[string]bool{"deadbeef": true})
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("uppercase digest with lowercase allowlist: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_LaunchDigestAllowlistDenied(t *testing.T) {
	mock := newMockAttestationService(t, "unknown-digest")
	h := newTestAttestHandler(t, mock.URL, map[string]bool{"approved-digest": true})
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "measurement_denied") {
		t.Errorf("body should mention measurement_denied; got %s", w.Body.String())
	}
}

func TestAttest_TimeoutBeforeSigningReturns504(t *testing.T) {
	h := newTestAttestHandler(t, "http://attestation.test", nil)
	ctx, cancel := context.WithCancel(context.Background())
	h.AttestationClient = attestationclient.NewClientWithHTTP("http://attestation.test", &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cancel()
			match := true
			resp := types.VerifyResponse{
				Result: types.VerificationResult{
					Platform:        "snp",
					SignatureValid:  true,
					ReportDataMatch: &match,
					Claims:          types.Claims{LaunchDigest: "deadbeef"},
				},
			}
			var body bytes.Buffer
			if err := json.NewEncoder(&body).Encode(resp); err != nil {
				t.Fatalf("encode verify response: %v", err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(&body),
				Request:    req,
			}, nil
		}),
	})
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence:  types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{"test":true}`)},
		CSR:       csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("status: got %d, want 504; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), types.ErrorCodeTimeout) {
		t.Errorf("body should mention timeout; got %s", w.Body.String())
	}
}

func TestAttest_ConsumedChallengeRejectsReplay(t *testing.T) {
	mock := newMockAttestationService(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	if w := postAttest(t, h, challenge, csrPEM); w.Code != http.StatusOK {
		t.Fatalf("first attest: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replayed challenge: got %d, want 400", w.Code)
	}
}

func TestAttest_BadCSRRejected(t *testing.T) {
	mock := newMockAttestationService(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	challenge := issueChallenge(t, h)

	w := postAttest(t, h, challenge, "not a pem")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
}

func TestAttest_RejectsCSRWithUnconfiguredDNSSAN(t *testing.T) {
	mock := newMockAttestationService(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSRWith(t, pkix.Name{CommonName: "node"}, []string{"foo.mesh.svc"}, nil)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "DNS SAN") {
		t.Errorf("body should mention DNS SAN; got %s", w.Body.String())
	}
}

func TestAttest_AcceptsCSRWithAllowedDNSSAN(t *testing.T) {
	mock := newMockAttestationService(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.Policy.DNSSANPattern = regexp.MustCompile(`^[a-z]+\.mesh\.svc$`)
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSRWith(t, pkix.Name{CommonName: "node"}, []string{"foo.mesh.svc"}, nil)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsCSRWithBadCN(t *testing.T) {
	mock := newMockAttestationService(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.Policy.AllowedCNPattern = regexp.MustCompile(`^ratls-mesh-[0-9.]+$`)
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSRWith(t, pkix.Name{CommonName: "evil"}, nil, nil)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsCSRWithMismatchedSourceIP(t *testing.T) {
	mock := newMockAttestationService(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.SANValidation = true
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSRWith(t, pkix.Name{CommonName: "node"}, nil, []net.IP{net.ParseIP("10.0.0.99")})

	// httptest.NewRequest defaults RemoteAddr to "192.0.2.1:1234"; the CSR's
	// 10.0.0.99 IP SAN should not match.
	body, _ := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence:  types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		CSR:       csrPEM,
	})
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsCSRWithIPSANWhenSANValidationDisabled(t *testing.T) {
	mock := newMockAttestationService(t, "x")
	h := newTestAttestHandler(t, mock.URL, nil)
	// SANValidation defaults to false, leaving Policy.SourceIP empty.
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSRWith(t, pkix.Name{CommonName: "node"}, nil, []net.IP{net.ParseIP("10.0.0.99")})

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_AttestationServiceFailureReturns502(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(down.Close)
	h := newTestAttestHandler(t, down.URL, nil)
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502; body=%s", w.Code, w.Body.String())
	}
}
