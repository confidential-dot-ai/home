package attestclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lunal-dev/c8s/pkg/types"
)

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	c := NewClient("http://example.com/api/")
	if c.baseURL != "http://example.com/api" {
		t.Fatalf("expected trailing slash trimmed, got %q", c.baseURL)
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.ChallengeResponse{
			Challenge: "dGVzdC1jaGFsbGVuZ2U=",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	resp, err := c.Authenticate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Challenge != "dGVzdC1jaGFsbGVuZ2U=" {
		t.Fatalf("expected challenge 'dGVzdC1jaGFsbGVuZ2U=', got %q", resp.Challenge)
	}
}

func TestObtainCertificateWithEvidenceReturnsAttestationMaterial(t *testing.T) {
	const challenge = "dGVzdC1jaGFsbGVuZ2U="
	const certPEM = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"

	csrPEM := testCSRPEM(t)
	challengeBytes := []byte("test-challenge")
	expectedReportData, err := reportDataForCSR(csrPEM, challengeBytes)
	if err != nil {
		t.Fatalf("reportDataForCSR: %v", err)
	}

	var attestationServiceSawReportData []byte
	attestationService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			t.Fatalf("attestation service path = %s, want /attest", r.URL.Path)
		}
		var req types.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode attestation request: %v", err)
		}
		attestationServiceSawReportData = append([]byte(nil), req.ReportData.Bytes()...)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"platform":"snp","evidence":{"quote":"abc"}}`)
	}))
	defer attestationService.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: challenge})
	})
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		var req attestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode assam attest request: %v", err)
		}
		if req.Challenge != challenge {
			t.Fatalf("challenge = %q, want %q", req.Challenge, challenge)
		}
		if req.Evidence.Platform != "snp" {
			t.Fatalf("platform = %q, want snp", req.Evidence.Platform)
		}
		if !strings.Contains(string(req.Evidence.Evidence), `"quote":"abc"`) {
			t.Fatalf("evidence = %s, want quote", req.Evidence.Evidence)
		}
		_, _ = io.WriteString(w, certPEM)
	})
	assam := httptest.NewServer(mux)
	defer assam.Close()

	client := NewClientWithHTTP(assam.URL, assam.Client())
	result, err := client.ObtainCertificateWithEvidence(attestationService.URL, csrPEM)
	if err != nil {
		t.Fatalf("ObtainCertificateWithEvidence: %v", err)
	}

	if result.Certificate != certPEM {
		t.Fatalf("certificate = %q, want %q", result.Certificate, certPEM)
	}
	if result.Challenge != challenge {
		t.Fatalf("challenge = %q, want %q", result.Challenge, challenge)
	}
	if result.Platform != "snp" {
		t.Fatalf("platform = %q, want snp", result.Platform)
	}
	if !strings.Contains(string(result.Evidence), `"quote":"abc"`) {
		t.Fatalf("evidence = %s, want quote", result.Evidence)
	}
	if !bytes.Equal(attestationServiceSawReportData, expectedReportData) {
		t.Fatalf("report_data = %x, want key-bound challenge %x", attestationServiceSawReportData, expectedReportData)
	}
}

func testCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate csr key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-node"},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func TestObtainCertificateWithEvidenceContextCanceled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("authenticate handler should not be called after context cancellation")
	})
	assam := httptest.NewServer(mux)
	defer assam.Close()

	client := NewClientWithHTTP(assam.URL, assam.Client())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.ObtainCertificateWithEvidenceContext(ctx, "http://127.0.0.1:1", "csr")
	if err == nil {
		t.Fatal("ObtainCertificateWithEvidenceContext succeeded with canceled context")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("error = %v, want context canceled", err)
	}
}

func TestHealthzSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	ok, err := c.Healthz()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected healthz to return true")
	}
}

func TestReadyzSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	ok, err := c.Readyz()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected readyz to return true")
	}
}
