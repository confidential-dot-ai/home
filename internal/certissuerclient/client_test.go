package certissuerclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/pkg/types"
)

func TestSignCSRSuccess(t *testing.T) {
	leafPEM := testCertificatePEM(t, "leaf")
	caPEM := testCertificatePEM(t, "ca")

	mux := http.NewServeMux()
	mux.HandleFunc("/sign-csr", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req types.SignCsrRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.SignCsrResponse{
			Certificate:   leafPEM,
			CACertificate: caPEM,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	cert, err := c.SignCSR(context.Background(), "ear-token", "csr-pem", "1h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert != leafPEM+caPEM {
		t.Fatalf("expected certificate chain, got %q", cert)
	}
}

func TestSignCSRRejectsInvalidCertificatePEM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign-csr", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.SignCsrResponse{
			Certificate:   "not a certificate",
			CACertificate: testCertificatePEM(t, "ca"),
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	_, err := c.SignCSR(context.Background(), "ear-token", "csr-pem", "1h")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSignCSRAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign-csr", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid csr"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	_, err := c.SignCSR(context.Background(), "ear-token", "bad-csr", "1h")
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Status != 400 {
		t.Fatalf("expected status 400, got %d", apiErr.Status)
	}
	if apiErr.Body != "invalid csr" {
		t.Fatalf("expected body 'invalid csr', got %q", apiErr.Body)
	}
}

func TestReadySuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	ok, err := c.Ready(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected ready to return true")
	}
}

func TestReadyWhenDown(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	ok, err := c.Ready(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ready to return false")
	}
}

func testCertificatePEM(t *testing.T, commonName string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
