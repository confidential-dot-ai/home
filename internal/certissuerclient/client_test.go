package certissuerclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lunal-dev/c8s/pkg/types"
)

func TestSignCSRSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sign-csr", func(w http.ResponseWriter, r *http.Request) {
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
			Certificate: "pem-data",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	cert, err := c.SignCSR(context.Background(), "ear-token", "csr-pem", "1h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert != "pem-data" {
		t.Fatalf("expected certificate 'pem-data', got %q", cert)
	}
}

func TestSignCSRAPIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sign-csr", func(w http.ResponseWriter, r *http.Request) {
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
