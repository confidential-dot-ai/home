package whitelistclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lunal-dev/c8s/pkg/types"
)

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	c := NewClient("http://example.com/api/")
	if c.baseURL != "http://example.com/api" {
		t.Fatalf("expected trailing slash trimmed, got %q", c.baseURL)
	}
}

func TestListSuccess(t *testing.T) {
	digest1, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	digest2, _ := types.ParseDigest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	mux := http.NewServeMux()
	mux.HandleFunc("/whitelist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.WhitelistListResponse{
			Version: "1.0",
			Digests: map[types.Digest]string{
				digest1: "image-a",
				digest2: "image-b",
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	resp, err := c.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Version != "1.0" {
		t.Fatalf("expected version 1.0, got %q", resp.Version)
	}
	if len(resp.Digests) != 2 {
		t.Fatalf("expected 2 digests, got %d", len(resp.Digests))
	}
}

func TestAddSuccess(t *testing.T) {
	digest, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	earToken := []byte("test-ear")

	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/whitelist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	err := c.Add(digest, "my-image", earToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedAuth := "Bearer " + string(earToken)
	if gotAuth != expectedAuth {
		t.Fatalf("expected auth header %q, got %q", expectedAuth, gotAuth)
	}
}

func TestDeleteSuccess(t *testing.T) {
	digest, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	mux := http.NewServeMux()
	mux.HandleFunc("/whitelist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	err := c.Delete([]types.Digest{digest}, []byte("test-ear"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	digest, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	mux := http.NewServeMux()
	mux.HandleFunc("/whitelist", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	err := c.Delete([]types.Digest{digest}, []byte("test-ear"))
	if err == nil {
		t.Fatal("expected error")
	}

	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected StatusError, got %T: %v", err, err)
	}
	if statusErr.Status != 404 {
		t.Fatalf("expected status 404, got %d", statusErr.Status)
	}
}
