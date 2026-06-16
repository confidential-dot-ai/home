package allowlistclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
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
	mux.HandleFunc("/allowlist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.AllowlistListResponse{
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
	resp, err := c.List(context.Background())
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
	mux.HandleFunc("/allowlist", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/allowlist", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/allowlist", func(w http.ResponseWriter, r *http.Request) {
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

func TestFetchAllowlistConditionalAcceptsJSONContentTypeWithCharset(t *testing.T) {
	digest, _ := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", `W/"1"`)
		_ = json.NewEncoder(w).Encode(types.AllowlistListResponse{
			Version: "1",
			Digests: map[types.Digest]string{
				digest: "image-a",
			},
		})
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	wl, etag, notModified, err := c.FetchAllowlistConditional(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if notModified {
		t.Fatal("expected 200 response, got notModified")
	}
	if etag != `W/"1"` {
		t.Fatalf("etag = %q, want W/\"1\"", etag)
	}
	if got := wl.Digests[digest.String()]; got != "image-a" {
		t.Fatalf("digest missing from allowlist: %q", got)
	}
}

func TestFetchAllowlistConditionalRejectsOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"big"`)
		w.WriteHeader(http.StatusOK)
		// Stream more bytes than the cap. The body is junk; we expect the
		// cap to trip before ParseJSON ever runs.
		chunk := strings.Repeat("a", 64*1024)
		written := int64(0)
		for written <= maxAllowlistResponseBytes {
			n, err := w.Write([]byte(chunk))
			if err != nil {
				return
			}
			written += int64(n)
		}
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, &http.Client{Timeout: 5 * time.Second})
	_, _, _, err := c.FetchAllowlistConditional(context.Background(), "")
	if !errors.Is(err, errAllowlistResponseTooLarge) {
		t.Fatalf("expected errAllowlistResponseTooLarge, got %v", err)
	}
}
