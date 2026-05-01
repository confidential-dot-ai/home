package nodecontainerwhitelist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/pkg/whitelist"
	"github.com/lunal-dev/c8s/pkg/whitelistclient"
)

func validWhitelistJSON() string {
	return `{"version":"1","digests":{"sha256:` + strings.Repeat("a", 64) + `":"img1"}}`
}

func newTestClient(url string) whitelistclient.Client {
	return whitelistclient.NewClientWithHTTP(url, &http.Client{Timeout: 5 * time.Second})
}

func TestFetchWhitelist_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(validWhitelistJSON()))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	wl, err := client.FetchWhitelist(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(wl.Digests) != 1 {
		t.Fatalf("expected 1 digest, got %d", len(wl.Digests))
	}
}

func TestFetchWhitelist_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.FetchWhitelist(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchWhitelist_MissingContentTypeHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(validWhitelistJSON()))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.FetchWhitelist(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchWhitelist_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.FetchWhitelist(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFetchWhitelist_EmptyDigests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":"1","digests":{}}`))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.FetchWhitelist(context.Background())
	if err == nil {
		t.Fatal("expected error for empty digests")
	}
}

func TestFetchWithRetries_SuccessOnSecondAttempt(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(validWhitelistJSON()))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	wl, err := fetchWithRetries(context.Background(), client, 3, 10*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(wl.Digests) != 1 {
		t.Fatalf("expected 1 digest, got %d", len(wl.Digests))
	}
}

func TestFetchWithRetries_AllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := fetchWithRetries(context.Background(), client, 3, 10*time.Millisecond, 5*time.Second)
	if err == nil {
		t.Fatal("expected error after all retries exhausted")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("failed after %d attempts", 3)) {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRespondJSON(t *testing.T) {
	w := httptest.NewRecorder()
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %s", body["status"])
	}
}

func TestServerGetSet(t *testing.T) {
	srv := &server{}
	if srv.get() != nil {
		t.Error("expected nil whitelist initially")
	}

	wl := &whitelist.Whitelist{
		Version: "1",
		Digests: map[string]string{"sha256:" + strings.Repeat("a", 64): "img"},
	}
	srv.set(wl)

	got := srv.get()
	if got == nil {
		t.Fatal("expected non-nil whitelist after set")
	}
	if len(got.Digests) != 1 {
		t.Errorf("expected 1 digest, got %d", len(got.Digests))
	}
}

func TestHealthzHandler_Ready(t *testing.T) {
	wl := &whitelist.Whitelist{
		Version: "1",
		Digests: map[string]string{"sha256:" + strings.Repeat("a", 64): "img"},
	}
	srv := &server{wl: wl}

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if srv.get() != nil {
			respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		} else {
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
		}
	})
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHealthzHandler_NotReady(t *testing.T) {
	srv := &server{}

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if srv.get() != nil {
			respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		} else {
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
		}
	})
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}
