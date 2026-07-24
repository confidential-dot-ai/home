package secretspolicy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHandler(t *testing.T, authz WriteAuthorizer) (Handler, func()) {
	t.Helper()
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	return Handler{Store: &store, WriteAuthorizer: authz}, func() { store.Close() }
}

func allow(*http.Request, []byte) error { return nil }
func deny(*http.Request, []byte) error  { return fmt.Errorf("no") }

func do(h Handler, method, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/secrets-policy", strings.NewReader(body))
	rec := httptest.NewRecorder()
	switch method {
	case http.MethodGet:
		h.HandleList(rec, req)
	case http.MethodPost:
		h.HandlePut(rec, req)
	case http.MethodPut:
		h.HandleReplace(rec, req)
	case http.MethodDelete:
		h.HandleDelete(rec, req)
	}
	return rec
}

// Writes require operator authorization; a denied write never mutates the store.
func TestWritesRequireAuthorization(t *testing.T) {
	h, done := newTestHandler(t, deny)
	defer done()

	rec := do(h, http.MethodPost, `{"workloadDigest":"aabb","allow":["secret/data/x"]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("denied write: code = %d, want 401", rec.Code)
	}
	if _, entries, _ := h.Store.ListAll(); len(entries) != 0 {
		t.Fatalf("store mutated despite denied auth: %v", entries)
	}
}

// A nil WriteAuthorizer (no operator keys) closes the write path entirely.
func TestWritesDisabledWithoutAuthorizer(t *testing.T) {
	h, done := newTestHandler(t, nil)
	defer done()
	if rec := do(h, http.MethodPost, `{"workloadDigest":"aa","allow":["x"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

// Put then List round-trips; the ETag version bumps on each mutation.
func TestPutListRoundTrip(t *testing.T) {
	h, done := newTestHandler(t, allow)
	defer done()

	if rec := do(h, http.MethodPost, `{"workloadDigest":"AABB","allow":["secret/data/api/*#password"]}`); rec.Code != http.StatusNoContent {
		t.Fatalf("put: code = %d", rec.Code)
	}
	rec := do(h, http.MethodGet, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: code = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"aabb"`) { // stored lowercased
		t.Fatalf("list missing digest: %s", rec.Body.String())
	}
	if et := rec.Header().Get("ETag"); et != `W/"2"` {
		t.Fatalf("ETag = %q, want W/\"2\" after one mutation", et)
	}
}

// Replace with a nil entries list is rejected (would silently clear the policy);
// an explicit empty list clears it.
func TestReplaceNilRejected(t *testing.T) {
	h, done := newTestHandler(t, allow)
	defer done()
	if rec := do(h, http.MethodPut, `{}`); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("nil replace: code = %d, want 422", rec.Code)
	}
	if rec := do(h, http.MethodPut, `{"entries":[]}`); rec.Code != http.StatusNoContent {
		t.Fatalf("empty replace: code = %d, want 204", rec.Code)
	}
}
