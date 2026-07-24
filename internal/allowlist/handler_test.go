package allowlist_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/readiness"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	digestA       = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	digestMissing = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// testOperatorCredential generates an operator key pair: a Signer for minting
// write tokens and the public key CDS would pin.
func testOperatorCredential(t *testing.T) (*operatorauth.Signer, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen operator key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal operator key: %v", err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatalf("new operator signer: %v", err)
	}
	return signer, &key.PublicKey
}

// authHeader mints an operator token bound to method + /allowlist + body and
// returns it as a Bearer header value. Callers MUST pass the exact method and
// bytes the server will receive — any difference breaks the token's bindings.
func authHeader(t *testing.T, signer *operatorauth.Signer, method string, body []byte) string {
	t.Helper()
	header, err := signer.Authorization(method, "/allowlist", body)
	if err != nil {
		t.Fatalf("mint operator token: %v", err)
	}
	return header
}

func testAllowlistApp(t *testing.T) (http.Handler, *readiness.Checker, *operatorauth.Signer) {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}

	signer, pub := testOperatorCredential(t)

	asClient := attestationclient.NewClient("http://localhost:0")
	checker := readiness.NewChecker(asClient, 10*time.Second)

	// Writes authorize through the production operatorauth.Verifier, so these
	// tests exercise the same auth path a deployment runs.
	wh := allowlist.Handler{
		Store:           &store,
		WriteAuthorizer: operatorauth.Verifier{Keys: []*ecdsa.PublicKey{pub}, ClockSkew: 30 * time.Second}.Authorize,
	}

	return allowlistTestRouter(wh, checker.Ready), &checker, signer
}

// allowlistTestRouter mounts only the routes the allowlist tests exercise, so
// these unit tests don't depend on the full server router.
func allowlistTestRouter(wh allowlist.Handler, ready attestation.ReadinessFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", attestation.HandleReadyz(ready))
	mux.HandleFunc("GET /allowlist", wh.HandleList)
	mux.HandleFunc("POST /allowlist", wh.HandleAdd)
	mux.HandleFunc("PUT /allowlist", wh.HandleReplace)
	mux.HandleFunc("DELETE /allowlist", wh.HandleDelete)
	return mux
}

func TestHealthzReturnsOK(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
}

func TestReadyzReturnsUnavailableInitially(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want 503", resp.StatusCode)
	}
}

func TestAllowlistListEmpty(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/allowlist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var version string
	if err := json.Unmarshal(raw["version"], &version); err != nil {
		t.Fatalf("unmarshal version: %v", err)
	}
	if version != "1" {
		t.Fatalf("version = %q, want 1", version)
	}

	var digests map[string]string
	if err := json.Unmarshal(raw["digests"], &digests); err != nil {
		t.Fatalf("unmarshal digests: %v", err)
	}
	if len(digests) != 0 {
		t.Fatalf("expected empty digests, got %d entries", len(digests))
	}
}

func TestAllowlistReplaceRequiresAuth(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digests":{"%s":"test-image"}}`, digestA)
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

// TestAllowlistReplaceSwapsSet verifies PUT is a full replace: an entry present
// before the replace and absent from the new set is gone afterward.
func TestAllowlistReplaceSwapsSet(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	// Seed digestA via POST.
	addBody := fmt.Sprintf(`{"digest":"%s","image":"old-image"}`, digestA)
	addReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/allowlist", strings.NewReader(addBody))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("Authorization", authHeader(t, signer, http.MethodPost, []byte(addBody)))
	addResp, err := http.DefaultClient.Do(addReq)
	if err != nil {
		t.Fatalf("add request: %v", err)
	}
	addResp.Body.Close()
	if addResp.StatusCode != http.StatusNoContent {
		t.Fatalf("add: got %d, want 204", addResp.StatusCode)
	}

	// Replace with a set containing only digestMissing.
	putBody := fmt.Sprintf(`{"digests":{"%s":"new-image"}}`, digestMissing)
	putReq, _ := http.NewRequest(http.MethodPut, srv.URL+"/allowlist", strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, []byte(putBody)))
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent {
		t.Fatalf("put: got %d, want 204", putResp.StatusCode)
	}

	// GET and confirm the set is exactly {digestMissing}.
	resp, err := http.Get(srv.URL + "/allowlist")
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	defer resp.Body.Close()
	var listed types.AllowlistListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Digests) != 1 {
		t.Fatalf("expected exactly 1 digest after replace, got %d", len(listed.Digests))
	}
	newDigest, _ := types.ParseDigest(digestMissing)
	if listed.Digests[newDigest] != "new-image" {
		t.Fatalf("replaced set missing new entry: %#v", listed.Digests)
	}
	oldDigest, _ := types.ParseDigest(digestA)
	if _, ok := listed.Digests[oldDigest]; ok {
		t.Fatal("old entry survived a full replace")
	}
}

// guardTestHandler builds a Handler with a permissive authorizer, for tests of
// the post-auth request-decoding guards.
func guardTestHandler(t *testing.T) (allowlist.Handler, *allowlist.Store) {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	h := allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }}
	return h, &store
}

// TestAllowlistReplaceRejectsNilDigests pins the wipe guard: a body whose
// digests decode to a nil map (absent or null) must 422 without touching the
// store, since clearing the allowlist denies every image on every node.
func TestAllowlistReplaceRejectsNilDigests(t *testing.T) {
	h, store := guardTestHandler(t)
	d, _ := types.ParseDigest(digestA)
	if err := store.Add(d, "img"); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	versionBefore, _, _ := store.ListAll()

	for _, body := range []string{`{}`, `{"digests":null}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(body))
		h.HandleReplace(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("PUT %s: got status %d, want 422", body, rec.Code)
		}
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(digests) != 1 || version != versionBefore {
		t.Fatalf("nil-digests PUT must not change the allowlist: %d entries, version %s -> %s",
			len(digests), versionBefore, version)
	}
}

// TestAllowlistReplaceExplicitEmptyClears verifies the deliberate wipe path
// stays open: a non-nil empty set clears the allowlist.
func TestAllowlistReplaceExplicitEmptyClears(t *testing.T) {
	h, store := guardTestHandler(t)
	d, _ := types.ParseDigest(digestA)
	if err := store.Add(d, "img"); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(`{"digests":{}}`))
	h.HandleReplace(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want 204", rec.Code)
	}

	_, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(digests) != 0 {
		t.Fatalf("explicit empty replace left %d entries", len(digests))
	}
}

// TestAllowlistAddRejectsMissingDigest pins the zero-digest guard: an absent
// digest field skips Digest's validating UnmarshalJSON, and the row it would
// insert is invisible to ListAll and unaddressable by Delete.
func TestAllowlistAddRejectsMissingDigest(t *testing.T) {
	h, store := guardTestHandler(t)
	versionBefore, _, _ := store.ListAll()

	for _, body := range []string{`{}`, `{"image":"ghost"}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/allowlist", strings.NewReader(body))
		h.HandleAdd(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("POST %s: got status %d, want 422", body, rec.Code)
		}
	}

	// The version pins the no-insert invariant: ListAll hides a zero-digest
	// row, but inserting one would still have bumped the version.
	version, _, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if version != versionBefore {
		t.Fatalf("zero-digest POST bumped version %s -> %s (ghost row inserted)", versionBefore, version)
	}
}

func TestAllowlistAddRequiresAuth(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digest":"%s","image":"test-image"}`, digestA)
	resp, err := http.Post(srv.URL+"/allowlist", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

// TestAllowlistAddRejectsUnpinnedOperatorKey proves a well-formed token signed
// by a key CDS does not pin is rejected at the handler level.
func TestAllowlistAddRejectsUnpinnedOperatorKey(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	otherSigner, _ := testOperatorCredential(t) // not the pinned key
	body := fmt.Sprintf(`{"digest":"%s","image":"test-image"}`, digestA)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, otherSigner, http.MethodPost, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func addDigest(t *testing.T, srvURL string, signer *operatorauth.Signer, digest, image string) {
	t.Helper()
	body := fmt.Sprintf(`{"digest":"%s","image":"%s"}`, digest, image)
	req, err := http.NewRequest(http.MethodPost, srvURL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPost, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("add digest got status %d, want 204", resp.StatusCode)
	}
}

func TestAllowlistAddAndListRoundtrip(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	addDigest(t, srv.URL, signer, digestA, "test-image")

	resp, err := http.Get(srv.URL + "/allowlist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	var result types.AllowlistListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	expectedDigest, _ := types.ParseDigest(digestA)
	img, ok := result.Digests[expectedDigest]
	if !ok {
		t.Fatal("digest not found in allowlist")
	}
	if img != "test-image" {
		t.Fatalf("image = %q, want test-image", img)
	}

	// version should have been incremented from "1" to "2"
	if result.Version != "2" {
		t.Fatalf("version = %q, want 2", result.Version)
	}
}

func TestAllowlistDeleteExistingReturnsNoContent(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	addDigest(t, srv.URL, signer, digestA, "test-image")

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestA)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodDelete, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("got status %d, want 204", resp.StatusCode)
	}

	// verify empty
	listResp, err := http.Get(srv.URL + "/allowlist")
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	defer listResp.Body.Close()

	var result types.AllowlistListResponse
	if err := json.NewDecoder(listResp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result.Digests) != 0 {
		t.Fatalf("expected empty digests, got %d", len(result.Digests))
	}
}

func TestAllowlistDeleteNonexistentReturnsNotFound(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestMissing)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodDelete, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got status %d, want 404", resp.StatusCode)
	}
}

func TestAllowlistDeleteRequiresAuth(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestA)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// no auth header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func TestAllowlistAddRejectsInvalidDigest(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := `{"digest":"sha256:abc","image":"test-image"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPost, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("got status %d, want 422", resp.StatusCode)
	}
}

// TestAllowlistAddRejectsReplayWithDifferentBody is the H2 regression test:
// a captured operator token for one body MUST NOT authorize a different body
// within the token's TTL.
func TestAllowlistAddRejectsReplayWithDifferentBody(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	// Token is bound to the legitimate digestA body.
	originalBody := fmt.Sprintf(`{"digest":"%s","image":"trusted-image"}`, digestA)
	header := authHeader(t, signer, http.MethodPost, []byte(originalBody))

	// Attacker replays the same token but ships a different digest.
	attackerBody := fmt.Sprintf(`{"digest":"%s","image":"attacker-image"}`, digestMissing)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist", strings.NewReader(attackerBody))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", header)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("captured token authorized a different body: got status %d, want 401", resp.StatusCode)
	}
}

// TestAllowlistAddRejectsBodyOverConfiguredCap confirms the per-Handler cap
// is honoured: an over-cap body returns 413 *before* the auth check runs
// (so the handler doesn't burn CPU hashing megabytes a malicious caller
// supplied).
func TestAllowlistAddRejectsBodyOverConfiguredCap(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	signer, pub := testOperatorCredential(t)
	asClient := attestationclient.NewClient("http://localhost:0")
	checker := readiness.NewChecker(asClient, 10*time.Second)
	wh := allowlist.Handler{
		Store:             &store,
		WriteAuthorizer:   operatorauth.Verifier{Keys: []*ecdsa.PublicKey{pub}, ClockSkew: 30 * time.Second}.Authorize,
		MaxWriteBodyBytes: 64,
	}
	srv := httptest.NewServer(allowlistTestRouter(wh, checker.Ready))
	defer srv.Close()

	body := strings.Repeat("x", 1024)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPost, []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap body got status %d, want 413", resp.StatusCode)
	}
}

func TestAllowlistListEmitsETag(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/allowlist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != `W/"1"` {
		t.Fatalf("ETag = %q, want W/\"1\"", got)
	}
}

func TestAllowlistListMatchingIfNoneMatchReturns304(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/allowlist", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("If-None-Match", `W/"1"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != `W/"1"` {
		t.Fatalf("ETag = %q, want W/\"1\"", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("304 body should be empty, got %d bytes", len(body))
	}
}

func TestAllowlistListStaleIfNoneMatchReturns200WithNewETag(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	addDigest(t, srv.URL, signer, digestA, "test-image")

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/allowlist", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("If-None-Match", `W/"1"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != `W/"2"` {
		t.Fatalf("ETag = %q, want W/\"2\"", got)
	}
}

// TestAllowlistWritesRejectedWithoutAuthorizer pins the fail-closed default:
// a Handler wired without a WriteAuthorizer refuses every mutation.
func TestAllowlistWritesRejectedWithoutAuthorizer(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	h := allowlist.Handler{Store: &store}

	body := fmt.Sprintf(`{"digest":"%s","image":"img"}`, digestA)
	rec := httptest.NewRecorder()
	h.HandleAdd(rec, httptest.NewRequest(http.MethodPost, "/allowlist", strings.NewReader(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST without authorizer: got status %d, want 401", rec.Code)
	}
}

// TestAllowlistMutationsRejectMalformedBody covers the decode guards on every
// mutation: syntactically invalid JSON and unknown fields both 422.
func TestAllowlistMutationsRejectMalformedBody(t *testing.T) {
	h, _ := guardTestHandler(t)

	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		body    string
	}{
		{"add invalid json", h.HandleAdd, http.MethodPost, `{`},
		{"add unknown field", h.HandleAdd, http.MethodPost, `{"digest":"` + digestA + `","bogus":1}`},
		{"delete invalid json", h.HandleDelete, http.MethodDelete, `{`},
		{"delete unknown field", h.HandleDelete, http.MethodDelete, `{"digests":["` + digestA + `"],"bogus":1}`},
		{"replace invalid json", h.HandleReplace, http.MethodPut, `{`},
		{"replace unknown field", h.HandleReplace, http.MethodPut, `{"digests":{},"bogus":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler(rec, httptest.NewRequest(tc.method, "/allowlist", strings.NewReader(tc.body)))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("got status %d, want 422", rec.Code)
			}
		})
	}
}

// TestAllowlistHandlersReturn500OnStoreFailure drives every handler against a
// store whose DB is closed, so the storage layer errors surface as 500s.
func TestAllowlistHandlersReturn500OnStoreFailure(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	h := allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }}

	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		body    string
	}{
		{"list", h.HandleList, http.MethodGet, ""},
		{"add", h.HandleAdd, http.MethodPost, fmt.Sprintf(`{"digest":"%s","image":"img"}`, digestA)},
		{"delete", h.HandleDelete, http.MethodDelete, fmt.Sprintf(`{"digests":["%s"]}`, digestA)},
		{"replace", h.HandleReplace, http.MethodPut, fmt.Sprintf(`{"digests":{"%s":"img"}}`, digestA)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler(rec, httptest.NewRequest(tc.method, "/allowlist", strings.NewReader(tc.body)))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("got status %d, want 500", rec.Code)
			}
		})
	}
}
