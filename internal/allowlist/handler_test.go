package allowlist_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/readiness"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
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

// authHeader mints an operator token bound to method + path + body and returns
// it as an Authorization header value. Callers MUST pass the exact method, path,
// and bytes the server will receive — any difference breaks the token's bindings.
func authHeader(t *testing.T, signer *operatorauth.Signer, method, path string, body []byte) string {
	t.Helper()
	header, err := signer.Authorization(method, path, body)
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

// allowlistTestRouter mounts the allowlist routes on a chi router so the
// workload path parameter resolves the same way the cds router serves it.
func allowlistTestRouter(wh allowlist.Handler, ready attestation.ReadinessFunc) http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/readyz", attestation.HandleReadyz(ready))
	r.Get("/allowlist", wh.HandleList)
	r.Put("/allowlist", wh.HandleReplaceAll)
	r.Post("/allowlist/digests", wh.HandleAddDigest)
	r.Delete("/allowlist/digests", wh.HandleDeleteDigests)
	r.Put("/allowlist/workloads/{name}", wh.HandlePutWorkload)
	r.Delete("/allowlist/workloads/{name}", wh.HandleDeleteWorkload)
	return r
}

// getAllowlist fetches and parses the served document.
func getAllowlist(t *testing.T, srvURL string) *pkgallowlist.Allowlist {
	t.Helper()
	resp, err := http.Get(srvURL + "/allowlist")
	if err != nil {
		t.Fatalf("get allowlist: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get allowlist: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	al, err := pkgallowlist.ParseJSON(body)
	if err != nil {
		t.Fatalf("parse served allowlist: %v; body=%s", err, body)
	}
	return al
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

	al := getAllowlist(t, srv.URL)
	if al.Schema != pkgallowlist.Schema {
		t.Fatalf("schema = %q, want %q", al.Schema, pkgallowlist.Schema)
	}
	if len(al.Digests) != 0 {
		t.Fatalf("expected empty floor, got %d entries", len(al.Digests))
	}
	if len(al.Workloads) != 0 {
		t.Fatalf("expected empty workloads, got %d entries", len(al.Workloads))
	}
}

func TestAllowlistReplaceRequiresAuth(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"schema":%q,"digests":{"%s":"test-image"}}`, pkgallowlist.Schema, digestA)
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
// before the replace and absent from the new document is gone afterward.
func TestAllowlistReplaceSwapsSet(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	addDigest(t, srv.URL, signer, digestA, "old-image")

	putBody := fmt.Sprintf(`{"schema":%q,"digests":{"%s":"new-image"}}`, pkgallowlist.Schema, digestMissing)
	putReq, _ := http.NewRequest(http.MethodPut, srv.URL+"/allowlist", strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, "/allowlist", []byte(putBody)))
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent {
		t.Fatalf("put: got %d, want 204", putResp.StatusCode)
	}

	al := getAllowlist(t, srv.URL)
	if len(al.Digests) != 1 {
		t.Fatalf("expected exactly 1 floor digest after replace, got %d", len(al.Digests))
	}
	if al.Digests[digestMissing] != "new-image" {
		t.Fatalf("replaced set missing new entry: %#v", al.Digests)
	}
	if _, ok := al.Digests[digestA]; ok {
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

// TestAllowlistReplaceRejectsInvalidDoc pins that PUT validates via ParseJSON:
// a body without the schema field (or otherwise malformed) is 422 and does not
// touch the store.
func TestAllowlistReplaceRejectsInvalidDoc(t *testing.T) {
	h, store := guardTestHandler(t)
	d, _ := types.ParseDigest(digestA)
	if err := store.Add(d, "img"); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	versionBefore, _, _ := store.ListAll()

	for _, body := range []string{`{}`, `{"digests":{}}`, `{"schema":"other","digests":{}}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(body))
		h.HandleReplaceAll(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("PUT %s: got status %d, want 422", body, rec.Code)
		}
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(digests) != 1 || version != versionBefore {
		t.Fatalf("invalid PUT must not change the allowlist: %d entries, version %s -> %s",
			len(digests), versionBefore, version)
	}
}

// TestAllowlistReplaceExplicitEmptyClears verifies a valid empty document clears
// the allowlist.
func TestAllowlistReplaceExplicitEmptyClears(t *testing.T) {
	h, store := guardTestHandler(t)
	d, _ := types.ParseDigest(digestA)
	if err := store.Add(d, "img"); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	rec := httptest.NewRecorder()
	body := fmt.Sprintf(`{"schema":%q,"digests":{}}`, pkgallowlist.Schema)
	req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(body))
	h.HandleReplaceAll(rec, req)
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
// insert is invisible to LoadAll and unaddressable by Delete.
func TestAllowlistAddRejectsMissingDigest(t *testing.T) {
	h, store := guardTestHandler(t)
	versionBefore, _, _ := store.ListAll()

	for _, body := range []string{`{}`, `{"image":"ghost"}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/allowlist/digests", strings.NewReader(body))
		h.HandleAddDigest(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("POST %s: got status %d, want 422", body, rec.Code)
		}
	}

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
	resp, err := http.Post(srv.URL+"/allowlist/digests", "application/json", strings.NewReader(body))
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
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist/digests", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, otherSigner, http.MethodPost, "/allowlist/digests", []byte(body)))

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
	req, err := http.NewRequest(http.MethodPost, srvURL+"/allowlist/digests", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPost, "/allowlist/digests", []byte(body)))

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

	al := getAllowlist(t, srv.URL)
	if al.Digests[digestA] != "test-image" {
		t.Fatalf("floor digest = %q, want test-image", al.Digests[digestA])
	}
}

func TestAllowlistDeleteExistingReturnsNoContent(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	addDigest(t, srv.URL, signer, digestA, "test-image")

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestA)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/allowlist/digests", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodDelete, "/allowlist/digests", []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("got status %d, want 204", resp.StatusCode)
	}

	al := getAllowlist(t, srv.URL)
	if len(al.Digests) != 0 {
		t.Fatalf("expected empty floor, got %d", len(al.Digests))
	}
}

func TestAllowlistDeleteNonexistentReturnsNotFound(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestMissing)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/allowlist/digests", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodDelete, "/allowlist/digests", []byte(body)))

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
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/allowlist/digests", strings.NewReader(body))
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

func TestAllowlistAddRejectsInvalidDigest(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := `{"digest":"sha256:abc","image":"test-image"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist/digests", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPost, "/allowlist/digests", []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("got status %d, want 422", resp.StatusCode)
	}
}

// TestAllowlistAddRejectsReplayWithDifferentBody: a captured operator token for
// one body MUST NOT authorize a different body within the token's TTL.
func TestAllowlistAddRejectsReplayWithDifferentBody(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	originalBody := fmt.Sprintf(`{"digest":"%s","image":"trusted-image"}`, digestA)
	header := authHeader(t, signer, http.MethodPost, "/allowlist/digests", []byte(originalBody))

	attackerBody := fmt.Sprintf(`{"digest":"%s","image":"attacker-image"}`, digestMissing)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist/digests", strings.NewReader(attackerBody))
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

// TestAllowlistAddRejectsBodyOverConfiguredCap confirms the per-Handler cap is
// honoured: an over-cap body returns 413 before the auth check runs.
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
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/allowlist/digests", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPost, "/allowlist/digests", []byte(body)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap body got status %d, want 413", resp.StatusCode)
	}
}

// TestWorkloadPutDeleteRoundtrip exercises the workload routes end to end,
// including the {name} path parameter and the 404 on a repeated delete.
func TestWorkloadPutDeleteRoundtrip(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	path := "/allowlist/workloads/web"
	body := fmt.Sprintf(`{"label":"web","containers":[{"digest":"%s"}]}`, digestA)
	putReq, _ := http.NewRequest(http.MethodPut, srv.URL+path, strings.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, path, []byte(body)))
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent {
		t.Fatalf("put: got %d, want 204", putResp.StatusCode)
	}

	al := getAllowlist(t, srv.URL)
	w, ok := al.Workloads["web"]
	if !ok || len(w.Containers) != 1 || w.Containers[0].Digest.String() != digestA {
		t.Fatalf("served workload = %#v", al.Workloads)
	}

	del := func() int {
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+path, nil)
		req.Header.Set("Authorization", authHeader(t, signer, http.MethodDelete, path, nil))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := del(); code != http.StatusNoContent {
		t.Fatalf("first delete: got %d, want 204", code)
	}
	if code := del(); code != http.StatusNotFound {
		t.Fatalf("second delete: got %d, want 404", code)
	}
}

func TestWorkloadPutRejectsInvalidBody(t *testing.T) {
	app, _, signer := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	path := "/allowlist/workloads/web"
	body := `{"containers":[{"digest":"sha256:bad"}]}`
	req, _ := http.NewRequest(http.MethodPut, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(t, signer, http.MethodPut, path, []byte(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid workload body: got %d, want 422", resp.StatusCode)
	}
}

func TestWorkloadPutRequiresAuth(t *testing.T) {
	app, _, _ := testAllowlistApp(t)
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"containers":[{"digest":"%s"}]}`, digestA)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/allowlist/workloads/web", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth workload put: got %d, want 401", resp.StatusCode)
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
