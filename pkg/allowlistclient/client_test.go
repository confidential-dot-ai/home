package allowlistclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const testDigest = "sha256:" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

type stubAuth struct{}

func (stubAuth) Authorization(method, path string, body []byte) (string, error) {
	return "Bearer test", nil
}

func TestList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"7"`)
		io.WriteString(w, `{"schema":"c8s.allowlist/v1","digests":{"`+testDigest+`":"cds"}}`)
	}))
	defer srv.Close()

	al, version, err := NewClient(srv.URL).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != "7" {
		t.Fatalf("version = %q, want 7", version)
	}
	if al.Digests[testDigest] != "cds" {
		t.Fatalf("unexpected allowlist: %#v", al)
	}
}

func TestFetchNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `W/"3"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		t.Fatalf("expected If-None-Match header")
	}))
	defer srv.Close()

	_, _, notModified, err := NewClient(srv.URL).Fetch(context.Background(), `W/"3"`)
	if err != nil || !notModified {
		t.Fatalf("expected notModified, got nm=%v err=%v", notModified, err)
	}
}

func TestPutWorkloadBindsBody(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	wl := allowlist.Workload{Containers: []allowlist.Container{{
		Digest:  mustDigest(t, testDigest),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
	}}}
	if err := NewClient(srv.URL).PutWorkload(context.Background(), "my-app", wl, stubAuth{}); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method = %q", gotMethod)
	}
	if gotPath != "/allowlist/workloads/my-app" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.Contains(string(gotBody), testDigest) {
		t.Fatalf("body missing digest: %s", gotBody)
	}
}

func TestMutateRejectsNilAuthorizer(t *testing.T) {
	err := NewClient("http://x").DeleteDigests(context.Background(), []types.Digest{mustDigest(t, testDigest)}, nil)
	if err == nil || !strings.Contains(err.Error(), "nil Authorizer") {
		t.Fatalf("expected nil-authorizer error, got %v", err)
	}
}

func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
