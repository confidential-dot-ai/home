package secretbroker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A cert-auth store client logs in at /v1/auth/cert/login (no bearer credential)
// and uses the minted token for the KV read.
func TestVaultClientCertAuthLogin(t *testing.T) {
	var sawCertLogin bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/cert/login":
			sawCertLogin = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"auth":{"client_token":"minted-by-cert"}}`))
		case "/v1/secret/data/api/db":
			if r.Header.Get("X-Vault-Token") != "minted-by-cert" {
				http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"data":{"password":"s3cr3t"},"metadata":{"version":1}}}`))
		default:
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// certAuth without a token or roleID: the only credential is the (stub)
	// client cert the transport would present.
	c := &vaultClient{addr: srv.URL, httpc: srv.Client(), certAuth: true}

	got, err := c.readKV(context.Background(), "secret", "api/db")
	if err != nil {
		t.Fatalf("readKV under cert auth: %v", err)
	}
	if !sawCertLogin {
		t.Fatal("expected a /v1/auth/cert/login call")
	}
	if got.Data["password"] != "s3cr3t" {
		t.Fatalf("password = %v, want s3cr3t", got.Data["password"])
	}
	if c.currentToken() != "minted-by-cert" {
		t.Fatalf("token = %q, want minted-by-cert", c.currentToken())
	}
}

// canReauth is true for cert auth, so an expired token triggers a re-login.
func TestVaultClientCertAuthReauth(t *testing.T) {
	logins := 0
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/cert/login":
			logins++
			w.Write([]byte(`{"auth":{"client_token":"t"}}`))
		case "/v1/secret/data/api/db":
			if fail {
				fail = false
				http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
				return
			}
			w.Write([]byte(`{"data":{"data":{"password":"ok"},"metadata":{}}}`))
		}
	}))
	defer srv.Close()

	c := &vaultClient{addr: srv.URL, httpc: srv.Client(), certAuth: true}
	if _, err := c.readKV(context.Background(), "secret", "api/db"); err != nil {
		t.Fatalf("readKV: %v", err)
	}
	if logins != 2 {
		t.Fatalf("logins = %d, want 2 (initial + one re-login after 403)", logins)
	}
}
