package secretbroker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// vaultClient is a minimal typed client for the backing OpenBao/Vault store.
// It covers exactly the surface the broker needs — AppRole/token auth and a
// KV v2 read — deliberately avoiding a heavyweight Vault SDK dependency in a
// repo that minimizes its supply-chain surface.
type vaultClient struct {
	addr  string
	httpc *http.Client

	// AppRole credentials; empty when a static token is used.
	roleID   string
	secretID string

	// certAuth authenticates to OpenBao's TLS cert backend with the broker's
	// own mesh cert (presented by httpc), so there is no bearer credential in a
	// k8s Secret. certRole optionally names a specific cert-auth role.
	certAuth bool
	certRole string

	// mu guards token; loginMu serializes logins (no double-login).
	mu      sync.Mutex
	loginMu sync.Mutex
	token   string
}

// kvSecret is the decoded inner payload of a KV v2 read.
type kvSecret struct {
	Data     map[string]any `json:"data"`
	Metadata map[string]any `json:"metadata"`
}

func newVaultClient(cfg config) (*vaultClient, error) {
	// Under cert auth the broker presents its own mesh cert to OpenBao; that key
	// lives in the c8s-certs tmpfs, never in etcd, so there is no bearer
	// credential for the control plane to read.
	var clientCert *tls.Certificate
	if cfg.openbaoCertAuth {
		crt, err := tls.LoadX509KeyPair(cfg.tlsCert, cfg.tlsKey)
		if err != nil {
			return nil, fmt.Errorf("load mesh cert for openbao cert auth: %w", err)
		}
		clientCert = &crt
	}

	httpc, err := storeHTTPClient(cfg, clientCert)
	if err != nil {
		return nil, err
	}
	return &vaultClient{
		addr:     strings.TrimRight(cfg.openbaoAddr, "/"),
		httpc:    httpc,
		roleID:   cfg.openbaoRoleID,
		secretID: cfg.openbaoSecretID,
		certAuth: cfg.openbaoCertAuth,
		certRole: cfg.openbaoCertRole,
		token:    cfg.openbaoToken,
	}, nil
}

// storeHTTPClient builds the HTTP client used to reach OpenBao. When the store
// is attested, the transport verifies OpenBao's RA-TLS attestation (hardware
// chain + measurement) rather than trusting PKI alone. clientCert, when set, is
// presented as the TLS client certificate (OpenBao cert auth).
func storeHTTPClient(cfg config, clientCert *tls.Certificate) (*http.Client, error) {
	if cfg.openbaoAttested {
		ms, err := parseMeasurementsBytes(cfg.openbaoMeasurements)
		if err != nil {
			return nil, fmt.Errorf("--openbao-measurements: %w", err)
		}
		// Reuse the RA-TLS verifying config and attach the client cert, so the
		// broker both verifies the store's attestation and authenticates to it
		// with its mesh identity.
		tlsCfg, _, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
			Policy: &ratls.VerifyPolicy{Measurements: ms, AttestationApiURL: cfg.attestationApiURL},
		})
		if err != nil {
			return nil, fmt.Errorf("openbao attested client: %w", err)
		}
		if clientCert != nil {
			tlsCfg.Certificates = []tls.Certificate{*clientCert}
		}
		return &http.Client{Timeout: 15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if cfg.openbaoCA != "" {
		pem, err := os.ReadFile(cfg.openbaoCA)
		if err != nil {
			return nil, fmt.Errorf("read --openbao-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--openbao-ca: no certificates parsed")
		}
		tlsCfg.RootCAs = pool
	}
	if clientCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// login obtains a store token via AppRole when no token is held yet. A static
// token (set at construction) needs no login. loginMu serializes concurrent
// callers so at most one AppRole login is in flight and the token is set once.
func (c *vaultClient) login(ctx context.Context) error {
	c.mu.Lock()
	have, role, secret, certAuth := c.token, c.roleID, c.secretID, c.certAuth
	c.mu.Unlock()
	if have != "" && role == "" && !certAuth {
		return nil // static token
	}

	var (
		path string
		body []byte
		kind string
	)
	switch {
	case certAuth:
		// The client cert (presented by c.httpc) is the credential; cert auth
		// takes only an optional role name.
		path, kind = "/v1/auth/cert/login", "cert login"
		if c.certRole != "" {
			body, _ = json.Marshal(map[string]string{"name": c.certRole})
		}
	case role != "":
		path, kind = "/v1/auth/approle/login", "approle login"
		body, _ = json.Marshal(map[string]string{"role_id": role, "secret_id": secret})
	default:
		return fmt.Errorf("no OpenBao auth configured (set --openbao-token, --openbao-approle-*, or --openbao-cert-auth)")
	}

	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	if c.currentToken() != "" {
		return nil // another goroutine logged in while we waited
	}

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := c.do(ctx, http.MethodPost, path, "", reqBody, &out); err != nil {
		return fmt.Errorf("%s: %w", kind, err)
	}
	if out.Auth.ClientToken == "" {
		return fmt.Errorf("%s: empty client_token", kind)
	}
	c.mu.Lock()
	c.token = out.Auth.ClientToken
	c.mu.Unlock()
	return nil
}

// canReauth reports whether the client can obtain a fresh token on expiry
// (i.e. it is not using a static token).
func (c *vaultClient) canReauth() bool {
	return c.roleID != "" || c.certAuth
}

// readKV reads a KV v2 secret at <mount>/data/<path>. It authenticates lazily
// and, for AppRole, re-logs in once on an auth failure (token expiry).
func (c *vaultClient) readKV(ctx context.Context, mount, path string) (*kvSecret, error) {
	if err := c.login(ctx); err != nil {
		return nil, err
	}
	url := fmt.Sprintf("/v1/%s/data/%s", mount, path)

	var out struct {
		Data kvSecret `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, url, c.currentToken(), nil, &out)
	if isAuthErr(err) && c.canReauth() {
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		if lerr := c.login(ctx); lerr != nil {
			return nil, lerr
		}
		err = c.do(ctx, http.MethodGet, url, c.currentToken(), nil, &out)
	}
	if err != nil {
		return nil, err
	}
	return &out.Data, nil
}

func (c *vaultClient) currentToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// statusError carries the HTTP status of a non-2xx store response so callers
// can distinguish auth failures from other errors.
type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("openbao: status %d: %s", e.code, e.body)
}

func isAuthErr(err error) bool {
	var se *statusError
	if !errors.As(err, &se) {
		return false
	}
	return se.code == http.StatusForbidden || se.code == http.StatusUnauthorized
}

func (c *vaultClient) do(ctx context.Context, method, path, token string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, body)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &statusError{code: resp.StatusCode, body: strings.TrimSpace(string(data))}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func parseMeasurementsBytes(hexes []string) ([][]byte, error) {
	var out [][]byte
	for _, h := range hexes {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("invalid measurement %q: %w", h, err)
		}
		out = append(out, b)
	}
	return out, nil
}
