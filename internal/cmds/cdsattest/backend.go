package cdsattest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// hopByHopHeaders are not forwarded between the over-encrypted hop and the
// backend (RFC 7230 §6.1 plus the session header).
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"content-length":      true,
	"x-c8s-session":       true,
}

const maxUpstreamResponseBytes = 32 << 20

// EchoBackend reflects the request — used for the demo and tests.
type EchoBackend struct{}

// Forward implements Backend.
func (EchoBackend) Forward(_ context.Context, req types.TunnelRequest) (types.TunnelResponse, error) {
	msg := fmt.Sprintf("LB enclave received %d bytes over the over-encrypted channel for %s %s: %q",
		len(req.Body), req.Method, req.Path, string(req.Body))
	return types.TunnelResponse{
		Status:  http.StatusOK,
		Headers: map[string]string{"Content-Type": "text/plain; charset=utf-8"},
		Body:    []byte(msg),
	}, nil
}

// HTTPBackend forwards the decrypted request to a real upstream. The connection
// is plaintext HTTP by default — the cluster's transparent raTLS mesh wraps the
// sidecar→backend hop, exactly like every other c8s workload. When the upstream
// is https it does mTLS with the LB's CDS-issued client cert and verifies the
// peer against the mesh CA (mirroring the tls-lb nginx proxy_ssl_* config).
type HTTPBackend struct {
	base   string // upstream base URL, e.g. http://c8s-tee-proxy:80
	client *http.Client
}

// defaultUpstreamTimeout bounds a single forwarded request to the upstream
// backend (connect + headers + body) when HTTPBackendOptions.Timeout is unset.
// It guards the sidecar against slow or hung upstreams holding decrypted-traffic
// connections open indefinitely.
const defaultUpstreamTimeout = 30 * time.Second

// HTTPBackendOptions configures the raTLS/mTLS material for an https upstream.
type HTTPBackendOptions struct {
	// ClientCertFile/ClientKeyFile present the CDS-issued cert to the backend.
	ClientCertFile string
	ClientKeyFile  string
	// TrustedCAFile verifies the backend (the mesh CA bundle).
	TrustedCAFile string
	// ServerName overrides SNI / verification name.
	ServerName string
	// Timeout bounds a single forwarded upstream request. Values <= 0 fall back
	// to defaultUpstreamTimeout.
	Timeout time.Duration
}

// NewHTTPBackend builds an HTTP(S) forwarding backend for base (a full URL).
func NewHTTPBackend(base string, opts HTTPBackendOptions) (*HTTPBackend, error) {
	base = strings.TrimRight(base, "/")
	transport := &http.Transport{
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}
	if strings.HasPrefix(base, "https://") {
		tlsCfg := &tls.Config{ServerName: opts.ServerName, MinVersion: tls.VersionTLS12}
		if opts.TrustedCAFile != "" {
			caPEM, err := os.ReadFile(opts.TrustedCAFile)
			if err != nil {
				return nil, fmt.Errorf("read upstream CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("upstream CA file %q has no certificates", opts.TrustedCAFile)
			}
			tlsCfg.RootCAs = pool
		}
		if opts.ClientCertFile != "" && opts.ClientKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(opts.ClientCertFile, opts.ClientKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load upstream client cert: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		transport.TLSClientConfig = tlsCfg
	} else if !strings.HasPrefix(base, "http://") {
		return nil, fmt.Errorf("upstream must be an http:// or https:// URL, got %q", base)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultUpstreamTimeout
	}
	return &HTTPBackend{base: base, client: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

// Forward implements Backend by proxying the reconstructed request upstream.
func (b *HTTPBackend) Forward(ctx context.Context, env types.TunnelRequest) (types.TunnelResponse, error) {
	body := env.Body
	method := env.Method
	if method == "" {
		method = http.MethodGet
	}
	path := env.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	req, err := http.NewRequestWithContext(ctx, method, b.base+path, bytes.NewReader(body))
	if err != nil {
		return types.TunnelResponse{}, fmt.Errorf("build upstream request: %w", err)
	}
	for k, v := range env.Headers {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return types.TunnelResponse{}, fmt.Errorf("forward to upstream: %w", err)
	}
	defer resp.Body.Close()
	limitedBody := &io.LimitedReader{R: resp.Body, N: maxUpstreamResponseBytes + 1}
	respBody, err := io.ReadAll(limitedBody)
	if err != nil {
		return types.TunnelResponse{}, fmt.Errorf("read upstream response: %w", err)
	}
	if len(respBody) > maxUpstreamResponseBytes {
		return types.TunnelResponse{}, fmt.Errorf("upstream response exceeds %d byte limit", maxUpstreamResponseBytes)
	}

	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		headers[k] = resp.Header.Get(k)
	}
	return types.TunnelResponse{
		Status:  resp.StatusCode,
		Headers: headers,
		Body:    respBody,
	}, nil
}
