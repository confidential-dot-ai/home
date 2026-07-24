package luks

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// bao is the minimal openbao/Vault KV v2 client the luks CLI needs (read,
// write, delete, list). The broker's client has a disjoint surface (AppRole,
// RA-TLS), so they deliberately don't share one.
type bao struct {
	addr  string
	token string
	http  *http.Client
}

func newBao(addr, token string, pool *x509.CertPool, timeout time.Duration) *bao {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if pool != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &bao{
		addr:  strings.TrimRight(addr, "/"),
		token: token,
		http: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// KV v2 never needs redirects; following one would replay
			// X-Vault-Token to whatever host the response names.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("openbao returned a redirect; refusing to follow it with the token")
			},
		},
	}
}

// maxRespBytes caps decoded response bodies (KV JSON is small);
// maxErrBodyBytes caps error bodies embedded in messages.
const (
	maxRespBytes    = 1 << 20
	maxErrBodyBytes = 8 << 10
)

// kvMount is the KV v2 mount the CLI targets (openbao's default, same as
// Vault's).
const kvMount = "secret"

// kvPath maps a (workload, name) tuple to the openbao path our schema uses:
// KV v2 data endpoint is /v1/<mount>/data/<workload>/luks-<name>.
func kvPath(workload, name string) string {
	return path.Join("v1", kvMount, "data", workload, "luks-"+name)
}

func kvListPath(workload string) string {
	return path.Join("v1", kvMount, "metadata", workload)
}

func kvMetaPath(workload, name string) string {
	return path.Join("v1", kvMount, "metadata", workload, "luks-"+name)
}

// putPassphrase writes a KV v2 entry {passphrase: <pass>} at the CLI's
// per-volume schema path. The KV v2 write API is
// POST /v1/<mount>/data/<path> {"data": {...}}; see
// https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2.
func (b *bao) putPassphrase(ctx context.Context, workload, name string, passphrase []byte) error {
	// Hand-built JSON so the secret never becomes an immutable Go string; the
	// body is zeroized after the request. Requires JSON-safe passphrase bytes
	// (the hex from generatePassphrase always is).
	for _, c := range passphrase {
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return fmt.Errorf("passphrase contains a JSON-unsafe byte (0x%02x)", c)
		}
	}
	// cas=0: create-only — KV v2 rejects the write if any version exists.
	body := make([]byte, 0, len(passphrase)+64)
	body = append(body, `{"data":{"passphrase":"`...)
	body = append(body, passphrase...)
	body = append(body, `"},"options":{"cas":0}}`...)
	defer zero(body)
	var written struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	if err := b.do(ctx, http.MethodPost, kvPath(workload, name), body, &written); err != nil {
		if isCASConflict(err) {
			return errVolumeExists
		}
		return err
	}
	// A KV v1 mount accepts the same POST at the literal data/... path with a
	// bodiless 204 — and ignores cas, making create-only an overwrite and
	// destroy's metadata delete a no-op. Fail loudly instead.
	if written.Data.Version < 1 {
		return fmt.Errorf("openbao answered the write without data.version — %q does not look like a KV v2 mount (the cas=0 create-only and crypto-shred semantics require v2)", kvMount)
	}
	return nil
}

// errVolumeExists reports that a KV entry already exists at the volume's path,
// so the create-only putPassphrase was rejected.
var errVolumeExists = errors.New("passphrase already exists at this OpenBao path")

// isCASConflict reports whether err is a KV v2 check-and-set rejection — the
// cas=0 create-only write hitting an existing key, which openbao returns as
// HTTP 400 with a "check-and-set" message.
func isCASConflict(err error) bool {
	var he *httpError
	return errors.As(err, &he) && he.status == http.StatusBadRequest &&
		strings.Contains(he.body, "check-and-set")
}

// readMetadata returns the KV v2 metadata for a volume. Used by `show` to
// avoid disclosing the passphrase while confirming the entry exists.
func (b *bao) readMetadata(ctx context.Context, workload, name string) (map[string]any, error) {
	var raw struct {
		Data map[string]any `json:"data"`
	}
	if err := b.do(ctx, http.MethodGet, kvMetaPath(workload, name), nil, &raw); err != nil {
		return nil, err
	}
	return raw.Data, nil
}

// listVolumes returns the LUKS entries under the workload's KV path. The
// KV v2 list endpoint is LIST /v1/<mount>/metadata/<path> — which openbao
// serves as GET with ?list=true.
func (b *bao) listVolumes(ctx context.Context, workload string) ([]string, error) {
	var raw struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := b.do(ctx, "LIST", kvListPath(workload), nil, &raw); err != nil {
		// LIST returns 404 when the parent path has no entries; treat as empty.
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(raw.Data.Keys))
	for _, k := range raw.Data.Keys {
		if strings.HasPrefix(k, "luks-") {
			out = append(out, strings.TrimPrefix(k, "luks-"))
		}
	}
	return out, nil
}

// deleteVolume removes both current data and metadata for the volume, so
// a subsequent create is not shadowed by prior-version history.
func (b *bao) deleteVolume(ctx context.Context, workload, name string) error {
	// DELETE on /metadata destroys all versions and the entry itself.
	return b.do(ctx, http.MethodDelete, kvMetaPath(workload, name), nil, nil)
}

// do runs an HTTP request against the openbao instance with the client's
// token. For LIST, it uses the "?list=true" trick (openbao accepts either
// the LIST verb or the ?list=true query on GET); we send LIST verbatim since
// net/http passes arbitrary methods through and openbao understands both.
func (b *bao) do(ctx context.Context, method, urlPath string, body []byte, out any) error {
	if b.addr == "" {
		return errors.New("openbao address is empty")
	}
	url := b.addr + "/" + strings.TrimPrefix(urlPath, "/")
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	if b.token != "" {
		req.Header.Set("X-Vault-Token", b.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBodyBytes))
		return &httpError{status: resp.StatusCode, body: string(msg)}
	}
	if resp.StatusCode == http.StatusNoContent || out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxRespBytes)).Decode(out)
}

type httpError struct {
	status int
	body   string
}

// Error embeds the untrusted body sanitized so a hostile response cannot
// forge log lines or terminal escapes.
func (e *httpError) Error() string {
	return fmt.Sprintf("openbao HTTP %d: %s", e.status, sanitize(e.body))
}

func isNotFound(err error) bool {
	var he *httpError
	return errors.As(err, &he) && he.status == http.StatusNotFound
}

// generatePassphrase returns bytes*2 hex chars from crypto/rand. `bytes` is
// the raw byte count before hex encoding (32 bytes → 64 hex chars, the
// default), and must be at least 16.
func generatePassphrase(bytesN int) ([]byte, error) {
	if bytesN < 16 || bytesN > 128 {
		return nil, fmt.Errorf("passphrase entropy must be between 16 and 128 bytes, got %d", bytesN)
	}
	raw := make([]byte, bytesN)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("read random passphrase bytes: %w", err)
	}
	out := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(out, raw)
	zero(raw)
	return out, nil
}

// readTokenFile reads the openbao token from a file, trimming whitespace.
// Empty path returns an empty token (caller decides whether that's an error).
func readTokenFile(pathToFile string) (string, error) {
	if pathToFile == "" {
		return "", nil
	}
	fi, err := os.Stat(pathToFile)
	if err != nil {
		return "", fmt.Errorf("stat openbao token file %q: %w", pathToFile, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: openbao token file %s is group/world-readable (mode %04o); chmod 0600 it\n", pathToFile, fi.Mode().Perm())
	}
	b, err := os.ReadFile(pathToFile)
	if err != nil {
		return "", fmt.Errorf("read openbao token file %q: %w", pathToFile, err)
	}
	return strings.TrimSpace(string(b)), nil
}
