package requesthandoff

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

const (
	maxCABundleBytes = 1 << 20
	// maxErrorBodyBytes caps how much of the peer's non-2xx /ca body lands
	// in the error message.
	maxErrorBodyBytes = 8 << 10
)

type config struct {
	peerURL           string
	attestationApiURL string
	expectedIssuer    string
	logLevel          string
	measurements      []string
	operatorKeys      string
	timeout           time.Duration
}

// report is the operator-facing summary printed on stdout. It deliberately
// has no key-typed fields.
//
// INVARIANT: the handed-off CA private key must never reach an output,
// logging, or marshal path.
type report struct {
	CACertFingerprintSHA256 string `json:"ca_cert_fingerprint_sha256"`
	CACertSubject           string `json:"ca_cert_subject"`
	CACertNotAfter          string `json:"ca_cert_not_after"`
	BundleCertCount         int    `json:"bundle_cert_count"`
	AllowlistVersion        string `json:"allowlist_version"`
	AllowlistDigestCount    int    `json:"allowlist_digest_count"`
	ServedCAMatch           bool   `json:"served_ca_match"`
}

// errorf prints one error line with control characters stripped, so an
// untrusted peer body embedded in err cannot inject terminal escapes.
func errorf(w io.Writer, format string, args ...any) {
	msg := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, fmt.Sprintf(format, args...))
	fmt.Fprintf(w, "error: %s\n", msg)
}

// run pulls the CA over /handoff, verifies it is the live trust root served
// on /ca, and renders the report, returning the process exit code. It is the
// unit-testable core (no os.Exit inside).
func run(ctx context.Context, cfg config, out, errOut io.Writer) int {
	// Diagnostics go to errOut; stdout carries only the JSON report so a
	// caller can parse it directly.
	logger, err := certutil.NewJSONLoggerTo(errOut, cfg.logLevel)
	if err != nil {
		errorf(errOut, "--log-level: %v", err)
		return exitUsage
	}

	if cfg.timeout <= 0 {
		errorf(errOut, "--timeout must be positive; got %s", cfg.timeout)
		return exitUsage
	}

	parsed, err := url.Parse(cfg.peerURL)
	if err != nil {
		errorf(errOut, "--peer-url: %v", err)
		return exitUsage
	}
	// Same guard as get-cert's cdsHTTPClient: a plaintext peer URL would skip
	// RA-TLS attestation of the peer entirely.
	if parsed.Scheme != "https" {
		errorf(errOut, "--peer-url must use https (RA-TLS); got scheme %q", parsed.Scheme)
		return exitUsage
	}

	pinned, err := ratls.ParseHexMeasurementsList(cfg.measurements)
	if err != nil {
		errorf(errOut, "--measurements: %v", err)
		return exitUsage
	}
	if len(pinned) == 0 {
		// Handoff deliberately has no accept-any development mode: both the
		// RA-TLS peer and its issuer EAR must have an explicit identity pin.
		errorf(errOut, "--measurements: no usable measurement")
		return exitUsage
	}
	operatorKeysPEM, err := os.ReadFile(cfg.operatorKeys)
	if err != nil {
		errorf(errOut, "--operator-keys: %v", err)
		return exitUsage
	}
	operatorKeys, err := operatorauth.ParsePublicKeysPEM(operatorKeysPEM)
	if err != nil {
		errorf(errOut, "--operator-keys: %v", err)
		return exitUsage
	}
	operatorKeysHash, err := operatorauth.KeySetHash(operatorKeys)
	if err != nil {
		errorf(errOut, "--operator-keys: %v", err)
		return exitUsage
	}
	// The same digest set pins both channels: the peer's RA-TLS serving cert
	// and its handoff issuer EAR. The EAR-side map is derived from the
	// validated digests (hex.EncodeToString yields the NormalizeMeasurement
	// form) so the two representations stay in sync. For SNP the value is
	// LAUNCH_DIGEST; for TDX it is MRTD (not an RTMR/workload verdict).
	allowed := make(map[string]bool, len(pinned))
	for _, m := range pinned {
		allowed[hex.EncodeToString(m)] = true
	}

	httpClient, err := ratls.NewVerifyingHTTPClient(pinned, cfg.attestationApiURL)
	if err != nil {
		errorf(errOut, "%v", err)
		return exitUsage
	}

	peerURL := strings.TrimRight(cfg.peerURL, "/")
	// The JWKS cache's background refresher lives on the parent ctx, not the
	// pull deadline: a kid-miss refresh must still resolve when EAR
	// validation runs right at the edge of --timeout.
	keyProvider, err := issuer.NewJWKSKeyProvider(ctx, peerURL+"/.well-known/jwks.json", time.Minute, httpClient, logger)
	if err != nil {
		errorf(errOut, "JWKS key provider: %v", err)
		return exitUnavailable
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	material, err := issuer.PullHandoff(ctx, issuer.PullConfig{
		Deps: issuer.HandoffClientDeps{
			KeyProvider:         keyProvider,
			ExpectedIssuer:      cfg.expectedIssuer,
			AllowedMeasurements: allowed,
			OperatorKeysHash:    operatorKeysHash,
		},
		Attest:            attestclient.NewClientWithHTTP(peerURL, httpClient),
		PeerURL:           peerURL,
		AttestationApiURL: cfg.attestationApiURL,
		HTTPClient:        httpClient,
		Logger:            logger,
	})
	if err != nil {
		var handoffErr *issuer.HandoffStatusError
		if errors.As(err, &handoffErr) && handoffErr.Status == http.StatusNotFound {
			errorf(errOut, "%v (if /handoff is not mounted, enable it with cds.handoff.enabled=true and pinned cds.measurements)", err)
		} else {
			errorf(errOut, "%v", err)
		}
		return exitCodeFor(err)
	}
	logger.Info("handoff material received and validated",
		"fingerprint", certutil.CertFingerprint(material.CACert.Raw))

	// Same retry ladder as the pull stages: a 5xx/transport blip on /ca right
	// after a successful handoff is availability, not a verdict.
	served, err := issuer.PullRetry(ctx, logger, issuer.DefaultPullRetryInterval, "served-ca", func() ([]*x509.Certificate, error) {
		return fetchServedCA(ctx, httpClient, peerURL)
	})
	if err != nil {
		errorf(errOut, "fetch served /ca: %v", err)
		return exitCodeFor(err)
	}

	rep, code := reportFor(material, served)
	if !rep.ServedCAMatch {
		logger.Error("handed-off CA cert is not in the served /ca bundle")
	}

	line, err := json.Marshal(rep)
	if err != nil {
		errorf(errOut, "marshal report: %v", err)
		return exitFailed
	}
	fmt.Fprintln(out, string(line))

	return code
}

// reportFor builds the operator-facing report and the exit code it implies:
// exitVerified only when the handed-off CA cert is in the served /ca bundle.
func reportFor(material *issuer.HandoffMaterial, served []*x509.Certificate) (report, int) {
	rep := report{
		CACertFingerprintSHA256: certutil.CertFingerprint(material.CACert.Raw),
		CACertSubject:           material.CACert.Subject.String(),
		CACertNotAfter:          material.CACert.NotAfter.Format(time.RFC3339),
		BundleCertCount:         len(material.Bundle),
		AllowlistVersion:        material.AllowlistVersion,
		AllowlistDigestCount:    len(material.Allowlist),
		ServedCAMatch:           servedCAMatch(served, material.CACert),
	}
	if !rep.ServedCAMatch {
		return rep, exitFailed
	}
	return rep, exitVerified
}

// exitCodeFor maps a final pull error to a process exit code, derived from the
// single issuer.ClassifyPullError verdict: availability problems (transport,
// 5xx, 429, disabled, still bootstrapping) get exitUnavailable; definitive
// verification/protocol failures get exitFailed. A 404 (/handoff disabled) is
// an availability problem, not a verdict.
func exitCodeFor(err error) int {
	switch issuer.ClassifyPullError(err) {
	case issuer.PullTransient, issuer.PullDisabled:
		return exitUnavailable
	case issuer.PullDenied, issuer.PullFatal:
		return exitFailed
	default:
		return exitFailed
	}
}

// fetchServedCA GETs the peer's public /ca bundle over the same RA-TLS client.
// It reads one byte past the cap so an oversized bundle is a clear error, not
// a silent truncation that could drop the handed-off CA and fail the match.
// Non-200s surface as *issuer.HandoffStatusError so ClassifyPullError keeps
// availability (5xx/429) and verdicts apart here too.
func fetchServedCA(ctx context.Context, client *http.Client, peerURL string) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, peerURL+"/ca", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, &issuer.HandoffStatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	pemBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxCABundleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(pemBytes) > maxCABundleBytes {
		return nil, fmt.Errorf("served /ca bundle exceeds %d bytes", maxCABundleBytes)
	}
	certs, err := certutil.ParsePEMCertificates(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse served /ca bundle: %w", err)
	}
	return certs, nil
}

// servedCAMatch reports whether the handed-off CA cert is in the served
// bundle byte for byte. Combined with the key/cert pair validation
// RequestHandoff already performed, a match proves the pulled key is the
// live trust root's signing key; no separate issuance proof is needed.
func servedCAMatch(served []*x509.Certificate, ca *x509.Certificate) bool {
	for _, c := range served {
		if bytes.Equal(c.Raw, ca.Raw) {
			return true
		}
	}
	return false
}
