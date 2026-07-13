package verify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// attestationPath is the LB's well-known endpoint for nonce-bound attestation
// evidence (GET ?nonce=<b64url>), per c8s-verify-js PROTOCOL.md.
const attestationPath = "/.well-known/c8s/attestation"

// nonceSize is the verifier challenge length (bytes) for the endpoint flow.
const nonceSize = 32

// Canonical session-key lengths from c8s-verify-js PROTOCOL.md (X25519 public
// key = 32 bytes, ML-KEM-768 encapsulation key = 1184 bytes). Documentary — the
// verifier does not enforce them; see evidenceFromEndpointJSON for why.
const (
	x25519PubLen     = 32
	mlkem768EncapLen = 1184
)

// evidence is normalized attestation evidence ready for verification, plus the
// metadata needed to explain the result to a human. platform + rawEvidence are
// the self-describing evidence envelope ({platform, evidence}) forwarded
// verbatim to the verifier, so SEV-SNP, TDX, and az-snp all pass through in
// their own shape.
type evidence struct {
	// platform is the evidence-envelope platform discriminator (snp, tdx, az-snp…).
	platform string
	// rawEvidence is the platform-specific evidence object, forwarded verbatim.
	rawEvidence json.RawMessage
	// erd is the expected freshness anchor — the exact bytes the producer bound,
	// unpadded (48-byte SHA-384 for c8s bindings). Hardware-report verifiers
	// zero-pad it to the 64-byte REPORTDATA field; the Azure vTPM verifiers
	// compare it raw against the quote's extraData, so a pre-padded value fails
	// there (PROTOCOL.md "az-snp").
	erd []byte
	// fresh is true when erd binds a caller-supplied nonce, so a passing
	// verification proves the evidence was produced for THIS check (not replayed).
	fresh bool
	// source describes where the evidence came from (for output).
	source string
	// certSHA256 is the hex SHA-256 of the serving certificate (cert modes only).
	certSHA256 string
	// bindingNote explains what the REPORTDATA is bound to.
	bindingNote string
}

// platformOrDefault returns p, or "snp" when p is empty (the historical default
// for evidence carriers that predate the platform field). The verifier rejects a
// genuinely unknown platform, so a wrong guess fails closed.
func platformOrDefault(p string) string {
	if p == "" {
		return string(types.PlatformSnp)
	}
	return p
}

// attestationResponse is the JSON the attestation endpoint returns. The evidence
// object is kept raw and forwarded verbatim (platform-specific); only the nonce
// and session keys (used to derive the REPORTDATA binding) are parsed here.
type attestationResponse struct {
	Platform      string          `json:"platform"`
	Nonce         string          `json:"nonce"`
	Evidence      json.RawMessage `json:"evidence"`
	SessionPubkey struct {
		X25519   string `json:"x25519"`
		Mlkem768 string `json:"mlkem768"`
	} `json:"session_pubkey"`
}

// gatherFromRATLSCert dials an RA-TLS TLS endpoint, captures the serving
// certificate without trusting PKI (trust comes from the embedded hardware
// attestation), and binds REPORTDATA to the certificate key.
func gatherFromRATLSCert(ctx context.Context, addr, serverName string, timeout time.Duration) (*evidence, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		// INVARIANT: PKI verification is intentionally skipped — the RA-TLS
		// attestation in the cert extension is the trust anchor, verified below.
		Config: &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, //nolint:gosec
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, &connectError{err: fmt.Errorf("dial %s: %w", addr, err)}
	}
	defer conn.Close()

	// tls.Dialer.DialContext always returns a *tls.Conn, so this assertion is safe.
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, &connectError{err: fmt.Errorf("%s presented no certificate", addr)}
	}
	return evidenceFromCert(certs[0], fmt.Sprintf("RA-TLS serving certificate at %s", addr))
}

// evidenceFromCert extracts the attestation extension from a certificate and
// binds REPORTDATA to the certificate's public key. The serving cert carries no
// per-request nonce, so the binding proves "this key was born in a TEE" but not
// freshness (fresh=false).
func evidenceFromCert(cert *x509.Certificate, source string) (*evidence, error) {
	att, err := ratls.ExtractAttestation(cert)
	if err != nil {
		return nil, err
	}
	platform, raw, err := evidenceFromAttestation(att)
	if err != nil {
		return nil, err
	}
	rd, err := ratls.ReportDataForKey(cert.PublicKey, nil)
	if err != nil {
		return nil, fmt.Errorf("compute expected REPORTDATA: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return &evidence{
		platform:    platform,
		rawEvidence: raw,
		erd:         keyAnchor(rd),
		fresh:       false,
		source:      source,
		certSHA256:  hex.EncodeToString(sum[:]),
		bindingNote: "REPORTDATA binds the certificate public key (no per-request nonce — not a freshness proof)",
	}, nil
}

// evidenceFromAttestation turns an RA-TLS cert's embedded attestation into the
// platform + evidence object the verifier expects. An embedded {platform,
// evidence} envelope (e.g. az-snp) is forwarded verbatim; a raw SEV-SNP report
// is wrapped as {attestation_report, cert_chain.vcek?}. A raw TDX report has no
// evidence shape wired here yet — use the discovery / attestation endpoint,
// which carries the attester's evidence object directly.
func evidenceFromAttestation(att *ratls.Attestation) (string, json.RawMessage, error) {
	if env, ok := att.EmbeddedEvidence(); ok {
		return env.Platform, env.Evidence, nil
	}
	switch att.TEEType {
	case ratls.TEETypeSEVSNP:
		inner := map[string]any{"attestation_report": base64.StdEncoding.EncodeToString(att.Report)}
		if len(att.CertChain) > 0 {
			inner["cert_chain"] = map[string]any{"vcek": base64.StdEncoding.EncodeToString(att.CertChain)}
		}
		raw, err := json.Marshal(inner)
		if err != nil {
			return "", nil, fmt.Errorf("marshal snp evidence: %w", err)
		}
		return string(types.PlatformSnp), raw, nil
	case ratls.TEETypeTDX:
		return "", nil, fmt.Errorf("verifying a raw TDX report from an RA-TLS serving cert is not yet supported; use the discovery or attestation endpoint")
	default:
		return "", nil, fmt.Errorf("unsupported TEE type %d", att.TEEType)
	}
}

// gatherFromEndpoint fetches nonce-bound evidence from the attestation endpoint.
// It generates a fresh challenge, requires the response to echo it, and binds
// REPORTDATA to the attested session keys + nonce (a freshness proof).
func gatherFromEndpoint(ctx context.Context, base, serverName string, timeout time.Duration) (*evidence, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	endpoint, err := joinAttestationURL(base, nonce)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: timeout, Transport: &http.Transport{
		// Trust is the hardware attestation in the body, not PKI on the hop.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, //nolint:gosec
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &connectError{err: fmt.Errorf("GET %s: %w", endpoint, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, &connectError{err: fmt.Errorf("GET %s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &connectError{err: fmt.Errorf("read response: %w", err)}
	}
	return evidenceFromEndpointJSON(data, nonce, fmt.Sprintf("attestation endpoint %s", endpoint))
}

// evidenceFromEndpointJSON parses an attestation response. When expectNonce is
// non-nil (live fetch) the response must echo it; when nil (from-file) the
// response's own nonce is used and the result is not a freshness proof.
func evidenceFromEndpointJSON(data, expectNonce []byte, source string) (*evidence, error) {
	var r attestationResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse attestation response: %w", err)
	}
	if len(r.Evidence) == 0 {
		return nil, fmt.Errorf("attestation response carries no evidence")
	}

	nonce, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.Nonce, "="))
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	fresh := false
	if expectNonce != nil {
		if !bytes.Equal(nonce, expectNonce) {
			return nil, &securityError{err: fmt.Errorf("response nonce does not echo the challenge (possible replay or MITM)")}
		}
		fresh = true
	}

	x25519, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.SessionPubkey.X25519, "="))
	if err != nil {
		return nil, fmt.Errorf("decode session x25519 key: %w", err)
	}
	mlkem, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.SessionPubkey.Mlkem768, "="))
	if err != nil {
		return nil, fmt.Errorf("decode session mlkem768 key: %w", err)
	}
	if len(x25519) == 0 && len(mlkem) == 0 {
		return nil, fmt.Errorf("attestation response has no session_pubkey; pass --expected-report-data to verify bare evidence")
	}
	// Session-key lengths are NOT enforced. The freshness proof's security rests
	// on REPORTDATA == SHA-384(x25519‖mlkem768‖nonce) matching the
	// hardware-signed report (checked downstream): preimage resistance means a
	// response can't present session keys the TEE didn't bind, whatever their
	// length, and a re-split of the same bytes hashes the same (this verifier
	// never uses the keys beyond the binding, so the split is moot). The exact
	// lengths are a per-platform PROTOCOL.md detail (x25519PubLen /
	// mlkem768EncapLen document the current c8s scheme), not a property to police
	// here — enforcing them would wrongly reject other platforms' bindings.
	erd := endpointReportData(x25519, mlkem, nonce)
	return &evidence{
		platform:    platformOrDefault(r.Platform),
		rawEvidence: r.Evidence,
		erd:         erd,
		fresh:       fresh,
		source:      source,
		bindingNote: "REPORTDATA binds the attested session keys + nonce",
	}, nil
}

// endpointReportData computes the freshness anchor SHA-384(x25519 ‖ mlkem768 ‖
// nonce) per c8s-verify-js PROTOCOL.md — unpadded (see evidence.erd).
func endpointReportData(x25519, mlkem, nonce []byte) []byte {
	h := sha512.New384()
	h.Write(x25519)
	h.Write(mlkem)
	h.Write(nonce)
	return h.Sum(nil)
}

// keyAnchor extracts the unpadded SHA-384 anchor from ReportDataForKey's
// zero-padded 64-byte REPORTDATA — the form producers bind (see
// attestclient.MakeSNPRATLSAttestFunc) and Azure vTPM quotes carry raw.
func keyAnchor(rd [64]byte) []byte { return rd[:sha512.Size384] }

// gatherFromFile loads evidence from a saved PEM certificate or attestation
// response JSON. overrideERD, when non-nil, replaces the computed REPORTDATA —
// used to inspect bare evidence that carries no key/session binding.
func gatherFromFile(data []byte, overrideERD []byte, source string) (*evidence, error) {
	if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
		if overrideERD != nil {
			// A certificate's REPORTDATA binding is the certificate key; an
			// override would silently replace a real binding with an arbitrary
			// value while still reporting "binds the certificate public key".
			return nil, fmt.Errorf("--expected-report-data does not apply to a certificate (its binding is the certificate key)")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return evidenceFromCert(cert, source)
	}
	if overrideERD != nil {
		ev, err := evidenceFromBareJSON(data, overrideERD, source)
		if err == nil {
			return ev, nil
		}
		// fall through to full-response parsing if it wasn't bare evidence
	}
	return evidenceFromEndpointJSON(data, nil, source)
}

// evidenceFromBareJSON parses a bare {platform, evidence:{attestation_report,
// cert_chain:{vcek}}} object (no session keys) and binds the caller-supplied
// REPORTDATA.
func evidenceFromBareJSON(data []byte, erd []byte, source string) (*evidence, error) {
	var r attestationResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if len(r.Evidence) == 0 {
		return nil, fmt.Errorf("bare evidence has no evidence object")
	}
	return &evidence{
		platform:    platformOrDefault(r.Platform),
		rawEvidence: r.Evidence,
		erd:         erd,
		fresh:       false,
		source:      source,
		bindingNote: "REPORTDATA supplied via --expected-report-data (not independently bound)",
	}, nil
}

// joinAttestationURL appends the well-known attestation path and nonce query to
// a base URL (scheme + host[:port]).
func joinAttestationURL(base string, nonce []byte) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse url %q: %w", base, err)
	}
	u.Path = attestationPath
	u.RawQuery = "nonce=" + base64.RawURLEncoding.EncodeToString(nonce)
	return u.String(), nil
}

// parseExpectedReportData decodes the hex REPORTDATA / TPM-nonce anchor
// override, keeping the caller's exact bytes (verifiers pad per platform —
// see evidence.erd).
func parseExpectedReportData(s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("--expected-report-data is not hex: %w", err)
	}
	// The binding digest length isn't fixed across platforms/schemes (SHA-384 =
	// 48, a raw nonce, etc.). The only hard constraint is 1–64 bytes.
	if len(raw) == 0 || len(raw) > 64 {
		return nil, fmt.Errorf("--expected-report-data is %d bytes, want 1–64", len(raw))
	}
	return raw, nil
}
