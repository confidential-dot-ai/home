// Package getkubeconfig implements the operator-side client (B4 client) that
// obtains a kube credential from a measured TDX CVM: it attests the node,
// confirms the node was launched to trust the operator's key (RTMR[3]), then
// exchanges a CSR for a short-lived RKE2 client cert over the cred-release
// endpoint and assembles a kubeconfig.
package getkubeconfig

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// attestationCLIBinary is the external verifier we shell out to — the same
// tool confai's `verify` requires, so the operator flow uses one verifier.
// Override with ATTESTATION_CLI.
const attestationCLIBinary = "attestation-cli"

// expectedRTMR3 computes RTMR[3] = SHA384(0x00*48 || SHA384(pubkey)) — the
// value the guest reports iff it was launched to trust this exact key. The
// operator computes it offline from their own key, so a match is not TOFU.
func expectedRTMR3(operatorPubPEM []byte) string {
	keyDigest := sha512.Sum384(operatorPubPEM)
	rtmr3 := sha512.Sum384(append(make([]byte, 48), keyDigest[:]...))
	return hex.EncodeToString(rtmr3[:])
}

// attestAndCheckRTMR3 fetches a nonce-bound quote from the guest's
// attestation-api, verifies it with attestation-cli (HW chain + report_data
// freshness), and asserts the quote's rtmr_3 equals expectedRTMR3(pub). It
// proves: genuine TDX + the node trusts the operator's key. Returns nil on
// success. The RTMR[3] equality is a plain compare of the (CLI-authenticated)
// rtmr_3 claim — same posture as confai verify.
func attestAndCheckRTMR3(ctx context.Context, attestURL string, operatorPubPEM []byte) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)

	evidence, err := postAttest(ctx, attestURL, nonce)
	if err != nil {
		return fmt.Errorf("attest: %w", err)
	}

	claims, err := runAttestationCLIVerify(ctx, evidence, nonceHex)
	if err != nil {
		return fmt.Errorf("attestation-cli verify: %w", err)
	}

	sigValid, _ := claims["signature_valid"].(bool)
	rdMatch, _ := claims["report_data_match"].(bool)
	if !sigValid {
		return fmt.Errorf("quote signature invalid")
	}
	if !rdMatch {
		return fmt.Errorf("report_data does not match nonce (stale/replayed quote)")
	}

	got := platformDataString(claims, "rtmr_3")
	want := expectedRTMR3(operatorPubPEM)
	if got == "" {
		return fmt.Errorf("quote carries no rtmr_3")
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("RTMR[3] mismatch: node reports %s, operator key implies %s "+
			"(the node was NOT launched to trust this key)", got, want)
	}
	return nil
}

// postAttest sends the nonce to POST /attest and returns the raw evidence body
// (the same shape attestation-cli verify consumes on stdin).
//
// report_data goes to /attest base64-encoded (what the attestation-api decodes)
// but to attestation-cli --expected-report-data as hex; the two encodings must
// agree on the same bytes or verify reports "report_data mismatch". Matches
// confai's verify.
func postAttest(ctx context.Context, attestURL string, nonce []byte) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{
		"platform":    "auto",
		"report_data": base64.StdEncoding.EncodeToString(nonce),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, attestURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attest HTTP %d: %s", resp.StatusCode, respBody)
	}
	return respBody, nil
}

// runAttestationCLIVerify pipes evidence to `attestation-cli verify` and
// returns the parsed claims map. Mirrors confai's invocation.
func runAttestationCLIVerify(ctx context.Context, evidence []byte, nonceHex string) (map[string]any, error) {
	bin := attestationCLIBinary
	if env := os.Getenv("ATTESTATION_CLI"); env != "" {
		bin = env
	}
	cmd := exec.CommandContext(ctx, bin, "verify", "--expected-report-data", nonceHex)
	cmd.Stdin = bytes.NewReader(evidence)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()

	// attestation-cli exits non-zero on both hard failure (no JSON) and policy
	// mismatch (full JSON on stdout). Try to parse stdout first.
	var claims map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &claims); err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%w: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("parse verify output: %w", err)
	}
	return claims, nil
}

// platformDataString pulls claims.platform_data.<key> (where the TDX RTMRs
// live), lowercased/trimmed, or "".
func platformDataString(claims map[string]any, key string) string {
	c, ok := claims["claims"].(map[string]any)
	if !ok {
		return ""
	}
	pd, ok := c["platform_data"].(map[string]any)
	if !ok {
		return ""
	}
	v, _ := pd[key].(string)
	return strings.ToLower(strings.TrimSpace(v))
}
