// Package getkubeconfig implements the operator-side client (B4 client) that
// obtains a kube credential from a measured TDX CVM: it attests the node,
// confirms the node was launched to trust the operator's key (RTMR[3]), then
// exchanges a CSR for a short-lived kube client cert over the cred-release
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
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
)

// verifyEnvelope verifies a self-describing evidence envelope in-process with
// attestation-go, the same engine `c8s verify` uses, so the operator flow
// needs no external verifier binary. A package var so tests can stub the
// verdict.
var verifyEnvelope = teeverify.Verify

// expectedRTMR3 computes RTMR[3] = SHA384(0x00*48 || SHA384(pubkey)) — the
// value the guest reports iff it was launched to trust this exact key. The
// operator computes it offline from their own key, so a match is not TOFU.
func expectedRTMR3(operatorPubPEM []byte) string {
	keyDigest := sha512.Sum384(operatorPubPEM)
	rtmr3 := sha512.Sum384(append(make([]byte, 48), keyDigest[:]...))
	return hex.EncodeToString(rtmr3[:])
}

// verifyEvidence verifies an evidence envelope with attestation-go (HW chain +
// report_data binding) and returns the result. expectedReportData is what the
// quote must be bound to: the caller's nonce on the attest gate, the cert-key
// hash on the RA-TLS dial. Fails closed on any missing piece.
func verifyEvidence(envelopeJSON, expectedReportData []byte) (*teetypes.VerificationResult, error) {
	// The operator-key binding lives in RTMR[3], which only TDX measures, so
	// reject other platforms up front with a clear error instead of a late
	// "quote carries no rtmr_3" (e.g. a SEV-SNP node can never satisfy the
	// binding, however genuine its quote).
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("parse evidence envelope: %w", err)
	}
	if env.Platform != teetypes.PlatformTDX {
		return nil, fmt.Errorf("node platform is %q: the operator-key binding lives in RTMR[3], so credential release requires a TDX guest", env.Platform)
	}

	res, err := verifyEnvelope(envelopeJSON, teetypes.VerifyParams{
		ExpectedReportData: expectedReportData,
	})
	if err != nil {
		return nil, fmt.Errorf("verify evidence: %w", err)
	}
	// Defense in depth: a nil error already implies these, but never report a
	// success the result contradicts.
	if !res.SignatureValid {
		return nil, fmt.Errorf("quote signature invalid")
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		return nil, fmt.Errorf("report_data does not match the expected binding (stale/replayed quote)")
	}
	return res, nil
}

// checkRTMR3 asserts the verified quote's rtmr_3 equals expectedRTMR3(pub),
// i.e. the node was launched to trust the operator's key. The compare is over
// the rtmr_3 claim attestation-go extracted from the signature-verified quote
// body, the same posture as confai verify.
func checkRTMR3(res *teetypes.VerificationResult, operatorPubPEM []byte) error {
	got, _ := res.Claims.PlatformData["rtmr_3"].(string)
	got = strings.ToLower(strings.TrimSpace(got))
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

// attestAndCheckRTMR3 fetches a nonce-bound quote from the guest's
// attestation-api, verifies it in-process (HW chain + report_data freshness),
// and asserts the quote's rtmr_3 equals expectedRTMR3(pub). It proves: genuine
// TDX + the node trusts the operator's key. Returns nil on success.
func attestAndCheckRTMR3(ctx context.Context, attestURL string, operatorPubPEM []byte) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	evidence, err := postAttest(ctx, attestURL, nonce)
	if err != nil {
		return fmt.Errorf("attest: %w", err)
	}

	res, err := verifyEvidence(evidence, nonce)
	if err != nil {
		return err
	}
	return checkRTMR3(res, operatorPubPEM)
}

// postAttest sends the nonce to POST /attest and returns the raw evidence body
// (the self-describing {platform, evidence} envelope attestation-go consumes).
//
// report_data goes to /attest base64-encoded (what the attestation-api
// decodes); attestation-go compares the same raw bytes. Matches confai's
// verify.
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
