package attestationclient

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// verifyResult builds a /verify response body; measurement nil leaves the
// launch digest empty.
func verifyResult(platform string, sigValid bool, reportDataMatch *bool, measurement []byte) types.VerifyResponse {
	resp := types.VerifyResponse{}
	resp.Result.Platform = platform
	resp.Result.SignatureValid = sigValid
	resp.Result.ReportDataMatch = reportDataMatch
	if measurement != nil {
		resp.Result.Claims.LaunchDigest = hex.EncodeToString(measurement)
	}
	return resp
}

// verifyServer serves body on /verify and captures each request.
func verifyServer(t *testing.T, body types.VerifyResponse, captured *types.VerifyRequest) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			t.Fatalf("path = %s, want /verify", r.URL.Path)
		}
		if captured != nil {
			if err := json.NewDecoder(r.Body).Decode(captured); err != nil {
				t.Fatalf("decode verify request: %v", err)
			}
		}
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func boolPtr(b bool) *bool { return &b }

func TestEnforceVerdict(t *testing.T) {
	expected := types.NewBase64Bytes([]byte("expected"))
	bound := types.VerifyRequest{Params: &types.VerifyParams{ExpectedReportData: &expected}}
	unbound := types.VerifyRequest{}

	cases := []struct {
		name    string
		req     types.VerifyRequest
		resp    types.VerifyResponse
		wantErr error
	}{
		{"valid and bound", bound, verifyResult("snp", true, boolPtr(true), nil), nil},
		{"signature invalid", bound, verifyResult("snp", false, boolPtr(true), nil), ErrSignatureInvalid},
		{"report_data_match false", bound, verifyResult("snp", true, boolPtr(false), nil), ErrReportDataMismatch},
		{"report_data_match nil fails closed", bound, verifyResult("snp", true, nil, nil), ErrReportDataMismatch},
		{"no expected report data skips match check", unbound, verifyResult("snp", true, nil, nil), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EnforceVerdict(tc.req, tc.resp)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("EnforceVerdict = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyEnforced(t *testing.T) {
	var captured types.VerifyRequest
	srv := verifyServer(t, verifyResult("snp", false, nil, nil), &captured)

	expected := types.NewBase64Bytes([]byte("expected"))
	_, err := NewClient(srv.URL).VerifyEnforced(context.Background(), types.VerifyRequest{
		Platform: "snp",
		Params:   &types.VerifyParams{ExpectedReportData: &expected},
	})
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("want ErrSignatureInvalid, got: %v", err)
	}
}

func TestVerifyEvidenceWireForm(t *testing.T) {
	var erd [64]byte
	for i := range erd[:sha512.Size384] {
		erd[i] = byte(i) // SHA-384 digest portion; bytes 48-63 stay zero
	}
	measurement := bytes.Repeat([]byte{0x42}, snpMeasurementSize)

	cases := []struct {
		platform string
		wantLen  int
	}{
		// az-snp binds via a TPM nonce of exactly the 48-byte digest.
		{string(types.PlatformAzSnp), sha512.Size384},
		// Native platforms carry the full 64-byte REPORTDATA field.
		{string(types.PlatformSnp), 64},
		{string(types.PlatformGcpSnp), 64},
		{string(types.PlatformTdx), 64},
	}
	for _, tc := range cases {
		t.Run(tc.platform, func(t *testing.T) {
			var captured types.VerifyRequest
			srv := verifyServer(t, verifyResult(tc.platform, true, boolPtr(true), measurement), &captured)

			_, err := NewClient(srv.URL).VerifyEvidence(context.Background(),
				types.AttestationEvidence{Platform: tc.platform, Evidence: json.RawMessage(`{"x":1}`)},
				EvidencePolicy{ExpectedReportData: erd, Measurements: [][]byte{measurement}})
			if err != nil {
				t.Fatalf("VerifyEvidence: %v", err)
			}
			got := captured.Params.ExpectedReportData.Bytes()
			if len(got) != tc.wantLen {
				t.Fatalf("expected_report_data is %d bytes, want %d", len(got), tc.wantLen)
			}
			if !bytes.Equal(got, erd[:tc.wantLen]) {
				t.Fatalf("expected_report_data = %x, want %x", got, erd[:tc.wantLen])
			}
			if captured.Platform != tc.platform {
				t.Fatalf("platform = %q, want %q", captured.Platform, tc.platform)
			}
			if captured.IssueToken == nil || *captured.IssueToken {
				t.Fatal("issue_token must be explicitly false")
			}
		})
	}
}

func TestVerifyEvidenceMeasurementPolicy(t *testing.T) {
	var erd [64]byte
	measurement := bytes.Repeat([]byte{0x42}, snpMeasurementSize)
	pin := [][]byte{measurement}

	cases := []struct {
		name    string
		resp    types.VerifyResponse
		policy  EvidencePolicy
		wantErr error
	}{
		{"measurement in set", verifyResult("snp", true, boolPtr(true), measurement),
			EvidencePolicy{ExpectedReportData: erd, Measurements: pin}, nil},
		{"measurement not in set", verifyResult("snp", true, boolPtr(true), bytes.Repeat([]byte{0x01}, snpMeasurementSize)),
			EvidencePolicy{ExpectedReportData: erd, Measurements: pin}, ErrMeasurementNotAllowed},
		{"measurement missing while pinned", verifyResult("snp", true, boolPtr(true), nil),
			EvidencePolicy{ExpectedReportData: erd, Measurements: pin}, ErrMeasurementNotAllowed},
		{"no pin accepts any measurement", verifyResult("snp", true, boolPtr(true), bytes.Repeat([]byte{0x01}, snpMeasurementSize)),
			EvidencePolicy{ExpectedReportData: erd}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := verifyServer(t, tc.resp, nil)
			_, err := NewClient(srv.URL).VerifyEvidence(context.Background(),
				types.AttestationEvidence{Platform: string(types.PlatformSnp), Evidence: json.RawMessage(`{}`)}, tc.policy)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("VerifyEvidence = %v, want %v", err, tc.wantErr)
			}
		})
	}

	t.Run("malformed launch digest is not a policy miss", func(t *testing.T) {
		resp := verifyResult("snp", true, boolPtr(true), nil)
		resp.Result.Claims.LaunchDigest = "not-hex"
		srv := verifyServer(t, resp, nil)
		_, err := NewClient(srv.URL).VerifyEvidence(context.Background(),
			types.AttestationEvidence{Platform: string(types.PlatformSnp), Evidence: json.RawMessage(`{}`)},
			EvidencePolicy{ExpectedReportData: erd, Measurements: pin})
		if !errors.Is(err, ErrInvalidLaunchDigest) {
			t.Fatalf("want ErrInvalidLaunchDigest, got: %v", err)
		}
	})

	// The TDX verifier surfaces no launch measurement; a pinned set is
	// documented as ignored (see EvidencePolicy.Measurements).
	t.Run("tdx ignores pinned measurements and sends no min_tcb", func(t *testing.T) {
		var captured types.VerifyRequest
		srv := verifyServer(t, verifyResult("tdx", true, boolPtr(true), nil), &captured)
		_, err := NewClient(srv.URL).VerifyEvidence(context.Background(),
			types.AttestationEvidence{Platform: string(types.PlatformTdx), Evidence: json.RawMessage(`{}`)},
			EvidencePolicy{ExpectedReportData: erd, Measurements: pin, MinTcb: &types.MinTcb{Snp: 1}})
		if err != nil {
			t.Fatalf("VerifyEvidence: %v", err)
		}
		if captured.Params.MinTcb != nil {
			t.Fatal("min_tcb must not be sent on the TDX path")
		}
	})
}

func TestVerifyEvidenceUnsupportedPlatformFailsClosed(t *testing.T) {
	srv := verifyServer(t, verifyResult("az-tdx", true, boolPtr(true), nil), nil)
	for _, platform := range []string{string(types.PlatformAzTdx), "dstack", ""} {
		_, err := NewClient(srv.URL).VerifyEvidence(context.Background(),
			types.AttestationEvidence{Platform: platform, Evidence: json.RawMessage(`{}`)},
			EvidencePolicy{})
		if !errors.Is(err, ErrUnsupportedPlatform) {
			t.Fatalf("platform %q: want ErrUnsupportedPlatform, got: %v", platform, err)
		}
	}
}
