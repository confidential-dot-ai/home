package issuer_test

import (
	"encoding/json"
	"testing"

	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/internal/issuer"
)

func TestCheckMeasurementNormalizesLaunchDigestCase(t *testing.T) {
	rawEvidence, err := json.Marshal(map[string]any{
		earclaims.SubmodAttester: map[string]any{
			earclaims.LaunchDigest: "DEADBEEF",
		},
	})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	claims := &issuer.EARClaims{RawEvidence: rawEvidence}

	if err := issuer.CheckMeasurement(claims, map[string]bool{"deadbeef": true}, "sign-csr"); err != nil {
		t.Fatalf("uppercase launch digest should match lowercase allowlist: %v", err)
	}
}
