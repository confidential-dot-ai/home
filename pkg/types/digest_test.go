package types

import (
	"encoding/json"
	"testing"
)

const validDigest = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

func TestParseDigestValid(t *testing.T) {
	d, err := ParseDigest(validDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.String() != validDigest {
		t.Fatalf("got %q, want %q", d.String(), validDigest)
	}
}

func TestParseDigestCanonicalizesToLowercase(t *testing.T) {
	upper := "sha256:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"
	d, err := ParseDigest(upper)
	if err != nil {
		t.Fatalf("uppercase hex must be valid: %v", err)
	}
	if d.String() != validDigest {
		t.Fatalf("got %q, want lowercase %q", d.String(), validDigest)
	}
}

func TestParseDigestRejectsMissingPrefix(t *testing.T) {
	_, err := ParseDigest("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	if err == nil {
		t.Fatal("expected error for missing prefix")
	}
}

func TestParseDigestRejectsWrongHexLength(t *testing.T) {
	_, err := ParseDigest("sha256:abcd")
	if err == nil {
		t.Fatal("expected error for wrong hex length")
	}
}

func TestParseDigestRejectsNonHexChars(t *testing.T) {
	// 64 chars but contains 'g' and 'z'
	_, err := ParseDigest("sha256:g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6z1b2")
	if err == nil {
		t.Fatal("expected error for non-hex characters")
	}
}

func TestDigestJSONMarshalProducesPlainString(t *testing.T) {
	d, err := ParseDigest(validDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	want := `"` + validDigest + `"`
	if string(data) != want {
		t.Fatalf("got %s, want %s", data, want)
	}
}

func TestDigestJSONUnmarshalWithValidation(t *testing.T) {
	raw := `"` + validDigest + `"`
	var d Digest
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if d.String() != validDigest {
		t.Fatalf("got %q, want %q", d.String(), validDigest)
	}
}

func TestDigestJSONUnmarshalRejectsInvalid(t *testing.T) {
	var d Digest
	if err := json.Unmarshal([]byte(`"notadigest"`), &d); err == nil {
		t.Fatal("expected error for invalid digest")
	}
}

func TestDigestAsJSONMapKey(t *testing.T) {
	d, err := ParseDigest(validDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	original := map[Digest]string{d: "nginx:latest"}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded map[Digest]string
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	val, ok := decoded[d]
	if !ok {
		t.Fatal("key not found after roundtrip")
	}
	if val != "nginx:latest" {
		t.Fatalf("got %q, want %q", val, "nginx:latest")
	}
}

func TestDigestTextMarshalUnmarshalRoundtrip(t *testing.T) {
	d, err := ParseDigest(validDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text, err := d.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText error: %v", err)
	}
	if string(text) != validDigest {
		t.Fatalf("got %q, want %q", text, validDigest)
	}

	var d2 Digest
	if err := d2.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText error: %v", err)
	}
	if d2.String() != validDigest {
		t.Fatalf("got %q, want %q", d2.String(), validDigest)
	}
}
