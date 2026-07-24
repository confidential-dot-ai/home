package types

import (
	"encoding/json"
	"testing"
)

func TestDigestAddRequestRoundtrip(t *testing.T) {
	d, err := ParseDigest("sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(DigestAddRequest{Digest: d, Image: "img"})
	if err != nil {
		t.Fatal(err)
	}
	var got DigestAddRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Digest.String() != d.String() || got.Image != "img" {
		t.Fatalf("roundtrip mismatch: %#v", got)
	}
}

func TestDigestDeleteRequestRejectsBadDigest(t *testing.T) {
	if err := json.Unmarshal([]byte(`{"digests":["nope"]}`), &DigestDeleteRequest{}); err == nil {
		t.Fatal("expected invalid digest rejection")
	}
	// A valid decode should populate.
	var req DigestDeleteRequest
	d := "sha256:" + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if err := json.Unmarshal([]byte(`{"digests":["`+d+`"]}`), &req); err != nil {
		t.Fatalf("valid decode failed: %v", err)
	}
	if len(req.Digests) != 1 || req.Digests[0].String() != d {
		t.Fatalf("unexpected: %#v", req)
	}
}
