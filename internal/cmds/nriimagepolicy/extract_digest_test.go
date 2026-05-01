package nriimagepolicy

import "testing"

func TestExtractDigest(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"registry/repo@sha256:abc123", "sha256:abc123"},
		{"registry/repo:tag@sha256:abc123", "sha256:abc123"},
		{"registry/repo:latest", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractDigest(tt.input)
		if got != tt.want {
			t.Errorf("extractDigest(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
