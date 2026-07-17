package ratls

import "testing"

func TestNormalizePlatform(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"", ""},
		{" ", ""},
		{"snp", "sev-snp"},
		{"SEV-SNP", "sev-snp"},
		{"az-snp", "sev-snp"},
		{"gcp-snp", "sev-snp"},
		{"tdx", "tdx"},
		{"az-tdx", "tdx"},
		{"unknown", "unknown"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := NormalizePlatform(tc.input); got != tc.want {
				t.Fatalf("NormalizePlatform(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
