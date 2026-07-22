package luksopen

import (
	"strings"
	"testing"
)

func TestParseVolumeSpecs(t *testing.T) {
	vols, err := ParseVolumeSpecs([]string{
		"data=/dev/vdb:data:ext4:open",
		"scratch=/dev/vdc:scratch-secret:xfs:format-if-empty",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 2 {
		t.Fatalf("want 2 vols, got %d", len(vols))
	}
	if vols[0].Name != "data" || vols[0].Dev != "/dev/vdb" || vols[0].SecretName != "data" ||
		vols[0].FSType != "ext4" || vols[0].Mode != "open" {
		t.Errorf("vols[0] wrong: %+v", vols[0])
	}
	if vols[1].SecretName != "scratch-secret" || vols[1].Mode != "format-if-empty" {
		t.Errorf("vols[1] wrong: %+v", vols[1])
	}
}

func TestParseVolumeSpecsErrors(t *testing.T) {
	cases := []struct {
		spec, want string
	}{
		{"no-equals", "want <name>=<dev>"},
		{"data=", "want <name>=<dev>"},
		{"data=/dev/vdb", "want 4 colon-separated fields"},
		{"data=/dev/vdb:sec:ext4:wat", "mode must be open or format-if-empty"},
		{"data=:sec:ext4:open", "dev/secretName/fstype must be non-empty"},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			_, err := ParseVolumeSpecs([]string{tc.spec})
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestTrimTrailingNewline(t *testing.T) {
	if got := string(trimTrailingNewline([]byte("hello\n"))); got != "hello" {
		t.Errorf("got %q", got)
	}
	if got := string(trimTrailingNewline([]byte("hello\r\n"))); got != "hello" {
		t.Errorf("got %q", got)
	}
	if got := string(trimTrailingNewline([]byte("hello"))); got != "hello" {
		t.Errorf("got %q", got)
	}
}
