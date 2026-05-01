package getcert

import (
	"os"
	"testing"
)

func TestParseFileMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		want    os.FileMode
		wantErr bool
	}{
		{name: "owner-only", mode: "0600", want: 0600},
		{name: "group-readable", mode: "0640", want: 0640},
		{name: "without-leading-zero", mode: "640", want: 0640},
		{name: "invalid-octal", mode: "0999", wantErr: true},
		{name: "special-bits", mode: "1777", wantErr: true},
		{name: "empty", mode: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFileMode(tt.mode)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseFileMode(%q) succeeded, want error", tt.mode)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFileMode(%q): %v", tt.mode, err)
			}
			if got != tt.want {
				t.Fatalf("parseFileMode(%q) = %#o, want %#o", tt.mode, got, tt.want)
			}
		})
	}
}
