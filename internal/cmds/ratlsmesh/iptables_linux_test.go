//go:build linux

package ratlsmesh

import (
	"reflect"
	"testing"
)

func TestParseExcludeUIDs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint32
		wantErr bool
	}{
		{name: "empty", input: "", want: nil},
		{name: "single zero", input: "0", want: []uint32{0}},
		{name: "single non-root", input: "1337", want: []uint32{1337}},
		{name: "multiple", input: "0,65534", want: []uint32{0, 65534}},
		{name: "whitespace trimmed", input: " 0 , 65534 ", want: []uint32{0, 65534}},
		{name: "trailing comma skipped", input: "0,1,", want: []uint32{0, 1}},
		{name: "leading comma skipped", input: ",0,1", want: []uint32{0, 1}},
		{name: "only commas", input: ",,,", want: nil},
		{name: "only whitespace", input: "  ", want: nil},
		// Duplicates are preserved verbatim; the rule builder emits one
		// RETURN per entry and the second match is unreachable, so the
		// duplicate is benign rather than meaningful.
		{name: "duplicates kept", input: "0,0", want: []uint32{0, 0}},
		{name: "max uint32", input: "4294967295", want: []uint32{4294967295}},
		{name: "negative rejected", input: "-1", wantErr: true},
		{name: "overflow rejected", input: "4294967296", wantErr: true},
		{name: "non-numeric rejected", input: "abc", wantErr: true},
		{name: "mixed numeric and bad", input: "0,abc", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseExcludeUIDs(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseExcludeUIDs(%q) = %v, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExcludeUIDs(%q) unexpected error: %v", tc.input, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseExcludeUIDs(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseJumpAtHead(t *testing.T) {
	jump := iptablesRule{
		chain: "PREROUTING",
		args:  []string{"-j", preroutingChainName},
	}
	tests := []struct {
		name        string
		out         string
		wantAtHead  bool
		wantPresent bool
	}{
		{
			name: "absent on clean chain",
			out:  "-P PREROUTING ACCEPT\n",
		},
		{
			name: "at head",
			out: `-P PREROUTING ACCEPT
-A PREROUTING -j RATLS-MESH-PREROUTING
-A PREROUTING -j KUBE-SERVICES
`,
			wantAtHead:  true,
			wantPresent: true,
		},
		{
			name: "demoted below kube services",
			out: `-P PREROUTING ACCEPT
-A PREROUTING -j KUBE-SERVICES
-A PREROUTING -j RATLS-MESH-PREROUTING
`,
			wantPresent: true,
		},
		{
			name: "other chain ignored",
			out: `-A OUTPUT -j RATLS-MESH-PREROUTING
-A PREROUTING -j KUBE-SERVICES
`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAtHead, gotPresent := parseJumpAtHead(tc.out, jump)
			if gotAtHead != tc.wantAtHead || gotPresent != tc.wantPresent {
				t.Fatalf("parseJumpAtHead = (atHead=%v, present=%v), want (%v, %v)", gotAtHead, gotPresent, tc.wantAtHead, tc.wantPresent)
			}
		})
	}
}
