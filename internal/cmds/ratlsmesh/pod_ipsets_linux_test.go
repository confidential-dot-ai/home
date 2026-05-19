//go:build linux

package ratlsmesh

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestCollectPodIPSetMembersSkipsHostNetworkAndDeduplicates(t *testing.T) {
	sets := collectPodIPSetMembers([]interface{}{
		&corev1.Pod{
			Status: corev1.PodStatus{
				HostIP: "10.0.0.1",
				PodIP:  "10.244.0.5",
				PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}, {IP: "fd00:0:0:0:0:0:0:5"}},
			},
		},
		&corev1.Pod{
			Status: corev1.PodStatus{
				HostIP: "10.0.0.2",
				PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
			},
		},
		&corev1.Pod{
			Spec: corev1.PodSpec{HostNetwork: true},
			Status: corev1.PodStatus{
				PodIPs: []corev1.PodIP{{IP: "10.0.0.10"}},
			},
		},
		&corev1.Pod{
			Status: corev1.PodStatus{
				HostIP: "10.0.0.1",
				PodIP:  "10.244.0.6",
			},
		},
	}, "10.0.0.1")

	if want := []string{"10.244.0.5", "10.244.0.6"}; !reflect.DeepEqual(sets.allIPv4, want) {
		t.Fatalf("IPv4 pod IPs = %#v, want %#v", sets.allIPv4, want)
	}
	if want := []string{"fd00::5"}; !reflect.DeepEqual(sets.allIPv6, want) {
		t.Fatalf("IPv6 pod IPs = %#v, want %#v", sets.allIPv6, want)
	}
	if want := []string{"10.244.0.5", "10.244.0.6"}; !reflect.DeepEqual(sets.localIPv4, want) {
		t.Fatalf("local IPv4 pod IPs = %#v, want %#v", sets.localIPv4, want)
	}
	if want := []string{"fd00::5"}; !reflect.DeepEqual(sets.localIPv6, want) {
		t.Fatalf("local IPv6 pod IPs = %#v, want %#v", sets.localIPv6, want)
	}
}

func TestBuildIPSetRestoreScriptBatchesMembersWithMaxElem(t *testing.T) {
	script, err := buildIPSetRestoreScript("RATLS-MESH-PODS", "inet", []string{"10.244.0.5", "10.244.0.6"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"create RATLS-MESH-PODS hash:ip family inet maxelem 1024 -exist\n",
		"create RATLS-MESH-PODS-TMP hash:ip family inet maxelem 1024\n",
		"flush RATLS-MESH-PODS-TMP\n",
		"add RATLS-MESH-PODS-TMP 10.244.0.5 -exist\n",
		"add RATLS-MESH-PODS-TMP 10.244.0.6 -exist\n",
		"swap RATLS-MESH-PODS-TMP RATLS-MESH-PODS\n",
		"destroy RATLS-MESH-PODS-TMP\n",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("restore script missing %q\n%s", want, script)
		}
	}
}

func TestBuildIPSetRestoreScriptRejectsOversizedSet(t *testing.T) {
	_, err := buildIPSetRestoreScript("RATLS-MESH-PODS", "inet", []string{"10.244.0.5", "10.244.0.6"}, 1)
	if err == nil {
		t.Fatal("expected maxelem error")
	}
	if !strings.Contains(err.Error(), "exceeds maxelem 1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResetReadyFileRemovesStaleProbeMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ratls-iptables-ready")
	if err := os.WriteFile(path, []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := resetReadyFile(path); err != nil {
		t.Fatalf("resetReadyFile: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ready file still exists after reset: stat err=%v", err)
	}
	if err := resetReadyFile(path); err != nil {
		t.Fatalf("resetReadyFile should ignore already-removed path: %v", err)
	}
}

func TestParseIPSetMaxElemHeader(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		want    int
		wantErr string
	}{
		{
			name: "ipset 7.x header with skbinfo and counters",
			out: `Name: RATLS-MESH-PODS
Type: hash:ip
Revision: 5
Header: family inet hashsize 1024 maxelem 262144 bucketsize 12 initval 0xdeadbeef
Size in memory: 408
References: 1
Number of entries: 3
`,
			want: 262144,
		},
		{
			name: "ipset 6.x minimal header",
			out: `Name: RATLS-MESH-PODS6
Type: hash:ip
Header: family inet6 hashsize 1024 maxelem 1024
`,
			want: 1024,
		},
		{
			name:    "no header line",
			out:     "Name: RATLS-MESH-PODS\nType: hash:ip\n",
			wantErr: "no header line",
		},
		{
			name:    "header missing maxelem",
			out:     "Header: family inet hashsize 1024\n",
			wantErr: "header missing maxelem",
		},
		{
			name:    "non-integer maxelem",
			out:     "Header: family inet hashsize 1024 maxelem oops\n",
			wantErr: "parse maxelem",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIPSetMaxElemHeader(tt.out)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v; want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("maxelem = %d; want %d", got, tt.want)
			}
		})
	}
}
