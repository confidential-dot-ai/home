//go:build linux

package rtmr3measurer

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/rtmr3"
)

const (
	hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cid1 = "1111111111111111111111111111111111111111111111111111111111111111"
	cid2 = "2222222222222222222222222222222222222222222222222222222222222222"
	cid3 = "3333333333333333333333333333333333333333333333333333333333333333"
)

// fakeTDX emulates the RTMR[3] sysfs node: writes fold into the register,
// reads return it.
type fakeTDX struct {
	reg     [rtmr3.Size]byte
	extends int
	fail    error
}

func (f *fakeTDX) extend(event [rtmr3.Size]byte) error {
	if f.fail != nil {
		return f.fail
	}
	f.reg = rtmr3.Extend(f.reg, event)
	f.extends++
	return nil
}

func (f *fakeTDX) read() ([rtmr3.Size]byte, error) { return f.reg, nil }

// newTestMeasurer wires a measurer against a tempdir watch dir, a tempdir
// state file, and a fake TDX register. Reusing statePath and tdx across
// instances simulates a daemon restart inside a still-running VM.
func newTestMeasurer(t *testing.T, watchDir, statePath string, tdx *fakeTDX) *measurer {
	t.Helper()
	m := newMeasurer(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	m.watchDir = watchDir
	m.statePath = statePath
	m.extend = tdx.extend
	m.readRegister = tdx.read
	m.configReadDeadline = 100 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond
	if err := m.loadState(); err != nil {
		t.Fatalf("loadState: %v", err)
	}
	return m
}

func writeConfigJSON(t *testing.T, watchDir, cid string, annotations map[string]string) {
	t.Helper()
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ociSpec{Annotations: annotations})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeWorkload(t *testing.T, watchDir, cid, hexDigest string) {
	t.Helper()
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/confidential-dot-ai/app@sha256:" + hexDigest,
	})
}

func TestScanMeasuresWorkloadExactlyOnce(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	m.scanOnce()
	m.scanOnce()

	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1", tdx.extends)
	}
	if tdx.reg != rtmr3.FromDigests([]string{"sha256:" + hexA}) {
		t.Fatal("register does not match the expected single-extend fold")
	}
}

func TestReplicaOrRestartSameImageDoesNotReExtend(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	// Same image under a new cid: a crash-looped container or a second replica.
	writeWorkload(t, watch, cid2, hexA)
	m.scanOnce()

	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1 (same digest must dedup across cids)", tdx.extends)
	}
}

// The finding this package's persistence exists for: a daemon restart
// (Restart=always) inside a still-running VM must NOT re-extend digests the
// previous process already measured.
func TestDaemonRestartDoesNotReExtend(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m1 := newTestMeasurer(t, watch, state, tdx)
	writeWorkload(t, watch, cid1, hexA)
	m1.scanOnce()
	if tdx.extends != 1 {
		t.Fatalf("setup: extends = %d, want 1", tdx.extends)
	}

	// New process, same VM: fresh maps, same state file, same register.
	m2 := newTestMeasurer(t, watch, state, tdx)
	m2.scanOnce()
	m2.scanOnce()

	if tdx.extends != 1 {
		t.Fatalf("extends = %d after restart, want 1 (double-extend corrupts the register)", tdx.extends)
	}
	// A genuinely new image after the restart still measures.
	writeWorkload(t, watch, cid2, hexB)
	m2.scanOnce()
	if tdx.extends != 2 {
		t.Fatalf("extends = %d, want 2 (new digest after restart must extend)", tdx.extends)
	}
	if tdx.reg != rtmr3.FromDigests([]string{"sha256:" + hexA, "sha256:" + hexB}) {
		t.Fatal("register does not match the expected two-extend fold")
	}
}

// Crash after record() but before the extend landed: the log names a digest
// the register lacks. Startup must finish the interrupted extend.
func TestCrashBetweenRecordAndExtendIsRepaired(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	if err := os.WriteFile(state, []byte("sha256:"+hexA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tdx := &fakeTDX{} // register still at the boot value: the extend never ran

	m := newTestMeasurer(t, watch, state, tdx)
	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1 (startup repair)", tdx.extends)
	}
	if tdx.reg != rtmr3.FromDigests([]string{"sha256:" + hexA}) {
		t.Fatal("register does not match the repaired fold")
	}
	// The repaired digest stays deduped.
	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1 (repaired digest must not re-extend)", tdx.extends)
	}
}

// Register matching neither fold means a foreign extend: never "repair" that
// by extending again — surface it and keep the log as dedup truth.
func TestForeignExtendIsNotReExtended(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	if err := os.WriteFile(state, []byte("sha256:"+hexA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tdx := &fakeTDX{reg: rtmr3.FromDigests([]string{"sha256:" + hexB})}

	m := newTestMeasurer(t, watch, state, tdx)
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (diverged register must not be extended)", tdx.extends)
	}
	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (recorded digest stays deduped)", tdx.extends)
	}
}

func TestSandboxContainerNotMeasured(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeConfigJSON(t, watch, cid1, map[string]string{
		"io.kubernetes.cri.container-type": "sandbox",
	})
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (sandbox/pause is not a workload)", tdx.extends)
	}
}

func TestUnpinnedImageNotMeasured(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeConfigJSON(t, watch, cid1, map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/confidential-dot-ai/app:latest",
	})
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (tag-only image carries no digest)", tdx.extends)
	}
	if _, seen := m.seenCids[cid1]; !seen {
		t.Fatal("unmeasurable cid must be marked seen (no rescan loop)")
	}
}

// A failed extend must roll the log back so a later cid with the same digest
// retries, and the log keeps matching the register.
func TestExtendFailureRollsBackAndRetries(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{fail: errors.New("sysfs write failed")}
	m := newTestMeasurer(t, watch, state, tdx)

	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0", tdx.extends)
	}
	if len(m.measuredOrder) != 0 {
		t.Fatalf("measuredOrder = %v, want empty after rollback", m.measuredOrder)
	}
	if b, err := os.ReadFile(state); err != nil || len(b) != 0 {
		t.Fatalf("state file = %q, %v; want empty after rollback", b, err)
	}

	tdx.fail = nil
	writeWorkload(t, watch, cid2, hexA) // same image, new cid
	m.scanOnce()
	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1 (retry after rollback)", tdx.extends)
	}
}

func TestSeenCidsPrunedWhenContainerDirGoes(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	if _, seen := m.seenCids[cid1]; !seen {
		t.Fatal("cid1 should be seen")
	}
	if err := os.RemoveAll(filepath.Join(watch, cid1)); err != nil {
		t.Fatal(err)
	}
	m.scanOnce()
	if _, seen := m.seenCids[cid1]; seen {
		t.Fatal("cid1 should be pruned after its dir disappeared")
	}
	if _, measured := m.measuredDigests["sha256:"+hexA]; !measured {
		t.Fatal("measuredDigests must NOT be pruned (it mirrors the append-only register)")
	}
}

func TestNormalizeDigest(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		wantErr  bool
	}{
		{in: "ghcr.io/confidential-dot-ai/app@sha256:" + hexA, want: hexA},
		{in: "sha256:" + hexA, want: hexA},
		{in: hexA, want: hexA},
		{in: "SHA256:" + hexA, want: hexA},
		{in: "  sha256:" + hexA + "  ", want: hexA},
		{in: "ghcr.io/confidential-dot-ai/app:latest", wantErr: true},
		{in: "sha256:tooshort", wantErr: true},
		{in: "", wantErr: true},
	} {
		got, err := normalizeDigest(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeDigest(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeDigest(%q) err = %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeDigest(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExtractDigestAnnotationFallback(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        string
		wantOK      bool
	}{
		{
			name: "image-name preferred",
			annotations: map[string]string{
				"io.kubernetes.cri.image-name": "x@sha256:" + hexA,
				"io.kubernetes.cri.image-id":   "y@sha256:" + hexB,
			},
			want: "sha256:" + hexA, wantOK: true,
		},
		{
			name: "falls back to image-id",
			annotations: map[string]string{
				"io.kubernetes.cri.image-name": "x:latest",
				"io.kubernetes.cri.image-id":   "y@sha256:" + hexB,
			},
			want: "sha256:" + hexB, wantOK: true,
		},
		{
			name:        "nothing usable",
			annotations: map[string]string{"io.kubernetes.cri.image-name": "x:latest"},
			wantOK:      false,
		},
	} {
		got, ok := extractDigest(tc.annotations)
		if ok != tc.wantOK || (ok && got != tc.want) {
			t.Errorf("%s: extractDigest = %q, %v; want %q, %v", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}
