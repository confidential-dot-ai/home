//go:build linux

package rtmr3measurer

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/rtmr3"
)

// Malformed and duplicate log lines are tolerated: skipped/deduped, never
// treated as measured digests.
func TestLoadStateSkipsMalformedAndDuplicateLines(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	log := "sha256:" + hexA + "\n" +
		"not-a-digest\n" +
		"sha256:tooshort\n" +
		"\n" +
		"sha256:" + hexA + "\n" // duplicate
	if err := os.WriteFile(state, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	tdx := &fakeTDX{reg: rtmr3.FromDigests([]string{"sha256:" + hexA})}

	m := newTestMeasurer(t, watch, state, tdx)
	if len(m.measuredOrder) != 1 || m.measuredOrder[0] != "sha256:"+hexA {
		t.Fatalf("measuredOrder = %v, want exactly [sha256:%s]", m.measuredOrder, hexA)
	}
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (register already matches the log)", tdx.extends)
	}
}

// An unreadable register at startup must not block: the log stays the dedup
// truth and nothing is extended.
func TestLoadStateRegisterReadFailureKeepsLogAsTruth(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	if err := os.WriteFile(state, []byte("sha256:"+hexA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tdx := &fakeTDX{}

	m := newMeasurer(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	m.watchDir = watch
	m.statePath = state
	m.extend = tdx.extend
	m.readRegister = func() ([rtmr3.Size]byte, error) {
		return [rtmr3.Size]byte{}, errors.New("sysfs read failed")
	}
	if err := m.loadState(); err != nil {
		t.Fatalf("loadState: %v (register read failure must not be fatal)", err)
	}
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0", tdx.extends)
	}
	if _, ok := m.measuredDigests["sha256:"+hexA]; !ok {
		t.Fatal("logged digest must stay deduped when the register is unreadable")
	}
}

// A repair extend that itself fails is fatal: the process must not run with a
// log/register mismatch it knows how to fix but couldn't.
func TestLoadStateRepairExtendFailureIsFatal(t *testing.T) {
	state := filepath.Join(t.TempDir(), "measured")
	if err := os.WriteFile(state, []byte("sha256:"+hexA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tdx := &fakeTDX{fail: errors.New("sysfs write failed")} // register at boot value

	m := newMeasurer(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	m.statePath = state
	m.extend = tdx.extend
	m.readRegister = tdx.read
	if err := m.loadState(); err == nil {
		t.Fatal("loadState = nil, want error when the repair extend fails")
	}
}

func TestLoadStateUnreadableLogIsFatal(t *testing.T) {
	state := filepath.Join(t.TempDir(), "measured")
	if err := os.Mkdir(state, 0o755); err != nil { // a directory: ReadFile fails, not ErrNotExist
		t.Fatal(err)
	}
	m := newMeasurer(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	m.statePath = state
	if err := m.loadState(); err == nil {
		t.Fatal("loadState = nil, want error for an unreadable log")
	}
}

func TestLoadStateStateDirCreateFailureIsFatal(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := newMeasurer(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	m.statePath = filepath.Join(blocker, "measured") // parent is a regular file
	if err := m.loadState(); err == nil {
		t.Fatal("loadState = nil, want error when the state dir cannot be created")
	}
}

// An unreadable watch dir warns (throttled) instead of spinning silently, and
// the failure counter resets once the dir is back.
func TestScanOnceUnreadableWatchDir(t *testing.T) {
	watch, state := filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	m.scanOnce()
	m.scanOnce()
	if m.readDirFails != 2 {
		t.Fatalf("readDirFails = %d, want 2", m.readDirFails)
	}

	if err := os.MkdirAll(watch, 0o755); err != nil {
		t.Fatal(err)
	}
	m.scanOnce()
	if m.readDirFails != 0 {
		t.Fatalf("readDirFails = %d, want 0 after the dir is readable again", m.readDirFails)
	}
}

// Non-container entries are ignored: plain files, and dirs whose name is not a
// 64-hex container id ("shared"/"sandbox"/"image").
func TestScanOnceIgnoresNonContainerEntries(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	if err := os.WriteFile(filepath.Join(watch, "stray-file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeConfigJSON(t, watch, "shared", map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/confidential-dot-ai/app@sha256:" + hexA,
	})
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (non-cid entries are not workloads)", tdx.extends)
	}
	if len(m.seenCids) != 0 {
		t.Fatalf("seenCids = %v, want empty", m.seenCids)
	}
}

// If the digest cannot be recorded, it must NOT be extended: the log leading
// the register is repairable, the register leading the log is not.
func TestRecordFailureBlocksExtend(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	if err := os.Mkdir(state, 0o755); err != nil { // OpenFile O_WRONLY on a dir fails
		t.Fatal(err)
	}
	tdx := &fakeTDX{}
	m := newMeasurer(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	m.watchDir = watch
	m.statePath = state
	m.extend = tdx.extend
	m.readRegister = tdx.read
	m.configReadDeadline = 100 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond

	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (unrecorded digest must not be extended)", tdx.extends)
	}
	if len(m.measuredOrder) != 0 {
		t.Fatalf("measuredOrder = %v, want empty", m.measuredOrder)
	}
}

// A config.json that stays invalid JSON past the deadline is retried next
// scan (cid not marked seen); one that never appears behaves the same.
func TestReadConfigInvalidJSONAndMissingFile(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)
	m.configReadDeadline = 20 * time.Millisecond

	dir1 := filepath.Join(watch, cid1)
	if err := os.MkdirAll(dir1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir1, "config.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(watch, cid2), 0o755); err != nil { // no config.json at all
		t.Fatal(err)
	}

	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0", tdx.extends)
	}
	if len(m.seenCids) != 0 {
		t.Fatalf("seenCids = %v, want empty (undecided cids must be retried)", m.seenCids)
	}

	// The config becoming valid on a later scan is then measured.
	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1 once config.json turns valid", tdx.extends)
	}
}

// unrecordLast trims the in-memory order even when the log rewrite fails, and
// only logs the rewrite error.
func TestUnrecordLastRewriteFailureIsLoggedNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 0500 does not block writes, so the rewrite-failure path is not exercised")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "measured")
	if err := os.WriteFile(state, []byte("sha256:"+hexA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newMeasurer(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	m.statePath = state
	m.measuredOrder = []string{"sha256:" + hexA}

	if err := os.Chmod(dir, 0o500); err != nil { // .tmp WriteFile fails
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	})

	m.unrecordLast("sha256:" + hexA)
	if len(m.measuredOrder) != 0 {
		t.Fatalf("measuredOrder = %v, want empty even when the rewrite fails", m.measuredOrder)
	}
}

// The real sysfs helpers, pointed at a temp file standing in for the TSM node.
func TestSysfsExtendAndReadRegister(t *testing.T) {
	orig := rtmr3Sysfs
	t.Cleanup(func() { rtmr3Sysfs = orig })

	node := filepath.Join(t.TempDir(), "rtmr3:sha384")
	if err := os.WriteFile(node, make([]byte, rtmr3.Size), 0o600); err != nil {
		t.Fatal(err)
	}
	rtmr3Sysfs = node

	event := rtmr3.Event("sha256:" + hexA)
	if err := extendSysfs(event); err != nil {
		t.Fatalf("extendSysfs: %v", err)
	}
	got, err := readRegisterSysfs()
	if err != nil {
		t.Fatalf("readRegisterSysfs: %v", err)
	}
	if !bytes.Equal(got[:], event[:]) {
		t.Fatal("readRegisterSysfs did not return the written event bytes")
	}

	// Wrong-size node contents are rejected, not silently truncated.
	if err := os.WriteFile(node, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegisterSysfs(); err == nil {
		t.Fatal("readRegisterSysfs = nil error, want size mismatch error")
	}

	// A missing node fails both helpers.
	rtmr3Sysfs = filepath.Join(t.TempDir(), "absent", "rtmr3:sha384")
	if err := extendSysfs(event); err == nil {
		t.Fatal("extendSysfs = nil error, want write failure")
	}
	if _, err := readRegisterSysfs(); err == nil {
		t.Fatal("readRegisterSysfs = nil error, want read failure")
	}
}
