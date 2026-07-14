//go:build linux

package policymonitor

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// (The thread-safe pidLocator test double lives in monitor_test.go as
// threadSafeFakeLocator, because it's used from goroutines started by
// the inotify dispatcher. There is no second non-thread-safe variant —
// the kill_test.go cases drive findInitPID directly through the real
// cgroupLocator against a tempdir-rooted fake hierarchy.)

// fakeKiller records every call and lets the test assert on it. The
// mutex makes it safe to share between the inotify dispatch goroutine
// and the test's polling loop in monitor_test.go.
type fakeKiller struct {
	mu    sync.Mutex
	calls []killCall
	err   error
}

type killCall struct {
	pid int
	sig os.Signal
}

func (k *fakeKiller) kill(pid int, sig os.Signal) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, killCall{pid: pid, sig: sig})
	return k.err
}

// snapshot returns a copy of the recorded calls so tests can assert
// without holding the lock.
func (k *fakeKiller) snapshot() []killCall {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]killCall, len(k.calls))
	copy(out, k.calls)
	return out
}

func TestFindCgroupDir_FoundAtRoot(t *testing.T) {
	root := t.TempDir()
	cid := "abc123"
	if err := os.MkdirAll(filepath.Join(root, cid), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := findCgroupDir(root, cid)
	if err != nil {
		t.Fatalf("findCgroupDir: %v", err)
	}
	if got == "" {
		t.Fatal("expected non-empty path")
	}
	if filepath.Base(got) != cid {
		t.Errorf("basename = %q, want %q", filepath.Base(got), cid)
	}
}

func TestFindCgroupDir_NestedUnderSlice(t *testing.T) {
	root := t.TempDir()
	cid := "deadbeef"
	nested := filepath.Join(root, "system.slice", "kata-shim-foo.scope", cid)
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := findCgroupDir(root, cid)
	if err != nil {
		t.Fatalf("findCgroupDir: %v", err)
	}
	if got != nested {
		t.Errorf("got %q, want %q", got, nested)
	}
}

// TestFindCgroupDir_SystemdScope covers the real-world layout a systemd-PID-1
// kata guest produces: the container's cgroup is a systemd scope
// (cri-containerd-<cid>.scope) nested under the pod's kubepods*.slice, not a
// bare <cid> directory. Matching only the bare basename was a silent
// enforcement hole — a denied container's SIGKILL never landed.
func TestFindCgroupDir_SystemdScope(t *testing.T) {
	root := t.TempDir()
	cid := "b790433fdb4f223a51940bae06c1cd54d73377fc3ea45c4fa5c7ea3bd4b6c829"
	scope := filepath.Join(root, "kubepods.slice", "kubepods-besteffort.slice",
		"kubepods-besteffort-podabc.slice", "cri-containerd-"+cid+".scope")
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := findCgroupDir(root, cid)
	if err != nil {
		t.Fatalf("findCgroupDir: %v", err)
	}
	if got != scope {
		t.Errorf("got %q, want %q", got, scope)
	}
}

func TestCgroupDirMatchesCID(t *testing.T) {
	cid := "b790433fdb4f223a51940bae06c1cd54d73377fc3ea45c4fa5c7ea3bd4b6c829"
	for _, tc := range []struct {
		name string
		want bool
	}{
		{cid, true},            // flat fs driver
		{cid + ".scope", true}, // bare systemd scope
		{"cri-containerd-" + cid + ".scope", true},  // containerd systemd driver
		{"crio-" + cid + ".scope", true},            // CRI-O systemd driver
		{"kubepods-besteffort-podabc.slice", false}, // a pod slice, not the container
		{"other-" + cid[:20], false},                // partial id must not match
		{"deadbeef", false},
		{"", false},
	} {
		if got := cgroupDirMatchesCID(tc.name, cid); got != tc.want {
			t.Errorf("cgroupDirMatchesCID(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFindCgroupDir_NotFound(t *testing.T) {
	root := t.TempDir()
	got, err := findCgroupDir(root, "missing")
	if err != nil {
		t.Fatalf("findCgroupDir: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestReadFirstPID(t *testing.T) {
	dir := t.TempDir()
	procs := filepath.Join(dir, "cgroup.procs")
	if err := os.WriteFile(procs, []byte("12345\n67890\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pid, err := readFirstPID(procs)
	if err != nil {
		t.Fatalf("readFirstPID: %v", err)
	}
	if pid != 12345 {
		t.Errorf("pid = %d, want 12345", pid)
	}
}

func TestReadFirstPID_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	procs := filepath.Join(dir, "cgroup.procs")
	if err := os.WriteFile(procs, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readFirstPID(procs)
	if err == nil {
		t.Fatal("expected error on empty file")
	}
}

func TestCgroupLocator_WaitsForCgroupToAppear(t *testing.T) {
	root := t.TempDir()
	cid := "feedface"
	locator := &cgroupLocator{
		cgroupRoot:   root,
		waitTimeout:  500 * time.Millisecond,
		pollInterval: 20 * time.Millisecond,
	}
	// Drop the cgroup in after a short delay; the locator should
	// re-scan and find it.
	go func() {
		time.Sleep(75 * time.Millisecond)
		dir := filepath.Join(root, cid)
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("4242\n"), 0o644)
	}()
	pid, ok, err := locator.findInitPID(cid)
	if err != nil {
		t.Fatalf("findInitPID: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if pid != 4242 {
		t.Errorf("pid = %d, want 4242", pid)
	}
}

func TestCgroupLocator_Timeout(t *testing.T) {
	root := t.TempDir()
	locator := &cgroupLocator{
		cgroupRoot:   root,
		waitTimeout:  50 * time.Millisecond,
		pollInterval: 20 * time.Millisecond,
	}
	pid, ok, err := locator.findInitPID("never-appears")
	if err != nil {
		t.Fatalf("findInitPID: %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false, got pid=%d", pid)
	}
}
