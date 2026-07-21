package nriimagepolicy

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func digestsOf(b *workloadBroker, pid int) ([]string, error) {
	cs, err := b.ContainersForPeer(pid)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range cs {
		out = append(out, c.Digest)
	}
	return out, nil
}

const (
	digestApp   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestApp2  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	digestOther = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

	// CRI container IDs are 64-hex (what the cgroup path carries).
	cidGetCert = "1111111111111111111111111111111111111111111111111111111111111111"
	cidApp1    = "aaaa111111111111111111111111111111111111111111111111111111111111"
	cidApp2    = "bbbb222222222222222222222222222222222222222222222222222222222222"
	cidOther   = "cccc333333333333333333333333333333333333333333333333333333333333"
)

// writeCgroup creates <procRoot>/<pid>/cgroup naming containerID.
func writeCgroup(t *testing.T, procRoot string, pid int, containerID string) {
	t.Helper()
	dir := filepath.Join(procRoot, itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "0::/kubepods.slice/.../cri-containerd-" + containerID + ".scope\n"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestBrokerResolvesPodAndExcludesInjected: a get-cert caller in pod P gets P's
// app-container digests, excluding the injected sidecar and any other pod.
func TestBrokerResolvesPodAndExcludesInjected(t *testing.T) {
	procRoot := t.TempDir()
	b := newWorkloadBroker(procRoot)

	const (
		pod1 = "sandbox-1"
		pod2 = "sandbox-2"
	)
	// pod1: get-cert sidecar + two app containers.
	b.record(cidGetCert, pod1, "c8s-cert", digestOther, nil)
	b.record(cidApp1, pod1, "app", digestApp, nil)
	b.record(cidApp2, pod1, "worker", digestApp2, nil)
	// pod2: a different app; must never appear in pod1's answer.
	b.record(cidOther, pod2, "app", digestOther, nil)

	// The caller is the get-cert process in pod1.
	writeCgroup(t, procRoot, 4242, cidGetCert)

	got, err := digestsOf(b, 4242)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	want := []string{digestApp2, digestApp} // sorted: 2... < a...
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("digests = %v, want %v (pod1 app containers, no sidecar, no pod2)", got, want)
	}
}

func TestBrokerRejectsUntrackedAndZeroPID(t *testing.T) {
	procRoot := t.TempDir()
	b := newWorkloadBroker(procRoot)
	b.record(cidApp1, "sandbox-1", "app", digestApp, nil)

	if _, err := digestsOf(b, 0); err == nil {
		t.Fatal("peer pid 0 accepted (node-CVM must bind the caller)")
	}
	writeCgroup(t, procRoot, 55, cidOther)
	if _, err := digestsOf(b, 55); err == nil {
		t.Fatal("untracked caller container accepted")
	}
}

// The nesting attack (review finding #1): a caller in pod2 creates a child
// cgroup named with pod1's app container ID. The broker must resolve the
// shallowest tracked container (pod2's own get-cert), NOT the nested pod1 ID,
// so it returns pod2's digests — never pod1's.
func TestBrokerRejectsNestedVictimCgroup(t *testing.T) {
	procRoot := t.TempDir()
	b := newWorkloadBroker(procRoot)

	const pod1, pod2 = "sandbox-1", "sandbox-2"
	b.record(cidApp1, pod1, "app", digestApp, nil) // victim's app in pod1
	b.record(cidGetCert, pod2, "c8s-cert", digestOther, nil)
	b.record(cidApp2, pod2, "app", digestApp2, nil) // attacker's own app in pod2

	// Attacker's process: its real scope is cidGetCert (pod2), with a nested
	// child cgroup named cidApp1 (pod1's container).
	dir := filepath.Join(procRoot, "999")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "0::/kubepods/.../cri-containerd-" + cidGetCert + ".scope/" + cidApp1 + "\n"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := digestsOf(b, 999)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got, digestApp) {
		t.Fatalf("nested victim cgroup leaked pod1's digest: %v", got)
	}
	if !slices.Contains(got, digestApp2) {
		t.Fatalf("attacker's own pod2 digests missing: %v", got)
	}
}

func TestBrokerEvicts(t *testing.T) {
	procRoot := t.TempDir()
	b := newWorkloadBroker(procRoot)
	b.record(cidGetCert, "sandbox-1", "c8s-cert", digestOther, nil)
	b.record(cidApp1, "sandbox-1", "app", digestApp, nil)
	writeCgroup(t, procRoot, 77, cidGetCert)

	b.remove(cidApp1)
	got, err := digestsOf(b, 77)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("evicted digest still served: %v", got)
	}
}
