package probefile

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbePassesOnNonEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := probe(path); err != nil {
		t.Fatalf("probe(non-empty file) = %v, want nil", err)
	}
}

func TestProbeFailsOnMissingFile(t *testing.T) {
	if err := probe(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("probe(missing) = nil, want error")
	}
}

func TestProbeFailsOnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}

	err := probe(path)
	if err == nil {
		t.Fatal("probe(empty) = nil, want error")
	}
}

func TestProbeFailsOnDirectory(t *testing.T) {
	if err := probe(t.TempDir()); err == nil {
		t.Fatal("probe(dir) = nil, want error")
	}
}

func TestWaitForReturnsOnceFileAppears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")

	go func() {
		time.Sleep(50 * time.Millisecond)
		tmp := filepath.Join(dir, "cert.pem.tmp")
		if err := os.WriteFile(tmp, []byte("hello"), 0600); err != nil {
			return
		}
		_ = os.Rename(tmp, path)
	}()

	// interval <= 0 exercises the default-interval branch; it is clamped to
	// 1s, so the file written above is seen on the second iteration.
	if err := waitFor(path, 0, 10*time.Second); err != nil {
		t.Fatalf("waitFor(appearing file) = %v, want nil", err)
	}
}

func TestWaitForTimesOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never.pem")

	err := waitFor(path, 10*time.Millisecond, 50*time.Millisecond)
	if err == nil {
		t.Fatal("waitFor(missing, timeout) = nil, want error")
	}
}

func TestCmdOneShot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute(non-empty file) = %v, want nil", err)
	}
}

func TestCmdOneShotFailsOnMissingFile(t *testing.T) {
	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{filepath.Join(t.TempDir(), "missing.pem")})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute(missing) = nil, want error")
	}
}

func TestCmdWaitTimesOut(t *testing.T) {
	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--wait",
		"--poll-interval", "10ms",
		"--timeout", "50ms",
		filepath.Join(t.TempDir(), "never.pem"),
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute(--wait, missing, timeout) = nil, want error")
	}
}
