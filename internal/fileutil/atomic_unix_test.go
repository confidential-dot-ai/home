//go:build unix

package fileutil

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteAtomicWriteFailureCleansUpTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	// Drop the process file-size limit to zero so the tmp.Write fails with
	// EFBIG, exercising the write error path and tmp cleanup. SIGXFSZ must
	// be ignored or the kernel would kill the process instead of returning
	// the error from write(2).
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	if old.Cur == 0 {
		t.Skip("RLIMIT_FSIZE already zero")
	}
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	zero := syscall.Rlimit{Cur: 0, Max: old.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &zero); err != nil {
		t.Skipf("setrlimit not permitted: %v", err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
			t.Fatalf("restore rlimit: %v", err)
		}
	}()

	if err := WriteAtomic(path, []byte("x"), 0o644); err == nil {
		t.Fatal("expected write error with RLIMIT_FSIZE=0")
	}

	// Restore before reading the directory back.
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatalf("restore rlimit: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("temp file not cleaned up, dir contains: %v", entries)
	}
}
