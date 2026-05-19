// Package fileutil holds small filesystem helpers shared across c8s commands.
package fileutil

import (
	"os"
	"path/filepath"
)

// WriteAtomic writes data to path via a same-directory temp file plus
// os.Rename. The Chmod is performed on the temp file before the rename so
// the destination never appears with the wrong permissions. The temp file
// is cleaned up on any error path.
//
// Same-directory tmpfile is required for os.Rename to be a true atomic
// replace on POSIX filesystems; a /tmp tmp would silently degrade to a
// copy+remove on cross-mount writes.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
