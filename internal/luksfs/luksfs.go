// Package luksfs is the single allowlist of filesystems c8s will create inside a
// LUKS mapper. Grow it only alongside the mkfs tooling installed in
// cmd/luks-open/Dockerfile.
package luksfs

// Allowed reports whether fstype is one c8s may mkfs and mount.
func Allowed(fstype string) bool {
	switch fstype {
	case "ext4", "xfs":
		return true
	}
	return false
}
