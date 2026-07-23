package luksclose

import (
	"os"
	"strings"
	"testing"
)

func TestRunRequiresVolumes(t *testing.T) {
	if err := Run(Config{}); err == nil || !strings.Contains(err.Error(), "no --volume") {
		t.Fatalf("Run with no volumes = %v, want 'no --volume' error", err)
	}
}

func TestCloseOneNoOpOnMissingMount(t *testing.T) {
	// The mount branch is the one we can drive without root or dm — an unmounted
	// path returns nil from unmountIfMounted, so closeOne then reaches devmapper
	// which needs /dev/mapper/control. Test hosts without that device (this
	// devcontainer) exercise the unmount branch only; a node has both.
	if _, err := os.Stat("/dev/mapper/control"); os.IsNotExist(err) {
		t.Skip("skip: /dev/mapper/control absent (not a node with device-mapper)")
	}
	cfg := Config{MountRoot: "/tmp/c8s-luksclose-test-does-not-exist", Names: []string{"absent"}}
	if err := closeOne(cfg, "absent"); err != nil {
		t.Fatalf("closeOne(missing mount + missing mapper) = %v, want nil (idempotent)", err)
	}
}

func TestUnmountIfMountedNoOpOnUnmountedPath(t *testing.T) {
	// The isolated unmount branch — testable everywhere. An unmounted path is a
	// no-op (nil), matching the "already closed" idempotent contract.
	if err := unmountIfMounted("/tmp/c8s-luksclose-test-really-not-mounted"); err != nil {
		t.Fatalf("unmountIfMounted(unmounted) = %v, want nil", err)
	}
}
