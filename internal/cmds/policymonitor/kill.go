//go:build linux

package policymonitor

// Container cgroup discovery + termination.
//
// kata-agent does not write a state.json or a pid file for the
// container's init process — the PID lives in the in-memory
// LinuxContainer.init_process_pid field
// (src/agent/rustjail/src/container.rs:1182 in kata-containers 3.30.0).
// The only external observation channel is the container's cgroup.
//
// On systemd-managed kata guests the cgroup hierarchy is v2 unified
// (systemd >= 232 enables it by default; the upstream kata-agent and
// runc work in this mode when systemd is PID 1, which is our case).
// Each container created by kata-agent ends up with its own cgroup
// directory under /sys/fs/cgroup. We wait for the cgroup to become
// populated, then terminate the cgroup as a unit. Selecting a PID from
// cgroup.procs is incorrect: the kernel does not order that file, and a
// PID can be recycled between the read and a signal syscall.
//
// We walk the hierarchy to find the subdirectory that identifies the
// container, because kata-agent's cgroup naming depends on the guest's
// cgroup driver:
//   - fs driver:      a flat /sys/fs/cgroup/<cid>, or a sandbox-then-
//                     container nesting like /sys/fs/cgroup/kata_<sandbox>/<cid>
//   - systemd driver: a systemd scope, cri-containerd-<cid>.scope (containerd)
//                     or crio-<cid>.scope (CRI-O), nested under the pod's
//                     kubepods*.slice — this is what a systemd-PID-1 kata
//                     guest actually uses, so it is the common case in the
//                     field. Matching only the bare <cid> basename here was a
//                     silent enforcement hole: policy-monitor denied a
//                     non-allowlisted container but then could not find its
//                     cgroup, so the SIGKILL never landed and the container
//                     ran. cgroupDirMatchesCID recognises both shapes.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// containerKiller is the dependency-injection surface used by the monitor.
// The boolean is false when the container has already exited or its cgroup
// never materialised within the configured budget.
type containerKiller interface {
	kill(containerID string) (bool, error)
}

// cgroupKiller searches the configured cgroup root and terminates the
// matching cgroup as a unit by writing the kernel's cgroup.kill interface.
type cgroupKiller struct {
	cgroupRoot string
	// waitTimeout caps how long we re-scan for the cgroup directory
	// before giving up. kata-agent creates the cgroup and forks the
	// init in quick succession after writing config.json, but
	// fsnotify's CREATE event for config.json may fire before the
	// cgroup is materialised. waitTimeout absorbs that race.
	waitTimeout time.Duration
	// pollInterval is how often we re-walk the hierarchy during the
	// wait. 50ms is short enough that we don't add measurable latency
	// to the kill path on hardware.
	pollInterval time.Duration
}

var _ containerKiller = (*cgroupKiller)(nil)

func newCgroupKiller(root string) *cgroupKiller {
	return &cgroupKiller{
		cgroupRoot:   root,
		waitTimeout:  2 * time.Second,
		pollInterval: 50 * time.Millisecond,
	}
}

func (c *cgroupKiller) kill(containerID string) (bool, error) {
	deadline := time.Now().Add(c.waitTimeout)
	for {
		dir, err := findCgroupDir(c.cgroupRoot, containerID)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("walk cgroup hierarchy: %w", err)
		}
		if dir != "" {
			group, err := filepath.Rel(c.cgroupRoot, dir)
			if err != nil {
				return false, fmt.Errorf("resolve cgroup path: %w", err)
			}
			// Include descendants: cgroup.kill terminates the entire subtree,
			// so a child cgroup must also make the group eligible for killing.
			procs, err := readCgroupProcs(c.cgroupRoot, group)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return false, fmt.Errorf("read cgroup processes: %w", err)
				}
			} else if len(procs) > 0 {
				if err := writeCgroupKill(dir); err != nil {
					return false, fmt.Errorf("kill cgroup: %w", err)
				}
				return true, nil
			}
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(c.pollInterval)
	}
}

func readCgroupProcs(root, group string) ([]string, error) {
	var procs []string
	err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(group)), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "cgroup.procs" {
			return nil
		}
		entries, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, proc := range strings.Fields(string(entries)) {
			if _, err := strconv.ParseUint(proc, 10, 64); err != nil {
				return fmt.Errorf("parse pid %q: %w", proc, err)
			}
			procs = append(procs, proc)
		}
		return nil
	})
	return procs, err
}

func writeCgroupKill(dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, "cgroup.kill"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, writeErr := io.WriteString(f, "1")
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	return closeErr
}

// findCgroupDir walks root looking for a directory that identifies
// containerID (see cgroupDirMatchesCID for the naming schemes). Returns
// the first match (depth-first) or an empty string. We don't bother with
// finer disambiguation — the kata container id is a 64-hex-char SHA-256
// (or similar high-entropy string) and collisions in the cgroup tree are
// not credible.
//
// Implementation note: we use filepath.WalkDir rather than recursing
// manually because the cgroup v2 hierarchy can be arbitrarily deep
// when nested inside systemd slices (e.g. /sys/fs/cgroup/
// system.slice/kata-shim-<sandbox>.scope/<cid>/), and WalkDir handles
// the symlink and permission edge cases consistently.
func findCgroupDir(root, containerID string) (string, error) {
	if containerID == "" {
		return "", errors.New("empty container id")
	}
	var found string
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Permission-denied on a sibling slice (an unreadable systemd
			// slice we don't own) is expected during a full-tree walk and
			// must not stop the search — skip it and keep going. Worst
			// case we miss the cgroup and the kill is a no-op, which is
			// fine for a denied container (kata-agent reaps it when
			// CreateContainer returns). But do NOT swallow *every* error:
			// anything else (an I/O error, a broken/zombie cgroup) is a
			// real signal, so propagate it. cgroupKiller returns it as
			// "walk cgroup hierarchy: ..." and the monitor logs it at
			// Warn — rather than silently continuing and reporting a
			// misleading no-op kill for a container we never searched.
			if errors.Is(err, os.ErrPermission) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if cgroupDirMatchesCID(d.Name(), containerID) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil {
		return "", walkErr
	}
	return found, nil
}

// cgroupDirMatchesCID reports whether a cgroup directory basename identifies
// containerID, across the cgroup-driver naming schemes kata-agent produces:
//   - flat / nested fs driver:  <cid>
//   - systemd scope:            cri-containerd-<cid>.scope, crio-<cid>.scope,
//     or <cid>.scope
//
// containerID is a 64-hex (or similarly high-entropy) kata container id, so a
// suffix match cannot credibly collide with an unrelated cgroup — the same
// argument findCgroupDir already relies on for the exact-match case.
func cgroupDirMatchesCID(basename, containerID string) bool {
	name := strings.TrimSuffix(basename, ".scope")
	return name == containerID || strings.HasSuffix(name, "-"+containerID)
}
