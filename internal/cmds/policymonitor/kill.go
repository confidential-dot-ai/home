//go:build linux

package policymonitor

// Container init PID discovery + SIGKILL.
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
// directory under /sys/fs/cgroup; the directory's `cgroup.procs` file
// lists every PID in the cgroup, one per line, lowest PID first.
//
// The init process is, by construction, the first process in the
// cgroup (kata-agent creates the cgroup, then forks the init into it
// before any exec setup; later children inherit the cgroup but get
// higher PIDs because they're descendants of init). So `head -1
// cgroup.procs` is the init PID.
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
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// killer is the dependency-injection surface the monitor uses to send
// signals. Real production: signalSender{} which wraps syscall.Kill.
// Tests: a fake that records its arguments.
type killer interface {
	kill(pid int, signal os.Signal) error
}

type signalSender struct{}

var _ killer = signalSender{}

func (signalSender) kill(pid int, sig os.Signal) error {
	if pid <= 1 {
		// Guard against killing init / a wrap-around. kata-agent never
		// allocates PID 1 (that's systemd inside the guest) or PID 0
		// (kernel) for a container; treat as a programming error.
		return fmt.Errorf("refusing to signal pid %d", pid)
	}
	s, ok := sig.(syscall.Signal)
	if !ok {
		return fmt.Errorf("unsupported signal type %T", sig)
	}
	return syscall.Kill(pid, s)
}

// pidLocator finds the init PID for a container. Like killer, it's an
// interface so tests can substitute a tempdir-rooted fake without
// having to fabricate a /sys/fs/cgroup hierarchy.
type pidLocator interface {
	// findInitPID returns the init PID for containerID. The boolean is
	// false if the container's cgroup couldn't be located in the
	// configured time budget — the monitor logs and skips, because a
	// container whose cgroup we can't find has probably already exited
	// (the desirable outcome anyway).
	findInitPID(containerID string) (int, bool, error)
}

// cgroupLocator is the production implementation. It searches the
// configured cgroup root for a directory whose basename equals the
// container id, then reads cgroup.procs.
type cgroupLocator struct {
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

var _ pidLocator = (*cgroupLocator)(nil)

func newCgroupLocator(root string) *cgroupLocator {
	return &cgroupLocator{
		cgroupRoot:   root,
		waitTimeout:  2 * time.Second,
		pollInterval: 50 * time.Millisecond,
	}
}

func (c *cgroupLocator) findInitPID(containerID string) (int, bool, error) {
	deadline := time.Now().Add(c.waitTimeout)
	for {
		dir, err := findCgroupDir(c.cgroupRoot, containerID)
		switch {
		case err == nil && dir != "":
			pid, err := readFirstPID(filepath.Join(dir, "cgroup.procs"))
			if err == nil {
				return pid, true, nil
			}
			// cgroup.procs exists but is empty (container init forked
			// then exited already) or unreadable. Treat as "not found"
			// — the kill path is a no-op in either case.
			return 0, false, nil
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return 0, false, fmt.Errorf("walk cgroup hierarchy: %w", err)
		}
		if time.Now().After(deadline) {
			return 0, false, nil
		}
		time.Sleep(c.pollInterval)
	}
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
			// real signal, so propagate it. findInitPID returns it as
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

// readFirstPID reads the first line of path and returns it as an int.
// The cgroup.procs format is one PID per line; we want the lowest,
// which is the file's first line on every kernel that produces sorted
// output (Linux >= 3.16 always sorts cgroup.procs; we don't care to
// support older kernels because kata SEV-SNP requires a much newer
// kernel anyway).
func readFirstPID(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return 0, err
		}
		return 0, errors.New("cgroup.procs is empty")
	}
	line := strings.TrimSpace(scanner.Text())
	pid, err := strconv.Atoi(line)
	if err != nil {
		return 0, fmt.Errorf("parse pid %q: %w", line, err)
	}
	return pid, nil
}
