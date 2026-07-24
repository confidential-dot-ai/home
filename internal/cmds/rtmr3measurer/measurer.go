//go:build linux

// Package rtmr3measurer is the in-VM workload measurer: it scans kata-agent's
// container bundles under /run/kata-containers and extends TDX RTMR[3] with
// each deployed workload's image digest, binding WHICH container ran into the
// guest's attestation — dynamically, for any image, with no baked allowlist.
// It is the measurement-only counterpart to policy-monitor (allowlist
// enforcement); either or both may run.
//
// The extend convention is pinned by pkg/rtmr3 — verifiers MUST build on that
// package. Each distinct image is extended exactly once; the dedup log is
// persisted to tmpfs so a daemon restart cannot re-extend the append-only
// register. Design and rationale: docs/kata-guest-base.md
// "Per-workload RTMR[3] measurement".
package rtmr3measurer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/rtmr3"
)

// rtmr3Sysfs is the kernel TSM node backing extendSysfs/readRegisterSysfs.
// A var (not const) only so tests can point it at a temp file.
var rtmr3Sysfs = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"

const (
	watchDir = "/run/kata-containers"
	// statePath is the measured-digest log. /run is tmpfs: it survives a
	// process restart and is wiped with the VM — the same lifetime as
	// RTMR[3] itself. The /run/c8s dir is created by tmpfiles.d/c8s.conf.
	statePath = "/run/c8s/rtmr3-measured"

	scanInterval     = 1 * time.Second
	readDirWarnEvery = 60 // scans between repeated cannot-read-watch-dir warns
)

// Kata names each container directory by its 64-hex container id ("shared"/
// "sandbox"/"image" never match); the same pattern validates sha256 hex.
var hex64Re = regexp.MustCompile(`^[a-f0-9]{64}$`)

type ociSpec struct {
	Annotations map[string]string `json:"annotations"`
}

// measurer holds the scan state. All fields are touched only from the single
// run loop (no lock).
type measurer struct {
	logger    *slog.Logger
	watchDir  string
	statePath string

	extend       func(event [rtmr3.Size]byte) error // TDX sysfs write
	readRegister func() ([rtmr3.Size]byte, error)   // TDX sysfs read

	// seenCids: cids already decided, so config.json isn't re-read every
	// scan; pruned as container dirs disappear. measuredDigests is the
	// correctness-critical dedup — digests already extended, keyed on digest
	// (not cid) so restarts/replicas of one image extend exactly once — and
	// mirrors the statePath log (measuredOrder is its line order).
	seenCids        map[string]struct{}
	measuredDigests map[string]struct{}
	measuredOrder   []string

	configReadDeadline time.Duration
	configReadInterval time.Duration
	readDirFails       int
}

func newMeasurer(logger *slog.Logger) *measurer {
	return &measurer{
		logger:             logger,
		watchDir:           watchDir,
		statePath:          statePath,
		extend:             extendSysfs,
		readRegister:       readRegisterSysfs,
		seenCids:           map[string]struct{}{},
		measuredDigests:    map[string]struct{}{},
		configReadDeadline: 2 * time.Second,
		configReadInterval: 50 * time.Millisecond,
	}
}

// Run is the cobra-driven entry point (mirrors policymonitor.Run's shape).
func Run(_ []string) error {
	m := newMeasurer(slog.Default())
	m.logger.Info("rtmr3-measurer starting",
		"watch_dir", m.watchDir, "state", m.statePath, "sysfs", rtmr3Sysfs)
	if err := m.loadState(); err != nil {
		return err
	}
	// Poll, don't inotify: kata-agent mounts /run/kata-containers after this
	// daemon starts, so an early inotify watch binds the pre-mount inode and
	// never fires. See docs/kata-guest-base.md — rtmr3-measurer.
	for {
		m.scanOnce()
		time.Sleep(scanInterval)
	}
}

// loadState reloads the measured-digest log after a daemon restart (RTMR[3]
// keeps its extends; a fresh in-memory dedup would re-extend and corrupt it)
// and repairs the one legal divergence: a crash after record() but before the
// extend landed. The register is readable from the extend sysfs, so it
// arbitrates which of the two happened.
func (m *measurer) loadState() error {
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	b, err := os.ReadFile(m.statePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // first start this boot
	}
	if err != nil {
		return fmt.Errorf("read measured-digest log %s: %w", m.statePath, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "sha256:") || !hex64Re.MatchString(strings.TrimPrefix(line, "sha256:")) {
			m.logger.Warn("ignoring malformed measured-digest log line", "line", line)
			continue
		}
		if _, dup := m.measuredDigests[line]; dup {
			continue
		}
		m.measuredDigests[line] = struct{}{}
		m.measuredOrder = append(m.measuredOrder, line)
	}
	if len(m.measuredOrder) == 0 {
		return nil
	}
	m.logger.Info("restart: reloaded measured-digest log", "count", len(m.measuredOrder))

	reg, err := m.readRegister()
	if err != nil {
		m.logger.Warn("cannot read RTMR[3] to cross-check the reloaded log; keeping the log as dedup truth",
			"error", err)
		return nil
	}
	if reg == rtmr3.FromDigests(m.measuredOrder) {
		return nil // register and log agree — clean restart
	}
	last := m.measuredOrder[len(m.measuredOrder)-1]
	if reg == rtmr3.FromDigests(m.measuredOrder[:len(m.measuredOrder)-1]) {
		// Crashed between record and extend: finish the recorded extend.
		if err := m.extend(rtmr3.Event(last)); err != nil {
			return fmt.Errorf("repair extend of recorded digest %s: %w", last, err)
		}
		m.logger.Info("repaired interrupted measurement", "digest", last)
		return nil
	}
	// Matches neither fold: something else extended RTMR[3]. Never re-extend
	// recorded digests — an extra extend is unrecoverable — just surface it.
	m.logger.Error("RTMR[3] does not match the measured-digest log; this VM's workload attestation will not verify")
	return nil
}

func (m *measurer) scanOnce() {
	entries, err := os.ReadDir(m.watchDir)
	if err != nil {
		// Throttled: a permanently unreadable watch dir must not spin silently.
		if m.readDirFails%readDirWarnEvery == 0 {
			m.logger.Warn("cannot read watch dir",
				"dir", m.watchDir, "error", err, "consecutive_failures", m.readDirFails+1)
		}
		m.readDirFails++
		return
	}
	m.readDirFails = 0
	present := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		present[e.Name()] = struct{}{}
		m.handle(filepath.Join(m.watchDir, e.Name()))
	}
	// Prune decided cids whose dirs are gone (container removed) so the map
	// cannot grow unbounded in a container-churning guest. Cids are never
	// reused; measuredDigests intentionally mirrors the register instead.
	for cid := range m.seenCids {
		if _, ok := present[cid]; !ok {
			delete(m.seenCids, cid)
		}
	}
}

func (m *measurer) handle(dir string) {
	cid := filepath.Base(dir)
	if !hex64Re.MatchString(cid) {
		return // "shared"/"sandbox"/"image" and other non-container entries
	}
	if _, done := m.seenCids[cid]; done {
		return
	}
	spec, err := m.readConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		return // config.json not written yet; retry next scan (do NOT mark seen)
	}
	m.seenCids[cid] = struct{}{} // decided this cid — don't re-read it every scan

	// The pause/sandbox container is the measured rootfs, not a workload,
	// and carries no image-name annotation.
	if spec.Annotations["io.kubernetes.cri.container-type"] == "sandbox" {
		return
	}
	digest, ok := extractDigest(spec.Annotations)
	if !ok {
		// Measure-only: unlike policy-monitor we do not kill; an unpinned
		// image simply isn't reflected in RTMR[3], so a relying party
		// rejects its quote there.
		m.logger.Warn("no image digest annotation; not measurable (pin the image by digest)", "cid", cid)
		return
	}
	if _, done := m.measuredDigests[digest]; done {
		m.logger.Info("image already measured into RTMR[3]; skipping duplicate (restart or replica)",
			"cid", cid, "digest", digest)
		return
	}
	m.measure(cid, digest)
}

// measure records the digest in the log, then extends. Record-first means a
// crash between the two can only UNDER-extend — repaired from the register
// readback at next start — never double-extend, which the append-only
// register cannot recover from.
func (m *measurer) measure(cid, digest string) {
	if err := m.record(digest); err != nil {
		m.logger.Error("record measured digest failed; not extending",
			"cid", cid, "digest", digest, "error", err)
		return
	}
	if err := m.extend(rtmr3.Event(digest)); err != nil {
		// Roll the log back so it keeps matching the register and a later
		// cid with this digest can retry.
		m.unrecordLast(digest)
		m.logger.Error("extend RTMR[3] failed", "cid", cid, "digest", digest, "error", err)
		return
	}
	m.measuredDigests[digest] = struct{}{}
	m.logger.Info("measured workload into RTMR[3]", "cid", cid, "digest", digest)
}

func (m *measurer) record(digest string) error {
	f, err := os.OpenFile(m.statePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(digest + "\n")
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	m.measuredOrder = append(m.measuredOrder, digest)
	return nil
}

// unrecordLast rewrites the log without the just-appended digest (atomic via
// rename; a crash mid-rewrite leaves the recorded-but-not-extended shape the
// startup repair resolves).
func (m *measurer) unrecordLast(digest string) {
	if n := len(m.measuredOrder); n > 0 && m.measuredOrder[n-1] == digest {
		m.measuredOrder = m.measuredOrder[:n-1]
	}
	var sb strings.Builder
	for _, d := range m.measuredOrder {
		sb.WriteString(d)
		sb.WriteByte('\n')
	}
	tmp := m.statePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err == nil {
		err = os.Rename(tmp, m.statePath)
		if err != nil {
			m.logger.Error("rewrite measured-digest log failed", "error", err)
		}
	} else {
		m.logger.Error("rewrite measured-digest log failed", "error", err)
	}
}

// readConfig reads config.json with a short retry, since a scan can catch the
// <cid> dir a moment before kata-agent has written the file.
func (m *measurer) readConfig(path string) (*ociSpec, error) {
	deadline := time.Now().Add(m.configReadDeadline)
	var lastErr error
	for {
		b, err := os.ReadFile(path)
		if err == nil {
			var s ociSpec
			if jerr := json.Unmarshal(b, &s); jerr == nil {
				return &s, nil
			} else {
				lastErr = jerr
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		time.Sleep(m.configReadInterval)
	}
}

// extractDigest mirrors policy-monitor: normalize `<ref>@sha256:<hex>` (or a
// bare `sha256:<hex>`) to canonical `sha256:<hex>`.
func extractDigest(ann map[string]string) (string, bool) {
	for _, key := range []string{
		"io.kubernetes.cri.image-name",
		"io.kubernetes.cri.image-id",
		"org.opencontainers.image.ref.name",
	} {
		v := ann[key]
		if v == "" {
			continue
		}
		if norm, err := normalizeDigest(v); err == nil {
			return "sha256:" + norm, true
		}
	}
	return "", false
}

func normalizeDigest(s string) (string, error) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "sha256:")
	if !hex64Re.MatchString(s) {
		return "", errors.New("not a sha256:<64hex> digest")
	}
	return s, nil
}

// extendSysfs performs TDG.MR.RTMR.EXTEND via the kernel TSM sysfs write:
// RTMR3 = SHA384(RTMR3 ‖ event). Needs mainline >= 6.16.
func extendSysfs(event [rtmr3.Size]byte) error {
	if err := os.WriteFile(rtmr3Sysfs, event[:], 0); err != nil {
		return fmt.Errorf("write %s: %w", rtmr3Sysfs, err)
	}
	return nil
}

// readRegisterSysfs reads the current RTMR[3] value from the same node.
func readRegisterSysfs() ([rtmr3.Size]byte, error) {
	var reg [rtmr3.Size]byte
	b, err := os.ReadFile(rtmr3Sysfs)
	if err != nil {
		return reg, err
	}
	if len(b) != rtmr3.Size {
		return reg, fmt.Errorf("read %s: got %d bytes, want %d", rtmr3Sysfs, len(b), rtmr3.Size)
	}
	copy(reg[:], b)
	return reg, nil
}
