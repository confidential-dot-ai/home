//go:build linux

// Package rtmr3measurer is the in-VM workload measurer: it binds *which*
// container a kata-qemu-tdx sandbox runs into the guest's attestation by
// extending TDX RTMR[3] with the deployed image digest — dynamically, for any
// image, with no baked allowlist.
//
// It is the measurement counterpart to policy-monitor (which enforces a baked
// allowlist), and deliberately a SEPARATE component so the allowlist use case
// stays untouched — a node can run either or both. kata-agent writes
// /run/kata-containers/<cid>/config.json before it forks the container's init;
// we read the digest from io.kubernetes.cri.image-name there and extend
// RTMR[3]. As a baked systemd daemon (not a guest hook) it runs fine under the
// locked agent policy.
//
// Requires a guest kernel that exposes the TDX RTMR-extend sysfs
// (/sys/devices/virtual/misc/tdx_guest/measurements/, mainline >= 6.16).
//
// Extend convention (MUST match `tdx-measure rtmr3-from-images` and the
// rtmr3-hook): event = SHA384("sha256:"+hex); RTMR[3] = extend(RTMR3, event).
// RTMR[3] is hardware-append-only and the measurer is part of the dm-verity
// root, so a workload can neither forge nor suppress its own measurement.
package rtmr3measurer

import (
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	watchDir   = "/run/kata-containers"
	rtmr3Sysfs = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"
)

// Kata names each container directory by its 64-hex container id; the
// "shared"/"sandbox"/"image" entries never match and are ignored.
var (
	cidRe   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	hex64Re = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// seen records cids already acted on so each extends RTMR[3] exactly once.
// Accessed only from the single Run() scan loop, so no lock is needed.
var seen = map[string]struct{}{}

type ociSpec struct {
	Annotations map[string]string `json:"annotations"`
}

// Run is the cobra-driven entry point (mirrors policymonitor.Run's shape).
func Run(_ []string) error {
	logger := slog.Default()
	logger.Info("rtmr3-measurer starting", "watch_dir", watchDir, "sysfs", rtmr3Sysfs)

	// Poll, don't inotify. kata-agent sets up /run/kata-containers as its own
	// mount after this daemon starts at boot; an inotify watch added early binds
	// the pre-mount inode and never sees the <cid> dirs created on the mounted
	// fs. A 1s scan is immune to that (and to dropped events); `seen` makes each
	// cid extend RTMR[3] exactly once — mandatory, since the register is
	// append-only and a double-extend would corrupt it.
	for {
		if entries, err := os.ReadDir(watchDir); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					handle(logger, filepath.Join(watchDir, e.Name()))
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func handle(logger *slog.Logger, dir string) {
	cid := filepath.Base(dir)
	if !cidRe.MatchString(cid) {
		return // "shared"/"sandbox"/"image" and other non-container entries
	}
	if _, done := seen[cid]; done {
		return
	}
	spec, err := readConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		return // config.json not written yet; retry next scan (do NOT mark seen)
	}
	seen[cid] = struct{}{} // definitive outcome from here — act once

	// Skip the pause/sandbox container — it's the measured rootfs, not a
	// workload, and carries no image-name annotation.
	if spec.Annotations["io.kubernetes.cri.container-type"] == "sandbox" {
		return
	}
	digest, ok := extractDigest(spec.Annotations)
	if !ok {
		// Measure-only: unlike policy-monitor we do not kill; an unpinned image
		// simply isn't reflected in RTMR[3], so its quote won't match any
		// expected digest and a relying party rejects it there.
		logger.Warn("no image digest annotation; not measurable (pin the image by digest)", "cid", cid)
		return
	}
	if err := extendRTMR3(digest); err != nil {
		logger.Error("extend RTMR[3] failed", "cid", cid, "digest", digest, "error", err)
		return
	}
	logger.Info("measured workload into RTMR[3]", "cid", cid, "digest", digest)
}

// readConfig reads config.json with a short retry, since a scan can catch the
// <cid> dir a moment before kata-agent has written the file.
func readConfig(path string) (*ociSpec, error) {
	deadline := time.Now().Add(2 * time.Second)
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
		time.Sleep(50 * time.Millisecond)
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

// extendRTMR3 extends RTMR[3] with SHA384(canonical digest). The kernel TSM
// sysfs write performs TDG.MR.RTMR.EXTEND: RTMR3 = SHA384(RTMR3 ‖ event).
func extendRTMR3(canonicalDigest string) error {
	event := sha512.Sum384([]byte(canonicalDigest))
	if err := os.WriteFile(rtmr3Sysfs, event[:], 0); err != nil {
		return fmt.Errorf("write %s: %w", rtmr3Sysfs, err)
	}
	return nil
}
