//go:build linux

package policymonitor

// Inotify watch + per-container decision logic.
//
// Topology: kata-agent writes /run/kata-containers/<cid>/config.json
// during do_create_container (rpc.rs:296 in kata-containers 3.30.0),
// before it forks the container's init. We watch the parent directory
// with IN_CREATE and parse config.json as soon as a new child appears.
//
// Order-of-events caveat
//
// inotify on a directory fires IN_CREATE when the new entry appears,
// not when its contents are settled. setup_bundle() in rpc.rs makes
// the child dir, writes config.json, then bind-mounts rootfs/. We
// retry the config.json read a few times with a short backoff to
// absorb the gap; in practice config.json appears within
// single-digit ms.
//
// We use filepath.Walk on startup to seed the watcher with any
// directories already present (e.g. policy-monitor restarted by
// systemd while containers were already up).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// runMonitor is the long-running entry. It's package-private rather
// than exported because the only caller is the cobra subcommand in
// run.go; tests drive it indirectly through the helpers it composes
// (loadAllowlist, evaluateContainer, killer interfaces).
func runMonitor(ctx context.Context, cfg *Config) error {
	logger, err := certutil.NewJSONLogger(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("log level: %w", err)
	}

	logger.Info("starting policy-monitor",
		"allowlist", cfg.AllowlistPath,
		"watch_dir", cfg.WatchDir,
		"cgroup_root", cfg.CgroupRoot,
	)

	a, warnings, err := loadAllowlist(cfg.AllowlistPath)
	if err != nil {
		return fmt.Errorf("load allowlist: %w", err)
	}
	for _, w := range warnings {
		logger.Warn("allowlist warning", "warning", w.Error())
	}
	logger.Info("allowlist loaded", "entries", a.Size())

	if err := os.MkdirAll(cfg.WatchDir, 0o755); err != nil {
		return fmt.Errorf("create watch dir %s: %w", cfg.WatchDir, err)
	}

	m := &monitor{
		cfg:        cfg,
		logger:     logger,
		allowlist:  a,
		killer:     signalSender{},
		pidLocator: newCgroupLocator(cfg.CgroupRoot),
		// configReadDeadline is the budget for re-reading config.json
		// after the initial CREATE event. kata-agent's setup_bundle
		// finishes well under this; the limit is just to bound a
		// pathological case.
		configReadDeadline: 2 * time.Second,
		configReadInterval: 25 * time.Millisecond,
	}

	// Hybrid refresh: when a CDS URL is configured (via the cloud-init
	// env the systemd unit loads), keep the allowlist current with CDS
	// additions on top of the baked seed. The goroutine shares the
	// *allowlist with m, whose merge is mutex-guarded. No CDS URL →
	// baked-seed-only and the network is never touched.
	if cfg.CDSURL != "" {
		go runAllowlistRefresh(ctx, logger, cfg, a)
	} else {
		logger.Info("allowlist refresh disabled (no CDS URL); enforcing baked seed only", "entries", a.Size())
	}

	return m.run(ctx)
}

// monitor encapsulates the runtime state. Exposed via dependency
// injection (killer + pidLocator) so the test suite can drive
// decisions against a tempdir without touching /sys/fs/cgroup or
// real PIDs.
type monitor struct {
	cfg                *Config
	logger             *slog.Logger
	allowlist          *allowlist
	killer             killer
	pidLocator         pidLocator
	configReadDeadline time.Duration
	configReadInterval time.Duration
}

func (m *monitor) run(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create inotify watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(m.cfg.WatchDir); err != nil {
		return fmt.Errorf("watch %s: %w", m.cfg.WatchDir, err)
	}

	// Seed: process directories that already exist. Important when
	// policy-monitor was restarted by systemd while containers were
	// running — we shouldn't grandfather them in just because we
	// missed their CREATE event. The fact that they're still around
	// means kata-agent considers them live, so we should make a
	// decision on each.
	if err := m.seedExisting(); err != nil {
		// Non-fatal: if we can't walk for some reason (permission,
		// transient FS error), log and keep going. New containers
		// from this point on are still observed via inotify.
		m.logger.Warn("seed existing containers failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("policy-monitor stopping", "reason", ctx.Err())
			return nil

		case evt, ok := <-watcher.Events:
			if !ok {
				return errors.New("watcher events channel closed")
			}
			// We only care about new entries appearing under the
			// watched directory. IN_CREATE covers both dirs and
			// files — we accept either and let pathLooksLikeContainer
			// filter the side artifacts (cleanup work files,
			// kata-agent's "shared" subdir).
			if !evt.Op.Has(fsnotify.Create) {
				continue
			}
			if !m.pathLooksLikeContainer(evt.Name) {
				m.logger.Debug("ignoring non-container path", "path", evt.Name)
				continue
			}
			// We don't gate kata-agent — process the event in a
			// goroutine so a slow read on one container doesn't
			// throttle our reaction time on another. The goroutine
			// is bounded by the context.
			go m.handleNewContainer(ctx, evt.Name)

		case err, ok := <-watcher.Errors:
			if !ok {
				return errors.New("watcher errors channel closed")
			}
			// Fail closed on queue overflow. IN_Q_OVERFLOW means the
			// kernel dropped CREATE events we never saw, so a container
			// that landed during the burst would otherwise run with no
			// decision made. Re-run the seed pass to re-scan the watch
			// dir and make a decision for everything currently present
			// (idempotent — see seedExisting). If the rescan itself
			// fails we exit non-zero and let systemd restart + reseed
			// rather than continue half-blind.
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				m.logger.Warn("inotify queue overflow; rescanning watch dir to recover dropped events")
				if serr := m.seedExisting(); serr != nil {
					return fmt.Errorf("rescan after inotify overflow: %w", serr)
				}
				continue
			}
			m.logger.Warn("inotify error", "error", err)
		}
	}
}

// seedExisting walks the watch dir at startup and dispatches a
// decision for every child directory present. Idempotent — kata-agent
// keeps the bundle around until the container is removed, and we make
// a fresh decision either way (allowlisted = nothing happens; denied
// = kill, but the kill is a no-op if the init has already exited).
func (m *monitor) seedExisting() error {
	entries, err := os.ReadDir(m.cfg.WatchDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		full := filepath.Join(m.cfg.WatchDir, e.Name())
		if !m.pathLooksLikeContainer(full) {
			continue
		}
		// Note: we pass context.Background here intentionally — the
		// seed pass is part of startup, not the main event loop, and
		// we want it to complete before we start handling new events.
		// Time bound is the per-decision configReadDeadline already
		// enforced in handleNewContainer.
		m.handleNewContainer(context.Background(), full)
	}
	return nil
}

// pathLooksLikeContainer applies a coarse filter: the path must be a
// direct child of WatchDir whose basename matches the kata
// verify_id() regex (alphanum + dash, 1-128 chars; this is what
// kata_sys_util::validate::verify_id accepts in upstream
// kata-containers 3.30.0). Anything else is a sibling artifact
// (e.g. /run/kata-containers/shared) and we ignore it.
func (m *monitor) pathLooksLikeContainer(path string) bool {
	rel, err := filepath.Rel(m.cfg.WatchDir, path)
	if err != nil {
		return false
	}
	if strings.ContainsAny(rel, string(os.PathSeparator)) {
		return false
	}
	if rel == "." || rel == "" {
		return false
	}
	return containerIDRe.MatchString(rel)
}

// containerIDRe mirrors kata_sys_util::validate::verify_id. We're
// deliberately a touch tighter than upstream (no dots, no
// underscores) to avoid matching obvious non-container entries like
// "shared" or "sandbox.sock"; the kata container ids we see in
// practice are all hex-or-base32 strings well within this set.
var containerIDRe = regexp.MustCompile(`^[a-zA-Z0-9-]{1,128}$`)

// handleNewContainer runs the full decision for one container
// directory. Synchronous from the caller's POV; the caller wraps it
// in a goroutine.
func (m *monitor) handleNewContainer(ctx context.Context, dir string) {
	cid := filepath.Base(dir)
	configPath := filepath.Join(dir, "config.json")

	spec, err := m.readConfigJSON(ctx, configPath)
	if err != nil {
		// "Not yet present" is the common case if the CREATE was for
		// the directory and config.json hasn't been written yet —
		// readConfigJSON already retries up to configReadDeadline.
		// Anything that reaches here is a real failure (parse error,
		// permission, missing-for-too-long).
		m.logger.Warn("read config.json failed", "cid", cid, "path", configPath, "error", err)
		return
	}

	// The pod sandbox (pause) container is out of allowlist scope. In
	// guest-pull mode (which c8s forces) kata-agent runs the pause baked
	// into the dm-verity rootfs for any container it deems a sandbox (see
	// isSandbox), so the sandbox's integrity comes from the launch
	// measurement, not a digest on the allowlist — and the host can't
	// substitute it. Skip it, identified exactly the way kata does so a
	// mislabelled workload can't slip through (kata would run the measured
	// pause for it, not the host's image). Checked before extractDigest
	// because the pause carries no image-name annotation.
	if isSandbox(spec.Annotations) {
		m.logger.Info("allow sandbox (pause) container — measured via rootfs, not allowlisted", "cid", cid)
		return
	}

	digest, ok := extractDigest(spec.Annotations)
	if !ok {
		// A non-sandbox container with no digest annotation we recognise
		// (the sandbox/pause container is handled above): a hand-crafted
		// bundle, or an attacker who stripped the annotation to evade the
		// policy. Threat-model decision: deny (fail closed) — stripping
		// the annotation must not buy a free pass. The cost is that an
		// operator who side-loads a bundle without CRI annotations must
		// put its digest on the allowlist or accept the kill.
		m.logger.Warn("deny container: no image digest annotation found", "cid", cid)
		m.kill(cid)
		return
	}

	if m.allowlist.Contains(digest) {
		m.logger.Info("allow container", "cid", cid, "digest", digest)
		return
	}
	m.logger.Warn("deny container: digest not allowlisted", "cid", cid, "digest", digest)
	m.kill(cid)
}

// kill resolves the container's init PID via its cgroup and sends
// SIGKILL. Best-effort: if the init has already exited, or its
// cgroup hasn't materialised yet, we log and move on (the worst-case
// is that an unallowlisted container ran for the duration of the
// kata-agent CreateContainer call before kata-agent's own cleanup
// reaps it — same as the inherent post-start window).
func (m *monitor) kill(cid string) {
	pid, ok, err := m.pidLocator.findInitPID(cid)
	if err != nil {
		m.logger.Warn("locate init pid failed", "cid", cid, "error", err)
		return
	}
	if !ok {
		m.logger.Warn("init pid not found", "cid", cid)
		return
	}
	if err := m.killer.kill(pid, syscall.SIGKILL); err != nil {
		// ESRCH = process already gone. Not an error from our POV;
		// the only goal was "this PID is dead", and it is.
		if errors.Is(err, syscall.ESRCH) {
			m.logger.Info("init already exited", "cid", cid, "pid", pid)
			return
		}
		m.logger.Warn("SIGKILL failed", "cid", cid, "pid", pid, "error", err)
		return
	}
	m.logger.Info("SIGKILLed container init", "cid", cid, "pid", pid)
}

// readConfigJSON retries reading + parsing config.json for the budget
// configReadDeadline. The retry absorbs the small gap between
// directory creation (which triggers our IN_CREATE event) and
// kata-agent finishing the config.json write.
func (m *monitor) readConfigJSON(ctx context.Context, path string) (*ociSpec, error) {
	deadline := time.Now().Add(m.configReadDeadline)
	var lastErr error
	for {
		spec, err := readOCISpec(path)
		if err == nil {
			return spec, nil
		}
		lastErr = err
		if !errors.Is(err, os.ErrNotExist) && !isPartialJSON(err) {
			// Unrecoverable: not a transient race. Return immediately.
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.configReadInterval):
		}
	}
}

// ociSpec is the subset of the OCI Runtime Spec we care about: the
// annotations map. We don't pull in opencontainers/runtime-spec
// because we only need this one field, and json.Unmarshal will
// silently drop everything else.
type ociSpec struct {
	Annotations map[string]string `json:"annotations"`
}

func readOCISpec(path string) (*ociSpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		// Half-written: kata-agent created the file but hasn't
		// finished writing. Surface a sentinel so the caller knows
		// to retry.
		return nil, errPartialJSON
	}
	var s ociSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		// A SyntaxError on an in-progress write is also a transient
		// state. We don't try to disambiguate (the alternative is to
		// fstat for stable size, which is fragile); we just retry on
		// any unmarshal error too. The outer loop bounds the retry.
		return nil, fmt.Errorf("%w: %v", errPartialJSON, err)
	}
	return &s, nil
}

// errPartialJSON is the sentinel that tells the read loop to retry.
// Wrapped via fmt.Errorf so callers can use errors.Is.
var errPartialJSON = errors.New("partial json")

func isPartialJSON(err error) bool {
	return errors.Is(err, errPartialJSON)
}
