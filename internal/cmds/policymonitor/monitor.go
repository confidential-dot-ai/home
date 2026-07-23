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
//
// Watch-generation caveat
//
// kata-agent's create_sandbox replaces the whole watch dir
// (remove_dir_all + create_dir_all on CONTAINER_BASE, rpc.rs), and an
// inotify watch binds to the inode, not the path — so a watch
// installed at guest boot dies silently at the first sandbox, before
// any workload bundle exists. run() therefore watches in generations:
// a Remove/Rename event for the watch dir itself (with a periodic
// inode revalidation as backstop for dropped events) ends the
// generation, and the next one re-creates the dir if needed, re-Adds,
// and re-runs the seed pass so bundles created in the gap still get a
// decision. See docs/pitfalls.md — "kata-agent replaces
// /run/kata-containers at sandbox creation".

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
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
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

	m := &monitor{
		cfg:       cfg,
		logger:    logger,
		allowlist: a,
		killer:    newCgroupKiller(cfg.CgroupRoot),
		// configReadDeadline is the budget for re-reading config.json
		// after the initial CREATE event. kata-agent's setup_bundle
		// finishes well under this; the limit is just to bound a
		// pathological case.
		configReadDeadline: 2 * time.Second,
		configReadInterval: 25 * time.Millisecond,
		revalidateInterval: 10 * time.Second,
	}

	// Workload-claims broker (docs/ratls.md): serve the guest
	// pod's admitted digests to the in-guest get-cert over a Unix socket the
	// guest bind-mounts into the pod.
	if cfg.WorkloadClaimsSocketDir != "" {
		m.broker = newWorkloadBroker()
		socketPath := filepath.Join(cfg.WorkloadClaimsSocketDir, workloadclaims.SocketName)
		if err := startWorkloadClaimsBroker(ctx, logger, m.broker, socketPath); err != nil {
			return fmt.Errorf("start workload-claims broker: %w", err)
		}
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
// injection (killer) so the test suite can drive
// decisions against a tempdir without touching /sys/fs/cgroup or
// real PIDs.
type monitor struct {
	cfg                *Config
	logger             *slog.Logger
	allowlist          *allowlist
	killer             containerKiller
	broker             *workloadBroker // serves the workload-claims flow (docs/ratls.md)
	configReadDeadline time.Duration
	configReadInterval time.Duration
	revalidateInterval time.Duration
}

func (m *monitor) run(ctx context.Context) error {
	for {
		done, err := m.watch(ctx)
		if done || err != nil {
			return err
		}
		// Watch generation invalidated: the watch dir was replaced
		// under us. Loop to re-establish; the next generation re-seeds,
		// so bundles created in the gap still get a decision.
	}
}

// watch runs one watch generation: create the dir if missing, install
// the inotify watch, seed, then serve events until the context ends
// (done=true), the watch dies in a way a fresh generation can fix
// (done=false, err=nil), or an unrecoverable error occurs.
func (m *monitor) watch(ctx context.Context) (done bool, err error) {
	if err := os.MkdirAll(m.cfg.WatchDir, 0o755); err != nil {
		return false, fmt.Errorf("create watch dir %s: %w", m.cfg.WatchDir, err)
	}

	// Record the watched inode's identity BEFORE Add: if kata-agent
	// swaps the dir between the two calls, SameFile below fails on the
	// first revalidation tick and we converge via one extra generation
	// — the reverse order could record the new inode while watching the
	// dead one, and never recover.
	watchedFI, err := os.Stat(m.cfg.WatchDir)
	if err != nil {
		return false, fmt.Errorf("stat watch dir %s: %w", m.cfg.WatchDir, err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return false, fmt.Errorf("create inotify watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(m.cfg.WatchDir); err != nil {
		return false, fmt.Errorf("watch %s: %w", m.cfg.WatchDir, err)
	}

	// Seed: process directories that already exist. Important when
	// policy-monitor was restarted by systemd while containers were
	// running, and on every re-watch after the dir was replaced — we
	// shouldn't grandfather containers in just because we missed their
	// CREATE event. The fact that they're still around means kata-agent
	// considers them live, so we should make a decision on each.
	if err := m.seedExisting(); err != nil {
		// Non-fatal: if we can't walk for some reason (permission,
		// transient FS error), log and keep going. New containers
		// from this point on are still observed via inotify.
		m.logger.Warn("seed existing containers failed", "error", err)
	}

	// Backstop for the event path below: if the Remove/Rename for the
	// watch dir itself is dropped (e.g. inside a queue overflow), a
	// periodic inode identity check still notices the swap.
	interval := m.revalidateInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	revalidate := time.NewTicker(interval)
	defer revalidate.Stop()

	watchDirGone := func(reason string) (bool, error) {
		m.logger.Warn("watch dir replaced; re-establishing watch and re-seeding",
			"watch_dir", m.cfg.WatchDir, "reason", reason)
		return false, nil
	}

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("policy-monitor stopping", "reason", ctx.Err())
			return true, nil

		case evt, ok := <-watcher.Events:
			if !ok {
				return false, errors.New("watcher events channel closed")
			}
			// kata-agent's create_sandbox does remove_dir_all +
			// create_dir_all on the watch dir; the Remove/Rename of the
			// dir itself is the generation's death notice (inotify
			// watches bind to the inode, so the recreated dir is
			// unwatched).
			if evt.Op.Has(fsnotify.Remove|fsnotify.Rename) && filepath.Clean(evt.Name) == filepath.Clean(m.cfg.WatchDir) {
				return watchDirGone("inotify " + evt.Op.String())
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
				return false, errors.New("watcher errors channel closed")
			}
			// Fail closed on queue overflow. IN_Q_OVERFLOW means the
			// kernel dropped CREATE events we never saw, so a container
			// that landed during the burst would otherwise run with no
			// decision made. Re-run the seed pass to re-scan the watch
			// dir and make a decision for everything currently present
			// (idempotent — see seedExisting). If the rescan itself
			// fails we exit non-zero and let systemd restart + reseed
			// rather than continue half-blind. The dropped events may
			// also include the watch dir's own Remove — check identity
			// too rather than wait for the next tick.
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				m.logger.Warn("inotify queue overflow; rescanning watch dir to recover dropped events")
				if serr := m.seedExisting(); serr != nil {
					return false, fmt.Errorf("rescan after inotify overflow: %w", serr)
				}
				if fi, serr := os.Stat(m.cfg.WatchDir); serr != nil || !os.SameFile(watchedFI, fi) {
					return watchDirGone("identity check after overflow")
				}
				continue
			}
			m.logger.Warn("inotify error", "error", err)

		case <-revalidate.C:
			if fi, serr := os.Stat(m.cfg.WatchDir); serr != nil || !os.SameFile(watchedFI, fi) {
				return watchDirGone("periodic identity check")
			}
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
		// A config.json that EXISTS but cannot be read or parsed (malformed
		// JSON, permission games, a directory in its place) means we cannot
		// determine the image digest for a container that clearly has a bundle.
		// Fail closed: deny (kill) rather than let it run unmonitored — an
		// attacker must not be able to evade the allowlist by mangling the
		// spec. When the file is simply absent (the common non-container watch
		// entry such as kata's "shared" dir, or a bundle whose config.json has
		// not been written yet), we skip: killing there would be a false
		// positive on infrastructure directories. The delayed-write/cgroup race
		// is tracked separately (persistent pending state, audit H-01/PR 07).
		if _, statErr := os.Stat(configPath); statErr == nil {
			m.logger.Warn("deny container: config.json present but unreadable/malformed", "cid", cid, "path", configPath, "error", err)
			m.kill(cid)
			return
		}
		m.logger.Warn("skip: config.json absent (not a container bundle, or not written yet)", "cid", cid, "path", configPath, "error", err)
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
		if m.broker != nil {
			m.broker.record(cid, containerName(spec.Annotations), digest)
		}
		return
	}
	m.logger.Warn("deny container: digest not allowlisted", "cid", cid, "digest", digest)
	m.kill(cid)
}

// kill resolves the container's cgroup and terminates it as a unit.
// Best-effort: if the container has already exited, or its cgroup never
// materialises within the budget, we log and move on.
func (m *monitor) kill(cid string) {
	ok, err := m.killer.kill(cid)
	if err != nil {
		m.logger.Warn("kill cgroup failed", "cid", cid, "error", err)
		return
	}
	if !ok {
		m.logger.Warn("container cgroup not found", "cid", cid)
		return
	}
	m.logger.Info("SIGKILLed container cgroup", "cid", cid)
}

// readConfigJSON retries reading + parsing config.json for the budget
// configReadDeadline. The retry absorbs the gap between directory creation
// (which triggers our IN_CREATE event, and re-seed after kata-agent replaces
// the watch dir) and kata-agent finishing the config.json write.
//
// A successfully parsed spec is complete: kata-agent builds the OCI spec in
// memory and saves config.json once. A valid spec without annotations is
// therefore an enforcement decision, not a partial write. The host controls
// this file, so delaying that decision based on an optional annotation would
// give a stripped workload an avoidable execution window.
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
