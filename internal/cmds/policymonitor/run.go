//go:build linux

// Package policymonitor implements the in-VM container-digest enforcement
// daemon baked into kata-guest-base. It replaces the older
// guest-policy-agent (a Rego renderer that fetched a allowlist from CDS
// over RA-TLS and rendered it informationally without enforcing).
// policy-monitor instead enforces directly, off a baked seed allowlist it
// refreshes from CDS at runtime; see docs/kata-image-policy.md.
//
// # What it does
//
// policy-monitor watches /run/kata-containers via inotify. Every time
// kata-agent creates a new container bundle, a directory <container_id>/
// appears with a config.json that contains the OCI spec — including the
// CRI annotations containerd's CRI plugin stamps onto the container.
// policy-monitor reads config.json, extracts the image digest from
// `io.kubernetes.cri.image-name`, and checks the digest portion against
// the allowlist (the baked /etc/c8s/bootstrap-allowlist.json seed on the
// dm-verity root, plus whatever the CDS refresh has merged on top). If
// the digest is not allowlisted, the monitor
// resolves the container's cgroup via the kata-agent / runc hierarchy and
// sends SIGKILL to the cgroup as a unit.
//
// # Why post-start kill, not pre-start gate
//
// In this kata version (3.30.0) the in-guest path from CreateContainer
// → ttRPC OCI spec → on-disk config.json → fork+exec is entirely
// in-process inside kata-agent. There is no upstream-supported pre-start
// callout from kata-agent to a sibling daemon: kata-agent's OPA policy
// is the only documented enforcement seam, and that seam is structurally
// permissive in the c8s shape (we don't carry a c8s-specific
// `default allow := false` in the baked policy because we don't yet have
// the operator-supplied digest list at policy-bake time for arbitrary
// workloads — only the bootstrap CDS images).
//
// So we accept the post-start window. The container's init process runs
// for the duration of the inotify event delivery + config.json parse +
// cgroup lookup + cgroup.kill write — typically a handful of
// milliseconds on hardware. That window is documented as a known
// limitation in docs/kata-image-policy.md, with the BPF-LSM upgrade
// path noted as the way to close it (intercept execve in the
// container's namespace pre-bprm_check via a CO-RE eBPF program loaded
// by the monitor at boot).
//
// Upstream archaeology — confirmed against kata-containers 3.30.0
//
//   - Container bundle path: /run/kata-containers/<container_id>/.
//     Set by `CONTAINER_BASE` in src/agent/src/rpc.rs:115. The bundle
//     directory and config.json are written by setup_bundle() at
//     src/agent/src/rpc.rs:2308 during CreateContainerRequest, before
//     kata-agent forks the container init. The OCI spec written to
//     config.json carries the full annotations map passed from the
//     containerd shim (containerd CRI plugin stamps
//     "io.kubernetes.cri.image-name" on every container; see
//     pkg/cri/annotations/annotations.go:78 in containerd v1.7.21).
//
//   - state.json is NOT written. kata-agent manages container state
//     in-memory (LinuxContainer struct in
//     src/agent/rustjail/src/container.rs). The init process PID is
//     stored in LinuxContainer.init_process_pid (set at line 1182 of
//     container.rs after fork). The external observation channel is the
//     container's cgroup: the agent's cgroup_manager puts the init under
//     /sys/fs/cgroup/<container_id> (unified hierarchy) or one of the v1
//     controller paths. We terminate the cgroup as a unit.
//
//   - The container_id format is verified by kata_sys_util::validate::
//     verify_id (rpc.rs:222), which restricts to a conservative
//     alphanum+dash subset. We re-validate inside the monitor before
//     using the id as a path or signal target.
//
//   - The "io.kubernetes.cri.image-name" annotation carries a string
//     of the form "<registry>/<image>@sha256:<hex>" when the image was
//     pulled by digest (the CRI plugin uses the canonical reference
//     when it has one). Some pulls record only "<registry>/<image>:<tag>"
//     plus a sibling annotation; we also fall back to
//     "io.kubernetes.cri.image-id" (rare) and the image-spec-style
//     "org.opencontainers.image.ref.name" when present. The matcher
//     normalises any of these forms to a bare sha256:<64hex> before
//     comparing against the allowlist.
//
// # CLI surface
//
// Mirrors internal/cmds/ratlsmesh/main.go's Run shape: cobra root with
// signal-wired Context, one default subcommand (`monitor`) that watches
// indefinitely and, when a CDS URL is configured, polls CDS for allowlist
// updates in the background (cds_refresh.go). The systemd unit
// (kata-guest-base/extra/etc/systemd/system/policy-monitor.service) is the
// supervisor; failure is signalled by process exit with
// `Restart=on-failure`.
package policymonitor

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// Run is the cobra-driven entry point invoked from cmd/policy-monitor/main.go
// and (via aliasing) the c8s multi-mode binary. It installs the SIGTERM
// /SIGINT handler at the root so subcommand RunE bodies read
// cmd.Context() instead of reinstalling their own NotifyContext —
// matches the shape of internal/cmds/ratlsmesh.Run.
func Run(args []string) error {
	cmd := newRootCommand()
	cmd.SetArgs(args)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return cmd.ExecuteContext(ctx)
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "policy-monitor",
		Short:         "In-VM container-digest enforcement (watches kata-agent bundles, kills disallowed)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newMonitorCommand())
	return root
}

func newMonitorCommand() *cobra.Command {
	var cfg Config
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Watch /run/kata-containers and SIGKILL containers whose image digest is not allowlisted.",
		Long: `monitor is the long-running daemon. It:

  - Loads the baked /etc/c8s/bootstrap-allowlist.json seed (sha256
    digests on the guest's dm-verity root).
  - When --cds-url (or $C8S_CDS_URL) is set, polls CDS's /allowlist over
    RA-TLS on an interval and merges new digests on top of the seed.
  - Sets up an inotify watch on /run/kata-containers/.
  - For each new container directory, reads <id>/config.json, extracts
    the image digest from OCI annotations, checks the allowlist.
  - If denied, locates the container cgroup and sends SIGKILL to the
    cgroup as a unit.

Decisions are logged at info level for operator visibility. If the
allowlist file is missing or unparseable, monitor exits non-zero — the
systemd unit's Restart=on-failure cycle keeps retrying, but a baked-in
file should never be missing, so a failure here surfaces a build defect
rather than a transient runtime problem.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg.fillDefaults()
			return runMonitor(cmd.Context(), &cfg)
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&cfg.AllowlistPath, "allowlist", defaultAllowlistPath, "path to the baked bootstrap-allowlist seed JSON")
	fs.StringVar(&cfg.WatchDir, "watch-dir", defaultWatchDir, "kata-agent container-bundle directory to watch via inotify")
	fs.StringVar(&cfg.CgroupRoot, "cgroup-root", defaultCgroupRoot, "cgroup hierarchy root (v2 unified)")
	fs.StringVar(&cfg.LogLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.StringVar(&cfg.CDSURL, "cds-url", "", "CDS base URL to refresh the allowlist from over RA-TLS (default $C8S_CDS_URL; empty = baked seed only, no network)")
	fs.StringVar(&cfg.CDSMeasurements, "cds-measurements", "", "comma-separated SHA-384 hex launch digests CDS's RA-TLS serving cert must match (default $C8S_CDS_MEASUREMENTS)")
	fs.StringVar(&cfg.AttestationServiceURL, "attestation-service-url", "", "local attestation-service URL for in-guest RA-TLS evidence (default $C8S_ATTESTATION_SERVICE_URL or http://127.0.0.1:8400)")
	fs.DurationVar(&cfg.RefreshInterval, "allowlist-refresh-interval", defaultRefreshInterval, "interval to poll CDS for allowlist updates (only when --cds-url is set)")
	return cmd
}

// Config holds the runtime configuration for the monitor. Values are
// CLI-overridable so tests can drive the monitor against a tempdir
// instead of /run/kata-containers; the systemd unit relies on defaults.
type Config struct {
	// AllowlistPath is the JSON file that lists the allowed sha256
	// digests. Baked into the IGVM at build time (see
	// kata-guest-base/scripts/fetch.sh's digest substitution step).
	AllowlistPath string

	// WatchDir is the directory the monitor inotify-watches. Defaults
	// to kata-agent's CONTAINER_BASE.
	WatchDir string

	// CgroupRoot is the unified-hierarchy root used to discover the
	// container's init PID. Defaults to /sys/fs/cgroup.
	CgroupRoot string

	// LogLevel is the slog level (debug / info / warn / error).
	LogLevel string

	// CDSURL, when non-empty, enables the hybrid refresh: the monitor
	// polls CDS's /allowlist over RA-TLS and merges it on top of the
	// baked seed. Empty (the default when no cloud-init env is present)
	// keeps the monitor baked-seed-only and off the network. Defaults
	// from $C8S_CDS_URL (the same cloud-init value ratls-mesh reads).
	CDSURL string

	// CDSMeasurements is a comma-separated list of SHA-384 hex launch
	// digests CDS's RA-TLS serving cert must match. Defaults from
	// $C8S_CDS_MEASUREMENTS. Empty = accept any (unsafe; warned).
	CDSMeasurements string

	// AttestationServiceURL is the local attester used to build the
	// in-guest RA-TLS evidence for the CDS handshake. Defaults from
	// $C8S_ATTESTATION_SERVICE_URL, else http://127.0.0.1:8400.
	AttestationServiceURL string

	// RefreshInterval is the CDS allowlist poll cadence (hybrid only).
	RefreshInterval time.Duration
}

func (c *Config) fillDefaults() {
	if c.AllowlistPath == "" {
		c.AllowlistPath = defaultAllowlistPath
	}
	if c.WatchDir == "" {
		c.WatchDir = defaultWatchDir
	}
	if c.CgroupRoot == "" {
		c.CgroupRoot = defaultCgroupRoot
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	// Hybrid CDS-refresh config defaults from the cloud-init env the
	// systemd unit loads (EnvironmentFile=/run/c8s/ratls-mesh.env) —
	// the same C8S_* values ratls-mesh reads, so the two in-guest
	// services pin the same CDS.
	if c.CDSURL == "" {
		c.CDSURL = os.Getenv("C8S_CDS_URL")
	}
	if c.CDSMeasurements == "" {
		c.CDSMeasurements = os.Getenv("C8S_CDS_MEASUREMENTS")
	}
	if c.AttestationServiceURL == "" {
		c.AttestationServiceURL = os.Getenv("C8S_ATTESTATION_SERVICE_URL")
	}
	if c.AttestationServiceURL == "" {
		c.AttestationServiceURL = defaultAttestationServiceURL
	}
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = defaultRefreshInterval
	}
}

// Defaults — exported as constants so the systemd unit (which calls
// `policy-monitor monitor` with no flags) and the tests can both refer
// to the same values without divergence.
const (
	// defaultAllowlistPath is the bake-time location of the allowlist.
	// /etc/c8s/ is on the verity root in kata-guest-base, so the file
	// can't be modified by anything inside the running VM (and
	// SEV-SNP memory encryption prevents the host from reaching it).
	defaultAllowlistPath = "/etc/c8s/bootstrap-allowlist.json"

	// defaultWatchDir is kata-agent's CONTAINER_BASE
	// (src/agent/src/rpc.rs:115 in kata-containers 3.30.0).
	defaultWatchDir = "/run/kata-containers"

	// defaultCgroupRoot is the v2 unified-hierarchy mount. Containers
	// created by the kata-agent live under their cid here.
	defaultCgroupRoot = "/sys/fs/cgroup"

	// defaultAttestationServiceURL is the loopback in-guest attester
	// (kata-guest-base's attestation-service.service). Matches the
	// default ratls-mesh uses.
	defaultAttestationServiceURL = "http://127.0.0.1:8400"

	// defaultRefreshInterval is the CDS allowlist poll cadence — matches
	// the host nri-image-policy worker's default pull interval.
	defaultRefreshInterval = 30 * time.Second
)
