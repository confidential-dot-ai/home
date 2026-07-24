//go:build linux

package policymonitor

// Runtime half of the hybrid image-policy allowlist.
//
// The baked bootstrap-allowlist.json (on the dm-verity root) is the SEED:
// it lets the guest enforce from t=0 with no network. This loop keeps the
// in-VM allowlist current with operator additions CDS has accepted by
// polling CDS's `/allowlist` over RA-TLS and merging the result on top of
// the seed. It reuses exactly the mechanism the host nri-image-policy
// worker uses (pkg/ratls RA-TLS client pinned to cds.measurements +
// pkg/allowlistclient), so the in-guest enforcer and the host enforcer
// pull from the same authenticated source. See docs/kata-image-policy.md.
//
// Gated on a configured CDS URL: with C8S_CDS_URL unset the monitor
// stays baked-seed-only and never opens the network.

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// runAllowlistRefresh builds the RA-TLS-pinned CDS allowlist client and
// polls it on cfg.RefreshInterval, merging each response into a. It runs
// until ctx is cancelled. Construction failures (bad measurements, RA-TLS
// setup) disable refresh but never crash the monitor — the baked seed
// still enforces.
func runAllowlistRefresh(ctx context.Context, logger *slog.Logger, cfg *Config, a *allowlist, overlay *policyOverlay) {
	measurements, err := ratls.ParseHexMeasurementsList(splitCSV(cfg.CDSMeasurements))
	if err != nil {
		logger.Error("allowlist refresh disabled: invalid C8S_CDS_MEASUREMENTS", "error", err)
		return
	}
	if len(measurements) == 0 {
		// Fail closed: with C8S_CDS_URL set but no measurements pinned, the
		// RA-TLS handshake would accept any CDS measurement. Disable refresh
		// rather than open that hole — the baked seed keeps enforcing.
		logger.Error("allowlist refresh disabled: C8S_CDS_URL set but C8S_CDS_MEASUREMENTS empty (refusing to accept any CDS measurement)")
		return
	}
	httpClient, err := ratls.NewVerifyingHTTPClient(measurements, cfg.AttestationServiceURL)
	if err != nil {
		logger.Error("allowlist refresh disabled: build RA-TLS client failed", "error", err)
		return
	}
	client := allowlistclient.NewClientWithHTTP(cfg.CDSURL, httpClient)

	// Per-call deadline so a hung CDS can't wedge this goroutine. Capped at
	// half the refresh interval (and never above refreshCallTimeoutMax) so
	// a stuck call always returns before the next tick fires.
	callTimeout := cfg.RefreshInterval / 2
	if callTimeout > refreshCallTimeoutMax {
		callTimeout = refreshCallTimeoutMax
	}

	logger.Info("allowlist refresh enabled", "cds_url", cfg.CDSURL, "interval", cfg.RefreshInterval, "call_timeout", callTimeout)
	ticker := time.NewTicker(cfg.RefreshInterval)
	defer ticker.Stop()
	for {
		refreshOnce(ctx, logger, client, a, overlay, callTimeout)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// refreshCallTimeoutMax bounds a single CDS round-trip. The refresh loop
// further clamps to half the configured interval so the call can never
// outlive the next tick.
const refreshCallTimeoutMax = 15 * time.Second

// refreshOnce pulls the current CDS allowlist. Two layers update: the baked
// floor grows additively with the pulled floor digests (never shrinks — a CDS
// outage or rollback can't loosen digest-only admission), and the workload argv
// policy overlay is replaced only when the pulled version advances the epoch.
// A failed pull is logged and skipped — the existing allowlist and overlay keep
// enforcing, so a CDS outage degrades to "stale but no smaller", never "open".
func refreshOnce(ctx context.Context, logger *slog.Logger, client allowlistclient.Client, a *allowlist, overlay *policyOverlay, callTimeout time.Duration) {
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, version, err := client.List(callCtx)
	if err != nil {
		logger.Warn("allowlist refresh from CDS failed (keeping current allowlist)", "error", err)
		return
	}

	pulled := make([]string, 0, len(resp.Digests))
	for d := range resp.Digests {
		pulled = append(pulled, d)
	}
	added := a.MergePulled(pulled)

	v, verr := strconv.ParseUint(version, 10, 64)
	if verr != nil {
		logger.Warn("allowlist refresh: unparseable CDS version; keeping current overlay", "version", version, "error", verr)
		return
	}
	if overlay.apply(resp, v) {
		logger.Info("allowlist refreshed from CDS", "version", v, "workloads", len(resp.Workloads), "floor_added", added, "floor_total", a.Size())
	} else {
		logger.Warn("allowlist refresh: ignoring rolled-back CDS version; keeping current overlay", "version", v, "floor_added", added, "floor_total", a.Size())
	}
}

// splitCSV trims and splits a comma-separated env value into non-empty
// fields. "" → nil.
func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
