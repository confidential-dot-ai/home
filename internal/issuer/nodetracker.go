package issuer

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	activeNodes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cds_active_nodes",
		Help: "Number of distinct node IPs that received certificates within the TTL window.",
	})

	oldestActiveCertExpiry = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cds_oldest_active_cert_expiry_seconds",
		Help: "Seconds until the oldest active node certificate expires.",
	})
)

type nodeEntry struct {
	lastSeen   time.Time
	certExpiry time.Time
}

// NodeTracker tracks aggregate certificate issuance metrics without per-IP
// cardinality. Entries older than 2*MaxTTL are evicted on UpdateMetrics().
type NodeTracker struct {
	mu     sync.Mutex
	nodes  map[string]nodeEntry
	maxTTL time.Duration
}

func NewNodeTracker(maxTTL time.Duration) *NodeTracker {
	return &NodeTracker{
		nodes:  make(map[string]nodeEntry),
		maxTTL: maxTTL,
	}
}

func (nt *NodeTracker) Track(ip string, certExpiry time.Time) {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	nt.nodes[ip] = nodeEntry{
		lastSeen:   time.Now(),
		certExpiry: certExpiry,
	}
}

// UpdateMetrics recomputes aggregate gauges. Call periodically from a
// background goroutine.
func (nt *NodeTracker) UpdateMetrics() {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-2 * nt.maxTTL)

	for ip, entry := range nt.nodes {
		if entry.lastSeen.Before(cutoff) {
			delete(nt.nodes, ip)
		}
	}

	activeNodes.Set(float64(len(nt.nodes)))

	if len(nt.nodes) == 0 {
		oldestActiveCertExpiry.Set(0)
		return
	}

	var oldest time.Time
	for _, entry := range nt.nodes {
		if oldest.IsZero() || entry.certExpiry.Before(oldest) {
			oldest = entry.certExpiry
		}
	}
	oldestActiveCertExpiry.Set(oldest.Sub(now).Seconds())
}

// RunUpdater calls UpdateMetrics on each tick until ctx is cancelled.
func (nt *NodeTracker) RunUpdater(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nt.UpdateMetrics()
		}
	}
}
