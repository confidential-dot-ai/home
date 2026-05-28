//go:build linux

package ratlsmesh

import (
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// metrics holds the proxy's Prometheus metrics. Each instance owns its own
// registry so tests can construct as many parallel proxies as they want
// without the default registry's duplicate-registration panics.
//
// A small number of fields are kept as atomic mirrors because the proxy or
// the readiness check reads them in-process (the Prometheus types have no
// public reader and the dto-protobuf round trip is too heavy for hot paths
// and readiness checks). Their Prometheus projections are GaugeFuncs that
// read the atomic at scrape time.
type metrics struct {
	registry  *prometheus.Registry
	startTime time.Time

	certMode                  atomic.Int64 // 0 = self-signed, 1 = cds (active)
	certModeConfigured        atomic.Int64 // 0 = self-signed, 1 = cds (configured)
	acceptConsecutiveInbound  atomic.Int64
	acceptConsecutiveOutbound atomic.Int64

	activeConnections          *prometheus.GaugeVec
	connectionsTotal           *prometheus.CounterVec
	bytesTotal                 *prometheus.CounterVec
	tlsDialFailures            prometheus.Counter
	dialFailures               prometheus.Counter
	connLimitRejected          prometheus.Counter
	connLimitPerSourceRejected prometheus.Counter
	routeErrors                prometheus.Counter
	destHeaderErrors           *prometheus.CounterVec
	inboundDestRejected        prometheus.Counter
	outboundDestRejected       *prometheus.CounterVec
	// Sidecar counter values are mirrored as Gauges (not Counters) because
	// they are snapshots of another process's counters; a sidecar restart
	// would otherwise show up as an illegal Counter reset.
	iptablesJumpViolations   prometheus.Gauge
	iptablesJumpCheckErrors  prometheus.Gauge
	iptablesIPSetOverflows   prometheus.Gauge
	iptablesMetricsTimestamp prometheus.Gauge
	resolverCacheSize        prometheus.Gauge
	resolverLocalCIDRs       prometheus.Gauge
	resolverLastEvent        prometheus.Gauge
	certRotationFailures     prometheus.Counter
	attestationFailures      prometheus.Counter
	acceptErrors             prometheus.Counter
	tlsSessionResumptions    prometheus.Counter
	measurementPinning       prometheus.Gauge
	certPipelineHealthy      prometheus.Gauge
	certExpiry               *prometheus.GaugeVec

	tlsHandshakeDuration *prometheus.HistogramVec
	connectionDuration   *prometheus.HistogramVec
	timeToFirstByte      *prometheus.HistogramVec
}

func newMetrics() *metrics {
	m := &metrics{
		registry:  prometheus.NewRegistry(),
		startTime: time.Now(),
	}

	dirCert := []string{"direction", "cert_mode"}
	histOpts := func(name, help string) prometheus.HistogramOpts {
		return prometheus.HistogramOpts{
			Name:    name,
			Help:    help,
			Buckets: prometheus.DefBuckets,
		}
	}

	m.activeConnections = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ratls_mesh_active_connections",
		Help: "Currently active proxy connections.",
	}, []string{"direction"})
	m.connectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratls_mesh_connections_total",
		Help: "Total connections handled.",
	}, []string{"direction", "result"})
	m.bytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratls_mesh_bytes_total",
		Help: "Bytes transferred through the proxy.",
	}, []string{"direction", "side"})
	m.tlsDialFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratls_mesh_tls_dial_failures_total",
		Help: "RA-TLS dial failures.",
	})
	m.dialFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratls_mesh_dial_failures_total",
		Help: "Plain TCP dial failures.",
	})
	m.connLimitRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratls_mesh_connection_limit_rejected_total",
		Help: "Connections rejected by global limit.",
	})
	m.connLimitPerSourceRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratls_mesh_connection_limit_per_source_rejected_total",
		Help: "Connections rejected by per-source limit.",
	})
	m.routeErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratls_mesh_route_errors_total",
		Help: "Outbound routing failures (origDst, resolve, parse).",
	})
	m.destHeaderErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratls_mesh_dest_header_errors_total",
		Help: "Destination header read/write failures.",
	}, []string{"side"})
	m.inboundDestRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratls_mesh_inbound_dest_rejected_total",
		Help: "Inbound destinations rejected (not a local pod).",
	})
	m.outboundDestRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ratls_mesh_outbound_dest_rejected_total",
		Help: "Outbound destinations rejected, split by reason (host_addr=direct dial, unknown_pod=informer skew baseline).",
	}, []string{"reason"})
	m.iptablesJumpViolations = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratls_mesh_iptables_jump_position_violations_total",
		Help: "Sidecar-reported count of base-chain jumps that were displaced and reinserted. Mirrored as a Gauge so a sidecar restart isn't a counter-reset.",
	})
	m.iptablesJumpCheckErrors = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratls_mesh_iptables_jump_position_check_errors_total",
		Help: "Sidecar-reported count of jump-position read failures.",
	})
	m.iptablesIPSetOverflows = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratls_mesh_iptables_ipset_overflow_total",
		Help: "Sidecar-reported reconcile cycles where pod count exceeded --ipset-maxelem.",
	})
	m.iptablesMetricsTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratls_mesh_iptables_metrics_file_updated_at_seconds",
		Help: "Unix-seconds timestamp of the last sidecar metrics snapshot the proxy successfully read; 0 = never read.",
	})
	m.resolverCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratls_mesh_resolver_cache_entries",
		Help: "Pod-to-node resolver cache size.",
	})
	m.resolverLocalCIDRs = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratls_mesh_resolver_local_cidrs",
		Help: "Host-discovered pod-network CIDRs available for ValidateLocalDest route cross-checks (0 = Kubernetes pod HostIP fallback active).",
	})
	m.resolverLastEvent = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratls_mesh_resolver_last_event_timestamp_seconds",
		Help: "Unix timestamp of last K8s informer event.",
	})
	m.certRotationFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratls_mesh_cert_rotation_failures_total",
		Help: "Background RA-TLS certificate rotation failures.",
	})
	m.attestationFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratls_mesh_attestation_failures_total",
		Help: "RA-TLS peer attestation verification failures.",
	})
	m.acceptErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratls_mesh_accept_errors_total",
		Help: "Listener accept errors (triggers backoff).",
	})
	m.tlsSessionResumptions = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratls_mesh_tls_session_resumptions_total",
		Help: "TLS session resumptions (skipped full handshake).",
	})
	m.measurementPinning = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratls_mesh_measurement_pinning",
		Help: "1 when --measurements is configured (T2/T3: unsafe without this in production).",
	})
	m.certPipelineHealthy = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ratls_mesh_cert_pipeline_healthy",
		Help: "1 when CDS /ready is reachable (0=unreachable). Stays at -1 when CDS probing is not configured.",
	})
	m.certPipelineHealthy.Set(-1)
	m.certExpiry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ratls_mesh_cert_expiry_timestamp_seconds",
		Help: "Unix timestamp when the RA-TLS certificate expires.",
	}, []string{"role"})

	m.tlsHandshakeDuration = prometheus.NewHistogramVec(histOpts(
		"ratls_mesh_tls_handshake_duration_seconds",
		"RA-TLS handshake duration in seconds."), dirCert)
	m.connectionDuration = prometheus.NewHistogramVec(histOpts(
		"ratls_mesh_connection_duration_seconds",
		"Total connection duration from accept to close in seconds."), dirCert)
	m.timeToFirstByte = prometheus.NewHistogramVec(histOpts(
		"ratls_mesh_time_to_first_byte_seconds",
		"Time from accept to pipe start in seconds."), dirCert)

	m.registry.MustRegister(
		m.activeConnections,
		m.connectionsTotal,
		m.bytesTotal,
		m.tlsDialFailures,
		m.dialFailures,
		m.connLimitRejected,
		m.connLimitPerSourceRejected,
		m.routeErrors,
		m.destHeaderErrors,
		m.inboundDestRejected,
		m.outboundDestRejected,
		m.iptablesJumpViolations,
		m.iptablesJumpCheckErrors,
		m.iptablesIPSetOverflows,
		m.iptablesMetricsTimestamp,
		m.resolverCacheSize,
		m.resolverLocalCIDRs,
		m.resolverLastEvent,
		m.certRotationFailures,
		m.attestationFailures,
		m.acceptErrors,
		m.tlsSessionResumptions,
		m.measurementPinning,
		m.certPipelineHealthy,
		m.certExpiry,
		m.tlsHandshakeDuration,
		m.connectionDuration,
		m.timeToFirstByte,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "ratls_mesh_accept_consecutive_errors",
			Help:        "Consecutive accept errors per listener (readiness degrades at threshold).",
			ConstLabels: prometheus.Labels{"direction": "inbound"},
		}, func() float64 { return float64(m.acceptConsecutiveInbound.Load()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "ratls_mesh_accept_consecutive_errors",
			Help:        "Consecutive accept errors per listener (readiness degrades at threshold).",
			ConstLabels: prometheus.Labels{"direction": "outbound"},
		}, func() float64 { return float64(m.acceptConsecutiveOutbound.Load()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "ratls_mesh_cert_mode",
			Help:        "Active certificate mode (1=active).",
			ConstLabels: prometheus.Labels{"mode": "cds"},
		}, func() float64 { return boolFloat(m.certMode.Load() == 1) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "ratls_mesh_cert_mode",
			Help:        "Active certificate mode (1=active).",
			ConstLabels: prometheus.Labels{"mode": "self-signed"},
		}, func() float64 { return boolFloat(m.certMode.Load() == 0) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "ratls_mesh_cert_mode_configured",
			Help:        "Configured certificate mode (1=active).",
			ConstLabels: prometheus.Labels{"mode": "cds"},
		}, func() float64 { return boolFloat(m.certModeConfigured.Load() == 1) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "ratls_mesh_cert_mode_configured",
			Help:        "Configured certificate mode (1=active).",
			ConstLabels: prometheus.Labels{"mode": "self-signed"},
		}, func() float64 { return boolFloat(m.certModeConfigured.Load() == 0) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "ratls_mesh_cert_mode_mismatch",
			Help: "1 when active cert mode differs from configured (stuck upgrade).",
		}, func() float64 { return boolFloat(m.certMode.Load() != m.certModeConfigured.Load()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "ratls_mesh_process_uptime_seconds",
			Help: "Seconds since proxy start.",
		}, func() float64 { return time.Since(m.startTime).Seconds() }),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	m.populateVecZeros()
	return m
}

// populateVecZeros materialises every (direction, cert_mode), (direction,
// result), (direction, side), (role), (side), and (reason) combination so
// /metrics output has the same set of lines on a freshly-started proxy
// that it does after traffic has flowed. Alerts that key on absence vs.
// zero get a stable shape to compare against.
func (m *metrics) populateVecZeros() {
	directions := []string{"inbound", "outbound", "outbound_same_node"}
	certModes := []string{"self-signed", "cds"}
	for _, dir := range []string{"inbound", "outbound"} {
		m.activeConnections.WithLabelValues(dir)
	}
	for _, dir := range directions {
		for _, res := range []string{"success", "error"} {
			m.connectionsTotal.WithLabelValues(dir, res)
		}
	}
	for _, dir := range []string{"inbound", "outbound"} {
		for _, side := range []string{"forward", "reverse"} {
			m.bytesTotal.WithLabelValues(dir, side)
		}
	}
	for _, side := range []string{"read", "write"} {
		m.destHeaderErrors.WithLabelValues(side)
	}
	for _, reason := range []string{outboundRejectHostAddr, outboundRejectUnknownPod} {
		m.outboundDestRejected.WithLabelValues(reason)
	}
	for _, role := range []string{"server", "client"} {
		m.certExpiry.WithLabelValues(role)
	}
	for _, dir := range directions {
		for _, mode := range certModes {
			m.tlsHandshakeDuration.WithLabelValues(dir, mode)
			m.connectionDuration.WithLabelValues(dir, mode)
			m.timeToFirstByte.WithLabelValues(dir, mode)
		}
	}
}

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// recordOutboundDestRejected increments the outbound-reject counter that
// matches reason. An unknown reason falls back to the unknown-pod bucket
// so a future caller adding a new reason still updates some counter
// rather than dropping the event silently.
func (m *metrics) recordOutboundDestRejected(reason string) {
	switch reason {
	case outboundRejectHostAddr:
		m.outboundDestRejected.WithLabelValues(outboundRejectHostAddr).Inc()
	default:
		m.outboundDestRejected.WithLabelValues(outboundRejectUnknownPod).Inc()
	}
}

func (m *metrics) refreshIptablesMetrics(path string) error {
	if path == "" {
		return nil
	}
	snap, err := readIptablesMetricsFile(path)
	if err != nil {
		return err
	}
	m.iptablesJumpViolations.Set(float64(snap.JumpPositionViolations))
	m.iptablesJumpCheckErrors.Set(float64(snap.JumpPositionCheckErrors))
	m.iptablesIPSetOverflows.Set(float64(snap.IPSetOverflows))
	if snap.UpdatedAtUnixNano > 0 {
		m.iptablesMetricsTimestamp.Set(float64(snap.UpdatedAtUnixNano / int64(time.Second)))
	}
	return nil
}
