package ratlsmesh

import (
	"fmt"
	"io"
	"math"
	"runtime"
	"sync/atomic"
	"time"
)

// Default histogram buckets (seconds). Covers sub-ms to multi-second latencies.
var defaultBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// histogram is a lock-free histogram with fixed buckets. Each bucket stores a
// non-cumulative count; cumulative values are computed at scrape time. The sum
// is stored as float64 bits inside an atomic.Uint64 using a CAS loop.
type histogram struct {
	bounds  []float64
	buckets []atomic.Uint64 // len == len(bounds)+1: [0,b0), [b0,b1), … [bN,+Inf)
	sum     atomic.Uint64   // math.Float64bits of the running sum
	count   atomic.Uint64
}

func newHistogram(bounds []float64) *histogram {
	h := &histogram{
		bounds:  bounds,
		buckets: make([]atomic.Uint64, len(bounds)+1),
	}
	return h
}

// Observe records a single observation.
func (h *histogram) Observe(v float64) {
	// Find bucket via linear scan (12 buckets → fast enough).
	idx := len(h.bounds) // +Inf bucket
	for i, b := range h.bounds {
		if v < b {
			idx = i
			break
		}
	}
	h.buckets[idx].Add(1)
	h.count.Add(1)

	// CAS loop to atomically add v to the float64 sum.
	for {
		old := h.sum.Load()
		new := math.Float64bits(math.Float64frombits(old) + v)
		if h.sum.CompareAndSwap(old, new) {
			break
		}
	}
}

// writePrometheus writes this histogram in standard Prometheus text format
// with the given metric name, help string, and optional label string (e.g.
// `direction="outbound",cert_mode="assam"`). The label string must NOT include
// surrounding braces.
func (h *histogram) writePrometheus(w io.Writer, name, help, labels string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)

	lbl := ""
	if labels != "" {
		lbl = labels + ","
	}

	// Cumulative buckets.
	var cum uint64
	for i, b := range h.bounds {
		cum += h.buckets[i].Load()
		fmt.Fprintf(w, "%s_bucket{%sle=\"%g\"} %d\n", name, lbl, b, cum)
	}
	cum += h.buckets[len(h.bounds)].Load()
	fmt.Fprintf(w, "%s_bucket{%sle=\"+Inf\"} %d\n", name, lbl, cum)

	fmt.Fprintf(w, "%s_sum{%s} %g\n", name, labels, math.Float64frombits(h.sum.Load()))
	fmt.Fprintf(w, "%s_count{%s} %d\n", name, labels, h.count.Load())
}

// labeledHistogram holds pre-allocated histograms keyed by label combinations.
// Linear scan of 2-6 entries on Observe.
type labeledHistogram struct {
	entries []labeledEntry
}

type labeledEntry struct {
	labels string // pre-formatted, e.g. `direction="outbound",cert_mode="assam"`
	hist   *histogram
}

func newLabeledHistogram(labelSets []string, bounds []float64) *labeledHistogram {
	lh := &labeledHistogram{
		entries: make([]labeledEntry, len(labelSets)),
	}
	for i, ls := range labelSets {
		lh.entries[i] = labeledEntry{labels: ls, hist: newHistogram(bounds)}
	}
	return lh
}

// Observe records a value for the given labels string. The labels string must
// exactly match one of the pre-allocated label sets.
func (lh *labeledHistogram) Observe(labels string, v float64) {
	for i := range lh.entries {
		if lh.entries[i].labels == labels {
			lh.entries[i].hist.Observe(v)
			return
		}
	}
}

// writePrometheus writes all label combinations for this histogram metric.
func (lh *labeledHistogram) writePrometheus(w io.Writer, name, help string) {
	first := true
	for _, e := range lh.entries {
		if first {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
			first = false
		}

		lbl := ""
		if e.labels != "" {
			lbl = e.labels + ","
		}

		var cum uint64
		for i, b := range e.hist.bounds {
			cum += e.hist.buckets[i].Load()
			fmt.Fprintf(w, "%s_bucket{%sle=\"%g\"} %d\n", name, lbl, b, cum)
		}
		cum += e.hist.buckets[len(e.hist.bounds)].Load()
		fmt.Fprintf(w, "%s_bucket{%sle=\"+Inf\"} %d\n", name, lbl, cum)

		fmt.Fprintf(w, "%s_sum{%s} %g\n", name, e.labels, math.Float64frombits(e.hist.sum.Load()))
		fmt.Fprintf(w, "%s_count{%s} %d\n", name, e.labels, e.hist.count.Load())
	}
}

// dirCertLabels returns the set of label combinations for direction x cert_mode.
func dirCertLabels() []string {
	return []string{
		`direction="inbound",cert_mode="self-signed"`,
		`direction="inbound",cert_mode="assam"`,
		`direction="outbound",cert_mode="self-signed"`,
		`direction="outbound",cert_mode="assam"`,
		`direction="outbound_local",cert_mode="self-signed"`,
		`direction="outbound_local",cert_mode="assam"`,
	}
}

// metrics holds atomic counters for proxy observability. Zero external
// dependencies — exposed as Prometheus text format via writePrometheus.
type metrics struct {
	startTime time.Time

	activeInbound  atomic.Int64
	activeOutbound atomic.Int64

	connSuccessInbound  atomic.Int64
	connSuccessOutbound atomic.Int64
	connSuccessLocal    atomic.Int64
	connErrorInbound    atomic.Int64
	connErrorOutbound   atomic.Int64
	connErrorLocal      atomic.Int64

	bytesInboundFwd  atomic.Int64
	bytesInboundRev  atomic.Int64
	bytesOutboundFwd atomic.Int64
	bytesOutboundRev atomic.Int64

	tlsDialFailures            atomic.Int64
	dialFailures               atomic.Int64
	connLimitRejected          atomic.Int64
	connLimitPerSourceRejected atomic.Int64
	resolverCacheSize          atomic.Int64
	resolverLastEventTime      atomic.Int64 // Unix timestamp of last informer event
	routeErrors                atomic.Int64
	destHeaderWriteErrors      atomic.Int64
	destHeaderReadErrors       atomic.Int64
	inboundDestRejected        atomic.Int64

	acceptConsecutiveInbound  atomic.Int64 // consecutive accept errors on inbound listener
	acceptConsecutiveOutbound atomic.Int64 // consecutive accept errors on outbound listener

	certRotationFailures  atomic.Int64
	attestationFailures   atomic.Int64
	acceptErrors          atomic.Int64
	certMode              atomic.Int64 // 0 = self-signed, 1 = assam
	certModeExpected      atomic.Int64 // 0 = self-signed, 1 = assam (configured via --cert-mode)
	certExpiryServer      atomic.Int64 // Unix timestamp of server cert NotAfter
	certExpiryClient      atomic.Int64 // Unix timestamp of client cert NotAfter (0 = no mTLS)
	certPipelineHealthy   atomic.Int64 // 1 = cert-issuer reachable, 0 = unreachable (-1 = not configured)
	measurementPinning    atomic.Int64 // 1 = measurements configured, 0 = accepting any TEE
	tlsSessionResumptions atomic.Int64 // TLS session resumptions (skipped full handshake)

	// Histograms for latency visibility.
	tlsHandshakeDuration *labeledHistogram // RA-TLS dial start to TLS established
	connectionDuration   *labeledHistogram // accept to close
	timeToFirstByte      *labeledHistogram // accept to pipe start
}

// newMetrics creates a metrics instance with histograms initialized.
func newMetrics() *metrics {
	labels := dirCertLabels()
	return &metrics{
		startTime:            time.Now(),
		tlsHandshakeDuration: newLabeledHistogram(labels, defaultBuckets),
		connectionDuration:   newLabeledHistogram(labels, defaultBuckets),
		timeToFirstByte:      newLabeledHistogram(labels, defaultBuckets),
	}
}

// writePrometheus writes all metrics in Prometheus text exposition format.
func (m *metrics) writePrometheus(w io.Writer) {
	gauge := func(name, help string, labelValues ...labelValue) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		for _, lv := range labelValues {
			if lv.label == "" {
				fmt.Fprintf(w, "%s %d\n", name, lv.value)
			} else {
				fmt.Fprintf(w, "%s{%s} %d\n", name, lv.label, lv.value)
			}
		}
	}
	counter := func(name, help string, labelValues ...labelValue) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
		for _, lv := range labelValues {
			if lv.label == "" {
				fmt.Fprintf(w, "%s %d\n", name, lv.value)
			} else {
				fmt.Fprintf(w, "%s{%s} %d\n", name, lv.label, lv.value)
			}
		}
	}

	gauge("ratls_mesh_active_connections", "Currently active proxy connections",
		lv(`direction="inbound"`, m.activeInbound.Load()),
		lv(`direction="outbound"`, m.activeOutbound.Load()),
	)

	counter("ratls_mesh_connections_total", "Total connections handled",
		lv(`direction="inbound",result="success"`, m.connSuccessInbound.Load()),
		lv(`direction="inbound",result="error"`, m.connErrorInbound.Load()),
		lv(`direction="outbound",result="success"`, m.connSuccessOutbound.Load()),
		lv(`direction="outbound",result="error"`, m.connErrorOutbound.Load()),
		lv(`direction="outbound_local",result="success"`, m.connSuccessLocal.Load()),
		lv(`direction="outbound_local",result="error"`, m.connErrorLocal.Load()),
	)

	counter("ratls_mesh_bytes_total", "Bytes transferred through the proxy",
		lv(`direction="inbound",side="forward"`, m.bytesInboundFwd.Load()),
		lv(`direction="inbound",side="reverse"`, m.bytesInboundRev.Load()),
		lv(`direction="outbound",side="forward"`, m.bytesOutboundFwd.Load()),
		lv(`direction="outbound",side="reverse"`, m.bytesOutboundRev.Load()),
	)

	counter("ratls_mesh_tls_dial_failures_total", "RA-TLS dial failures",
		lv("", m.tlsDialFailures.Load()),
	)
	counter("ratls_mesh_dial_failures_total", "Plain TCP dial failures",
		lv("", m.dialFailures.Load()),
	)
	counter("ratls_mesh_connection_limit_rejected_total", "Connections rejected by global limit",
		lv("", m.connLimitRejected.Load()),
	)
	counter("ratls_mesh_connection_limit_per_source_rejected_total", "Connections rejected by per-source limit",
		lv("", m.connLimitPerSourceRejected.Load()),
	)

	counter("ratls_mesh_route_errors_total", "Outbound routing failures (origDst, resolve, parse)",
		lv("", m.routeErrors.Load()),
	)
	counter("ratls_mesh_dest_header_errors_total", "Destination header read/write failures",
		lv(`side="write"`, m.destHeaderWriteErrors.Load()),
		lv(`side="read"`, m.destHeaderReadErrors.Load()),
	)
	counter("ratls_mesh_inbound_dest_rejected_total", "Inbound destinations rejected (not a local pod)",
		lv("", m.inboundDestRejected.Load()),
	)

	gauge("ratls_mesh_resolver_cache_entries", "Pod-to-node resolver cache size",
		lv("", m.resolverCacheSize.Load()),
	)

	gauge("ratls_mesh_resolver_last_event_timestamp_seconds", "Unix timestamp of last K8s informer event",
		lv("", m.resolverLastEventTime.Load()),
	)

	counter("ratls_mesh_cert_rotation_failures_total", "Background RA-TLS certificate rotation failures",
		lv("", m.certRotationFailures.Load()),
	)

	counter("ratls_mesh_attestation_failures_total", "RA-TLS peer attestation verification failures",
		lv("", m.attestationFailures.Load()),
	)

	counter("ratls_mesh_accept_errors_total", "Listener accept errors (triggers backoff)",
		lv("", m.acceptErrors.Load()),
	)

	counter("ratls_mesh_tls_session_resumptions_total", "TLS session resumptions (skipped full handshake)",
		lv("", m.tlsSessionResumptions.Load()),
	)

	gauge("ratls_mesh_accept_consecutive_errors", "Consecutive accept errors per listener (readiness degrades at 10)",
		lv(`direction="inbound"`, m.acceptConsecutiveInbound.Load()),
		lv(`direction="outbound"`, m.acceptConsecutiveOutbound.Load()),
	)

	gauge("ratls_mesh_measurement_pinning", "1 when --measurements is configured (T2/T3: unsafe without this in production)",
		lv("", m.measurementPinning.Load()),
	)

	// Cert pipeline health: 1=healthy, 0=unhealthy, -1=not configured.
	pipelineHealth := m.certPipelineHealthy.Load()
	if pipelineHealth >= 0 {
		gauge("ratls_mesh_cert_pipeline_healthy", "1 when cert-issuer /ready is reachable (0=unreachable)",
			lv("", pipelineHealth),
		)
	}

	// Certificate expiry timestamps (Unix seconds). 0 means no cert provisioned yet.
	serverExpiry := m.certExpiryServer.Load()
	clientExpiry := m.certExpiryClient.Load()
	fmt.Fprintf(w, "# HELP ratls_mesh_cert_expiry_timestamp_seconds Unix timestamp when the RA-TLS certificate expires\n")
	fmt.Fprintf(w, "# TYPE ratls_mesh_cert_expiry_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "ratls_mesh_cert_expiry_timestamp_seconds{role=\"server\"} %d\n", serverExpiry)
	fmt.Fprintf(w, "ratls_mesh_cert_expiry_timestamp_seconds{role=\"client\"} %d\n", clientExpiry)

	// Certificate mode gauge: 0=self-signed, 1=assam.
	mode := "self-signed"
	if m.certMode.Load() == 1 {
		mode = "assam"
	}
	gauge("ratls_mesh_cert_mode", "Active certificate mode (1=active)",
		lv(fmt.Sprintf(`mode="%s"`, mode), 1),
	)

	// Configured cert mode (what --cert-mode was set to).
	configuredMode := "self-signed"
	if m.certModeExpected.Load() == 1 {
		configuredMode = "assam"
	}
	gauge("ratls_mesh_cert_mode_configured", "Configured certificate mode (1=active)",
		lv(fmt.Sprintf(`mode="%s"`, configuredMode), 1),
	)

	// Mismatch: 1 when actual cert mode differs from configured.
	var mismatch int64
	if m.certMode.Load() != m.certModeExpected.Load() {
		mismatch = 1
	}
	gauge("ratls_mesh_cert_mode_mismatch", "1 when active cert mode differs from configured (stuck upgrade)",
		lv("", mismatch),
	)

	// Latency histograms.
	m.tlsHandshakeDuration.writePrometheus(w,
		"ratls_mesh_tls_handshake_duration_seconds",
		"RA-TLS handshake duration in seconds")
	m.connectionDuration.writePrometheus(w,
		"ratls_mesh_connection_duration_seconds",
		"Total connection duration from accept to close in seconds")
	m.timeToFirstByte.writePrometheus(w,
		"ratls_mesh_time_to_first_byte_seconds",
		"Time from accept to pipe start in seconds")

	// Process metrics (computed on read).
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	gauge("ratls_mesh_process_uptime_seconds", "Seconds since proxy start",
		lv("", int64(time.Since(m.startTime).Seconds())),
	)
	gauge("ratls_mesh_process_goroutines", "Current goroutine count",
		lv("", int64(runtime.NumGoroutine())),
	)
	gauge("ratls_mesh_process_heap_alloc_bytes", "Current heap allocation in bytes",
		lv("", int64(mem.Alloc)),
	)
	gauge("ratls_mesh_process_heap_sys_bytes", "Heap memory obtained from OS",
		lv("", int64(mem.HeapSys)),
	)
}

type labelValue struct {
	label string
	value int64
}

func lv(label string, value int64) labelValue {
	return labelValue{label: label, value: value}
}
