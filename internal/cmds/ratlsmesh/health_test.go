//go:build linux

package ratlsmesh

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthLive(t *testing.T) {
	h := newHealthServer(testMetrics(), nil, nil, 10, 5*time.Second, 10*time.Second)
	req := httptest.NewRequest("GET", "/live", nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /live = %d, want 200", w.Code)
	}
}

func TestHealthReadyNotReady(t *testing.T) {
	h := newHealthServer(testMetrics(), nil, nil, 10, 5*time.Second, 10*time.Second)
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /ready (not ready) = %d, want 503", w.Code)
	}
}

func TestHealthReadyAfterSignal(t *testing.T) {
	h := newHealthServer(testMetrics(), nil, nil, 10, 5*time.Second, 10*time.Second)
	h.ready.Store(true)

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /ready (ready) = %d, want 200", w.Code)
	}
}

func TestHealthReadyAcceptLoopDegraded(t *testing.T) {
	m := testMetrics()
	h := newHealthServer(m, nil, nil, 10, 5*time.Second, 10*time.Second)
	h.ready.Store(true)

	// Below threshold: should be ready.
	m.acceptConsecutiveInbound.Store(h.acceptErrorThreshold - 1)
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("below threshold: GET /ready = %d, want 200", w.Code)
	}

	// At threshold (inbound): should degrade.
	m.acceptConsecutiveInbound.Store(h.acceptErrorThreshold)
	req = httptest.NewRequest("GET", "/ready", nil)
	w = httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("at threshold (inbound): GET /ready = %d, want 503", w.Code)
	}

	// Reset inbound, trigger outbound.
	m.acceptConsecutiveInbound.Store(0)
	m.acceptConsecutiveOutbound.Store(h.acceptErrorThreshold)
	req = httptest.NewRequest("GET", "/ready", nil)
	w = httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("at threshold (outbound): GET /ready = %d, want 503", w.Code)
	}

	// Recovery: reset both counters.
	m.acceptConsecutiveOutbound.Store(0)
	req = httptest.NewRequest("GET", "/ready", nil)
	w = httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("after recovery: GET /ready = %d, want 200", w.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	m := testMetrics()
	m.connectionsTotal.WithLabelValues("inbound", "success").Add(42)
	m.bytesTotal.WithLabelValues("inbound", "forward").Add(1024)

	h := newHealthServer(m, nil, nil, 10, 5*time.Second, 10*time.Second)
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	text := string(body)

	checks := []string{
		"ratls_mesh_active_connections",
		"ratls_mesh_connections_total",
		"ratls_mesh_bytes_total",
		"ratls_mesh_tls_dial_failures_total",
		"ratls_mesh_resolver_cache_entries",
		"ratls_mesh_route_errors_total",
		"ratls_mesh_dest_header_errors_total",
		"ratls_mesh_process_uptime_seconds",
		"go_goroutines",
		"go_memstats_heap_alloc_bytes",
		"go_memstats_heap_sys_bytes",
		"ratls_mesh_inbound_dest_rejected_total",
		"ratls_mesh_cert_rotation_failures_total",
		"ratls_mesh_resolver_last_event_timestamp_seconds",
		"ratls_mesh_cert_mode_configured",
		"ratls_mesh_cert_mode_mismatch",
		"ratls_mesh_accept_consecutive_errors",
		"ratls_mesh_connection_limit_per_source_rejected_total",
		"ratls_mesh_measurement_pinning",
		`direction="inbound",result="success"} 42`,
		`direction="inbound",side="forward"} 1024`,
		// Histogram metrics.
		"ratls_mesh_tls_handshake_duration_seconds_bucket",
		"ratls_mesh_tls_handshake_duration_seconds_sum",
		"ratls_mesh_tls_handshake_duration_seconds_count",
		"ratls_mesh_connection_duration_seconds_bucket",
		"ratls_mesh_connection_duration_seconds_sum",
		"ratls_mesh_connection_duration_seconds_count",
		"ratls_mesh_time_to_first_byte_seconds_bucket",
		"ratls_mesh_time_to_first_byte_seconds_sum",
		"ratls_mesh_time_to_first_byte_seconds_count",
	}
	for _, want := range checks {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}
