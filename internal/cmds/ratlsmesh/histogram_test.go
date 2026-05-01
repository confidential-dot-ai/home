package ratlsmesh

import (
	"bytes"
	"math"
	"strings"
	"sync"
	"testing"
)

func TestHistogramObserve(t *testing.T) {
	h := newHistogram([]float64{0.01, 0.05, 0.1, 1.0})
	// 5 buckets: [0,0.01), [0.01,0.05), [0.05,0.1), [0.1,1.0), [1.0,+Inf)

	h.Observe(0.005) // bucket 0
	h.Observe(0.005) // bucket 0
	h.Observe(0.02)  // bucket 1
	h.Observe(0.07)  // bucket 2
	h.Observe(0.5)   // bucket 3
	h.Observe(2.0)   // bucket 4 (+Inf)

	// Non-cumulative bucket counts.
	wantBuckets := []uint64{2, 1, 1, 1, 1}
	for i, want := range wantBuckets {
		got := h.buckets[i].Load()
		if got != want {
			t.Errorf("bucket[%d] = %d, want %d", i, got, want)
		}
	}

	if got := h.count.Load(); got != 6 {
		t.Errorf("count = %d, want 6", got)
	}

	wantSum := 0.005 + 0.005 + 0.02 + 0.07 + 0.5 + 2.0
	gotSum := math.Float64frombits(h.sum.Load())
	if math.Abs(gotSum-wantSum) > 1e-9 {
		t.Errorf("sum = %g, want %g", gotSum, wantSum)
	}
}

func TestHistogramConcurrent(t *testing.T) {
	h := newHistogram(defaultBuckets)
	const goroutines = 100
	const obsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func(g int) {
			defer wg.Done()
			for i := range obsPerGoroutine {
				v := float64(g*obsPerGoroutine+i) * 0.0001
				h.Observe(v)
			}
		}(g)
	}
	wg.Wait()

	if got := h.count.Load(); got != goroutines*obsPerGoroutine {
		t.Errorf("count = %d, want %d", got, goroutines*obsPerGoroutine)
	}

	// Verify non-cumulative bucket counts sum to total count.
	var total uint64
	for i := range h.buckets {
		total += h.buckets[i].Load()
	}
	if total != goroutines*obsPerGoroutine {
		t.Errorf("bucket sum = %d, want %d", total, goroutines*obsPerGoroutine)
	}
}

func TestHistogramWritePrometheus(t *testing.T) {
	h := newHistogram([]float64{0.1, 0.5, 1.0})

	h.Observe(0.05) // bucket 0
	h.Observe(0.3)  // bucket 1
	h.Observe(0.8)  // bucket 2
	h.Observe(5.0)  // bucket 3 (+Inf)

	var buf bytes.Buffer
	h.writePrometheus(&buf, "test_duration_seconds", "A test histogram", `direction="inbound"`)
	text := buf.String()

	// Verify HELP and TYPE.
	if !strings.Contains(text, "# HELP test_duration_seconds A test histogram") {
		t.Error("missing HELP line")
	}
	if !strings.Contains(text, "# TYPE test_duration_seconds histogram") {
		t.Error("missing TYPE line")
	}

	// Cumulative buckets: 1, 2, 3, 4.
	wantLines := []string{
		`test_duration_seconds_bucket{direction="inbound",le="0.1"} 1`,
		`test_duration_seconds_bucket{direction="inbound",le="0.5"} 2`,
		`test_duration_seconds_bucket{direction="inbound",le="1"} 3`,
		`test_duration_seconds_bucket{direction="inbound",le="+Inf"} 4`,
		`test_duration_seconds_count{direction="inbound"} 4`,
	}
	for _, want := range wantLines {
		if !strings.Contains(text, want) {
			t.Errorf("missing line: %s\n\ngot:\n%s", want, text)
		}
	}

	// Verify sum is present and approximately correct.
	if !strings.Contains(text, `test_duration_seconds_sum{direction="inbound"}`) {
		t.Errorf("missing sum line\n\ngot:\n%s", text)
	}
}

func TestHistogramWritePrometheusNoLabels(t *testing.T) {
	h := newHistogram([]float64{1.0})
	h.Observe(0.5)

	var buf bytes.Buffer
	h.writePrometheus(&buf, "m", "help", "")
	text := buf.String()

	if !strings.Contains(text, `m_bucket{le="1"} 1`) {
		t.Errorf("missing bucket line for no-label histogram\n\ngot:\n%s", text)
	}
	if !strings.Contains(text, `m_bucket{le="+Inf"} 1`) {
		t.Errorf("missing +Inf bucket\n\ngot:\n%s", text)
	}
	if !strings.Contains(text, "m_count{} 1") {
		t.Errorf("missing count line\n\ngot:\n%s", text)
	}
}

func TestLabeledHistogramObserve(t *testing.T) {
	lh := newLabeledHistogram([]string{
		`direction="inbound"`,
		`direction="outbound"`,
	}, []float64{0.1, 1.0})

	lh.Observe(`direction="inbound"`, 0.05)
	lh.Observe(`direction="inbound"`, 0.05)
	lh.Observe(`direction="outbound"`, 5.0)

	// Verify per-label independence.
	if got := lh.entries[0].hist.count.Load(); got != 2 {
		t.Errorf("inbound count = %d, want 2", got)
	}
	if got := lh.entries[1].hist.count.Load(); got != 1 {
		t.Errorf("outbound count = %d, want 1", got)
	}
}

func TestLabeledHistogramWritePrometheus(t *testing.T) {
	lh := newLabeledHistogram([]string{
		`direction="inbound",cert_mode="self-signed"`,
		`direction="outbound",cert_mode="assam"`,
	}, []float64{0.1})

	lh.Observe(`direction="inbound",cert_mode="self-signed"`, 0.05)
	lh.Observe(`direction="outbound",cert_mode="assam"`, 0.5)

	var buf bytes.Buffer
	lh.writePrometheus(&buf, "test_hist", "test help")
	text := buf.String()

	// Should have exactly one HELP and TYPE line.
	if strings.Count(text, "# HELP") != 1 {
		t.Errorf("expected 1 HELP line, got %d", strings.Count(text, "# HELP"))
	}
	if strings.Count(text, "# TYPE") != 1 {
		t.Errorf("expected 1 TYPE line, got %d", strings.Count(text, "# TYPE"))
	}

	// Check both label sets appear.
	if !strings.Contains(text, `direction="inbound",cert_mode="self-signed",le="0.1"`) {
		t.Errorf("missing inbound bucket\n\ngot:\n%s", text)
	}
	if !strings.Contains(text, `direction="outbound",cert_mode="assam",le="+Inf"`) {
		t.Errorf("missing outbound +Inf bucket\n\ngot:\n%s", text)
	}
}
