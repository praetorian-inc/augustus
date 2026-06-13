package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrometheusExporter_Export(t *testing.T) {
	// Arrange: Create metrics with known values
	var mu sync.Mutex
	m := &Metrics{
		ProbesTotal:     100,
		ProbesSucceeded: 85,
		ProbesFailed:    15,
		AttemptsTotal:   500,
		AttemptsVuln:    75,
	}

	exporter := NewPrometheusExporter(m, &mu)

	// Act: Export to Prometheus format
	output := exporter.Export()

	// Assert: Verify Prometheus text format
	expectedLines := []string{
		"augustus_probes_total{status=\"success\"} 85",
		"augustus_probes_total{status=\"failed\"} 15",
		"augustus_probes_total 100",
		"augustus_attempts_total 500",
		"augustus_attempts_vulnerable 75",
		"augustus_attempts_vulnerability_rate 0.15",
	}

	for _, expected := range expectedLines {
		if !strings.Contains(output, expected) {
			t.Errorf("Export() missing expected line: %s\nGot:\n%s", expected, output)
		}
	}
}

func TestPrometheusExporter_Handler(t *testing.T) {
	// Arrange: Create metrics with known values
	var mu sync.Mutex
	m := &Metrics{
		ProbesTotal:     42,
		ProbesSucceeded: 40,
		ProbesFailed:    2,
		AttemptsTotal:   200,
		AttemptsVuln:    30,
	}

	exporter := NewPrometheusExporter(m, &mu)

	// Act: Create HTTP handler and make request
	handler := exporter.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Assert: Verify response
	if rec.Code != http.StatusOK {
		t.Errorf("Handler() status = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	expectedContentType := "text/plain; version=0.0.4; charset=utf-8"
	if contentType != expectedContentType {
		t.Errorf("Handler() Content-Type = %s, want %s", contentType, expectedContentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "augustus_probes_total{status=\"success\"} 40") {
		t.Errorf("Handler() body missing expected metric:\nGot:\n%s", body)
	}

	if !strings.Contains(body, "augustus_attempts_vulnerability_rate") {
		t.Errorf("Handler() body missing vulnerability rate metric:\nGot:\n%s", body)
	}
}

func TestPrometheusExporter_VulnerabilityRate(t *testing.T) {
	tests := []struct {
		name          string
		attemptsTotal int64
		attemptsVuln  int64
		wantRate      float64
	}{
		{
			name:          "15% vulnerability rate",
			attemptsTotal: 100,
			attemptsVuln:  15,
			wantRate:      0.15,
		},
		{
			name:          "zero attempts",
			attemptsTotal: 0,
			attemptsVuln:  0,
			wantRate:      0.0,
		},
		{
			name:          "100% vulnerability",
			attemptsTotal: 50,
			attemptsVuln:  50,
			wantRate:      1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			m := &Metrics{
				AttemptsTotal: tt.attemptsTotal,
				AttemptsVuln:  tt.attemptsVuln,
			}

			exporter := NewPrometheusExporter(m, &mu)
			output := exporter.Export()

			// Check that the rate appears in output
			rateStr := formatFloatTest(tt.wantRate)
			expectedLine := "augustus_attempts_vulnerability_rate " + rateStr
			if !strings.Contains(output, expectedLine) {
				t.Errorf("Export() vulnerability rate = want %s in output:\n%s", expectedLine, output)
			}
		})
	}
}

// Helper to format float consistently with Prometheus exporter
func formatFloatTest(f float64) string {
	if f == 0.0 {
		return "0"
	}
	// Format to 2 decimal places, then trim trailing zeros
	s := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", f), "0"), ".")
	return s
}

// ─── Category (i): Concurrent writes + live snapshot (race test) ─────────────

// TestMetrics_ConcurrentWritesAndSnapshot guards Issue B: 50 goroutines
// concurrently calling RecordProbeResult and AddTokens while another goroutine
// loops SnapshotLocked. Under -race this proves writers and the live reader
// share one lock. Would flag a data race if any write bypassed the mutex.
func TestMetrics_ConcurrentWritesAndSnapshot(t *testing.T) {
	const workers = 50
	m := &Metrics{}

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			m.RecordProbeResult(true, 2, 1)
			m.AddTokens(10)
		}()
	}

	// Concurrent reader: must not race with the writers above.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for i := 0; i < 1000; i++ {
			_ = m.SnapshotLocked()
		}
	}()

	wg.Wait()
	<-readerDone

	snapshot := m.SnapshotLocked()
	require.Equal(t, int64(workers), snapshot.ProbesTotal, "ProbesTotal must equal worker count")
	require.Equal(t, int64(workers), snapshot.ProbesSucceeded, "ProbesSucceeded must equal worker count")
	require.Equal(t, int64(workers*2), snapshot.AttemptsTotal, "AttemptsTotal must be 2 per worker")
	require.Equal(t, int64(workers), snapshot.AttemptsVuln, "AttemptsVuln must be 1 per worker")
	require.Equal(t, int64(workers*10), snapshot.TokensConsumed, "TokensConsumed must be 10 per worker")
}

// TestMetrics_ConcurrentExportDuringScan guards the live /metrics-scrape-during-scan
// scenario at the metrics-package level: PrometheusExporter.Export calls
// SnapshotLocked while multiple goroutines write via RecordProbeResult.
// A missing or wrong lock would surface under -race.
func TestMetrics_ConcurrentExportDuringScan(t *testing.T) {
	m := &Metrics{}
	exporter := NewPrometheusExporter(m, nil)

	var wg sync.WaitGroup
	const writers = 30
	wg.Add(writers)

	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			m.RecordProbeResult(false, 0, 0)
			m.AddTokens(5)
		}()
	}

	// Concurrent reads via Export while writers are running.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for i := 0; i < 500; i++ {
			out := exporter.Export()
			// Export must always produce a non-empty output; never a zero-value partial read.
			if !strings.Contains(out, "augustus_probes_total") {
				panic("Export returned malformed output during concurrent writes")
			}
		}
	}()

	wg.Wait()
	<-readerDone

	snapshot := m.SnapshotLocked()
	assert.Equal(t, int64(writers), snapshot.ProbesTotal)
	assert.Equal(t, int64(writers*5), snapshot.TokensConsumed)
}

// ─── Category (vi, metrics-level): SnapshotLocked returns same data as Snapshot ──

// TestMetrics_SnapshotLocked_EqualsSnapshot verifies that the new
// SnapshotLocked() and the deprecated Snapshot(_ *sync.Mutex) return identical
// snapshots for the same Metrics state (they share one code path).
func TestMetrics_SnapshotLocked_EqualsSnapshot(t *testing.T) {
	m := &Metrics{}
	m.RecordProbeResult(true, 3, 1)
	m.AddTokens(42)

	preferred := m.SnapshotLocked()

	//nolint:staticcheck // intentional deprecated-API backward-compat test
	var freshMu sync.Mutex
	//nolint:staticcheck // intentional deprecated-API backward-compat test
	deprecated := m.Snapshot(&freshMu)

	assert.Equal(t, preferred, deprecated, "SnapshotLocked and deprecated Snapshot must return identical data")
}

// TestMetrics_AddTokens_Accumulates verifies AddTokens is cumulative.
func TestMetrics_AddTokens_Accumulates(t *testing.T) {
	m := &Metrics{}
	m.AddTokens(10)
	m.AddTokens(20)
	m.AddTokens(5)

	snapshot := m.SnapshotLocked()
	require.Equal(t, int64(35), snapshot.TokensConsumed, "AddTokens must accumulate across calls")
}

// TestMetrics_RecordProbeResult_FailureIgnoresAttempts verifies that failed
// probes do not contribute to AttemptsTotal or AttemptsVuln.
func TestMetrics_RecordProbeResult_FailureIgnoresAttempts(t *testing.T) {
	m := &Metrics{}
	m.RecordProbeResult(false, 99, 99) // attempt counts must be ignored on failure

	snapshot := m.SnapshotLocked()
	assert.Equal(t, int64(1), snapshot.ProbesTotal)
	assert.Equal(t, int64(0), snapshot.ProbesSucceeded)
	assert.Equal(t, int64(1), snapshot.ProbesFailed)
	assert.Equal(t, int64(0), snapshot.AttemptsTotal, "failed probe must not add to AttemptsTotal")
	assert.Equal(t, int64(0), snapshot.AttemptsVuln, "failed probe must not add to AttemptsVuln")
}
