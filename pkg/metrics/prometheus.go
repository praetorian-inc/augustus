package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// Metrics tracks scan execution statistics. Safe for concurrent use:
// all mutators and SnapshotLocked lock the embedded mutex.
type Metrics struct {
	mu              sync.Mutex // guards all fields below
	ProbesTotal     int64
	ProbesSucceeded int64
	ProbesFailed    int64
	AttemptsTotal   int64
	AttemptsVuln    int64
	TokensConsumed  int64
}

// RecordProbeResult records one probe completion under the internal lock.
// On success it also adds the supplied attempt counts; on failure the attempt
// counts are ignored.
func (m *Metrics) RecordProbeResult(succeeded bool, totalAttempts, vulnAttempts int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ProbesTotal++
	if succeeded {
		m.ProbesSucceeded++
		m.AttemptsTotal += totalAttempts
		m.AttemptsVuln += vulnAttempts
	} else {
		m.ProbesFailed++
	}
}

// AddTokens adds n to the cumulative token counter under the internal lock.
func (m *Metrics) AddTokens(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TokensConsumed += n
}

// SnapshotLocked returns a point-in-time copy of the metrics, taking the
// internal lock. This is the preferred accessor; no external mutex required.
func (m *Metrics) SnapshotLocked() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return MetricsSnapshot{
		ProbesTotal:     m.ProbesTotal,
		ProbesSucceeded: m.ProbesSucceeded,
		ProbesFailed:    m.ProbesFailed,
		AttemptsTotal:   m.AttemptsTotal,
		AttemptsVuln:    m.AttemptsVuln,
		TokensConsumed:  m.TokensConsumed,
	}
}

// Snapshot returns a copy of the metrics.
//
// Deprecated: the mu argument is ignored; Metrics now synchronizes internally.
// Call SnapshotLocked instead.
func (m *Metrics) Snapshot(_ *sync.Mutex) MetricsSnapshot {
	return m.SnapshotLocked()
}

// MetricsSnapshot is a point-in-time copy of metrics values.
type MetricsSnapshot struct {
	ProbesTotal     int64
	ProbesSucceeded int64
	ProbesFailed    int64
	AttemptsTotal   int64
	AttemptsVuln    int64
	TokensConsumed  int64
}

// PrometheusExporter exports metrics in Prometheus text format
type PrometheusExporter struct {
	metrics *Metrics
}

// NewPrometheusExporter creates a new Prometheus exporter.
//
// Deprecated: the mu argument is ignored; Metrics now synchronizes internally.
// The two-argument signature is retained only for backward compatibility.
func NewPrometheusExporter(m *Metrics, _ *sync.Mutex) *PrometheusExporter {
	return &PrometheusExporter{
		metrics: m,
	}
}

// Export returns metrics in Prometheus text format
func (e *PrometheusExporter) Export() string {
	// Get a thread-safe snapshot of metrics via the internal lock.
	snapshot := e.metrics.SnapshotLocked()

	var b strings.Builder

	// augustus_probes_total with status labels
	fmt.Fprintf(&b, "augustus_probes_total{status=\"success\"} %d\n", snapshot.ProbesSucceeded)
	fmt.Fprintf(&b, "augustus_probes_total{status=\"failed\"} %d\n", snapshot.ProbesFailed)

	// augustus_probes_total (aggregate)
	fmt.Fprintf(&b, "augustus_probes_total %d\n", snapshot.ProbesTotal)

	// augustus_attempts_total
	fmt.Fprintf(&b, "augustus_attempts_total %d\n", snapshot.AttemptsTotal)

	// augustus_attempts_vulnerable
	fmt.Fprintf(&b, "augustus_attempts_vulnerable %d\n", snapshot.AttemptsVuln)

	// augustus_attempts_vulnerability_rate (calculated metric)
	var vulnRate float64
	if snapshot.AttemptsTotal > 0 {
		vulnRate = float64(snapshot.AttemptsVuln) / float64(snapshot.AttemptsTotal)
	}
	fmt.Fprintf(&b, "augustus_attempts_vulnerability_rate %s\n", formatFloat(vulnRate))

	return b.String()
}

// Handler returns an HTTP handler for the /metrics endpoint
func (e *PrometheusExporter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, e.Export())
	})
}

// formatFloat formats a float64 for Prometheus (removes trailing zeros)
func formatFloat(f float64) string {
	if f == 0.0 {
		return "0"
	}
	// Format to 2 decimal places, then trim trailing zeros
	s := fmt.Sprintf("%.2f", f)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}
