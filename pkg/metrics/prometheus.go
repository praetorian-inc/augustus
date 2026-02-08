package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// Metrics tracks scan execution statistics.
// Access to these fields must be protected by the caller's mutex.
type Metrics struct {
	ProbesTotal     int64
	ProbesSucceeded int64
	ProbesFailed    int64
	AttemptsTotal   int64
	AttemptsVuln    int64
	TokensConsumed  int64
}

// Snapshot returns a copy of the metrics with thread-safe access.
// The caller must hold a mutex protecting the Metrics instance.
func (m *Metrics) Snapshot(mu *sync.Mutex) MetricsSnapshot {
	mu.Lock()
	defer mu.Unlock()

	return MetricsSnapshot{
		ProbesTotal:     m.ProbesTotal,
		ProbesSucceeded: m.ProbesSucceeded,
		ProbesFailed:    m.ProbesFailed,
		AttemptsTotal:   m.AttemptsTotal,
		AttemptsVuln:    m.AttemptsVuln,
		TokensConsumed:  m.TokensConsumed,
	}
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
	mu      *sync.Mutex
}

// NewPrometheusExporter creates a new Prometheus exporter.
// The provided mutex must be the same mutex used to protect metrics updates.
func NewPrometheusExporter(m *Metrics, mu *sync.Mutex) *PrometheusExporter {
	return &PrometheusExporter{
		metrics: m,
		mu:      mu,
	}
}

// Export returns metrics in Prometheus text format
func (e *PrometheusExporter) Export() string {
	// Get a thread-safe snapshot of metrics
	snapshot := e.metrics.Snapshot(e.mu)

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
		fmt.Fprint(w, e.Export())
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
