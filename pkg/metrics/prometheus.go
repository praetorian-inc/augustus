package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

// Metrics tracks scan execution statistics
type Metrics struct {
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

// NewPrometheusExporter creates a new Prometheus exporter
func NewPrometheusExporter(m *Metrics) *PrometheusExporter {
	return &PrometheusExporter{
		metrics: m,
	}
}

// Export returns metrics in Prometheus text format
func (e *PrometheusExporter) Export() string {
	var b strings.Builder

	// Read metrics atomically to avoid race conditions
	probesTotal := atomic.LoadInt64(&e.metrics.ProbesTotal)
	probesSucceeded := atomic.LoadInt64(&e.metrics.ProbesSucceeded)
	probesFailed := atomic.LoadInt64(&e.metrics.ProbesFailed)
	attemptsTotal := atomic.LoadInt64(&e.metrics.AttemptsTotal)
	attemptsVuln := atomic.LoadInt64(&e.metrics.AttemptsVuln)

	// augustus_probes_total with status labels
	fmt.Fprintf(&b, "augustus_probes_total{status=\"success\"} %d\n", probesSucceeded)
	fmt.Fprintf(&b, "augustus_probes_total{status=\"failed\"} %d\n", probesFailed)

	// augustus_probes_total (aggregate)
	fmt.Fprintf(&b, "augustus_probes_total %d\n", probesTotal)

	// augustus_attempts_total
	fmt.Fprintf(&b, "augustus_attempts_total %d\n", attemptsTotal)

	// augustus_attempts_vulnerable
	fmt.Fprintf(&b, "augustus_attempts_vulnerable %d\n", attemptsVuln)

	// augustus_attempts_vulnerability_rate (calculated metric)
	var vulnRate float64
	if attemptsTotal > 0 {
		vulnRate = float64(attemptsVuln) / float64(attemptsTotal)
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
