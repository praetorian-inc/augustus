package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrometheusExporter_Export(t *testing.T) {
	// Arrange: Create metrics with known values
	m := &Metrics{
		ProbesTotal:     100,
		ProbesSucceeded: 85,
		ProbesFailed:    15,
		AttemptsTotal:   500,
		AttemptsVuln:    75,
	}

	exporter := NewPrometheusExporter(m)

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
	m := &Metrics{
		ProbesTotal:     42,
		ProbesSucceeded: 40,
		ProbesFailed:    2,
		AttemptsTotal:   200,
		AttemptsVuln:    30,
	}

	exporter := NewPrometheusExporter(m)

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
			m := &Metrics{
				AttemptsTotal: tt.attemptsTotal,
				AttemptsVuln:  tt.attemptsVuln,
			}

			exporter := NewPrometheusExporter(m)
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
