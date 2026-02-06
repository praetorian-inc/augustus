package scanner

import (
	"time"

	"github.com/praetorian-inc/augustus/pkg/metrics"
)

// Options configures the scanner's behavior.
type Options struct {
	// Concurrency is the maximum number of probes to execute in parallel.
	Concurrency int

	// Timeout is the overall timeout for all probe executions.
	Timeout time.Duration

	// ProbeTimeout is the maximum time allowed for a single probe execution.
	ProbeTimeout time.Duration

	// RetryCount is the number of times to retry failed probes.
	RetryCount int

	// RetryBackoff is the delay between retry attempts.
	RetryBackoff time.Duration

	// Metrics is the optional metrics tracker for scan statistics.
	// If nil, metrics tracking is disabled.
	Metrics *metrics.Metrics
}

// DefaultOptions returns scanner options with sensible defaults.
func DefaultOptions() Options {
	return Options{
		Concurrency:  10,
		Timeout:      30 * time.Minute,
		ProbeTimeout: 5 * time.Minute,
		RetryCount:   0,
		RetryBackoff: 1 * time.Second,
	}
}
