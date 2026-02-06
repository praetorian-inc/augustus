package packagehallucination

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// PackageChecker is an interface for checking if packages exist in a registry.
// Implementations can query PyPI, RubyGems, npm, or any other package registry.
//
// This interface enables:
//   - Dependency injection for testing
//   - Separation of HTTP concerns from detection logic
//   - Reusability across different package ecosystems
type PackageChecker interface {
	// Exists checks if a package exists in the registry.
	// Returns:
	//   - (true, nil) if package exists
	//   - (false, nil) if package doesn't exist
	//   - (false, error) if query fails (network error, etc.)
	Exists(ctx context.Context, pkg string) (bool, error)
}

// PyPIChecker implements PackageChecker for Python Package Index (PyPI).
// It makes HTTP requests to the PyPI JSON API to check package existence.
type PyPIChecker struct {
	url        string
	httpClient *http.Client
}

// NewPyPIChecker creates a new PyPIChecker with the given base URL and timeout.
//
// Parameters:
//   - url: Base URL for PyPI API (e.g., "https://pypi.org")
//   - timeout: HTTP request timeout duration
//
// Example:
//
//	checker := NewPyPIChecker("https://pypi.org", 10*time.Second)
//	exists, err := checker.Exists(ctx, "requests")
func NewPyPIChecker(url string, timeout time.Duration) *PyPIChecker {
	return &PyPIChecker{
		url: url,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Exists checks if a package exists on PyPI by querying the JSON API.
// Returns true if the package exists (HTTP 200), false if not found (HTTP 404).
func (c *PyPIChecker) Exists(ctx context.Context, pkg string) (bool, error) {
	url := fmt.Sprintf("%s/pypi/%s/json", c.url, pkg)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("pypi request: %w", err)
	}
	defer resp.Body.Close()

	// 200 = exists, 404 = doesn't exist, other = error
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

// CachedChecker wraps any PackageChecker and adds caching to reduce network calls.
// Thread-safe for concurrent access.
type CachedChecker struct {
	checker PackageChecker
	cache   *packageCache
}

// NewCachedChecker creates a new CachedChecker that wraps the given checker.
//
// The cache is shared across all calls, so repeated queries for the same
// package will only hit the underlying checker once.
//
// Example:
//
//	pypi := NewPyPIChecker("https://pypi.org", 10*time.Second)
//	cached := NewCachedChecker(pypi)
//	// First call hits PyPI, subsequent calls use cache
//	exists, err := cached.Exists(ctx, "requests")
func NewCachedChecker(checker PackageChecker) *CachedChecker {
	return &CachedChecker{
		checker: checker,
		cache:   newPackageCache(),
	}
}

// Exists checks if a package exists, using cache if available.
// Only queries the underlying checker if the result is not cached.
// Errors are NOT cached, so transient failures can be retried.
func (c *CachedChecker) Exists(ctx context.Context, pkg string) (bool, error) {
	// Check cache first
	if exists, found := c.cache.Get(pkg); found {
		return exists, nil
	}

	// Query underlying checker
	exists, err := c.checker.Exists(ctx, pkg)
	if err != nil {
		// Don't cache errors - allow retry
		return false, err
	}

	// Cache the result (both true and false)
	c.cache.Set(pkg, exists)
	return exists, nil
}
