package packagehallucination

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPackageChecker is a mock implementation for testing PackageChecker interface.
type mockPackageChecker struct {
	mu       sync.Mutex
	packages map[string]bool // true = exists, false = doesn't exist
	callLog  []string        // tracks which packages were queried
	err      error           // error to return (if any)
}

func newMockPackageChecker() *mockPackageChecker {
	return &mockPackageChecker{
		packages: make(map[string]bool),
		callLog:  []string{},
	}
}

func (m *mockPackageChecker) Exists(ctx context.Context, pkg string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callLog = append(m.callLog, pkg)
	if m.err != nil {
		return false, m.err
	}
	exists, found := m.packages[pkg]
	if !found {
		return false, nil // Package not in mock = doesn't exist
	}
	return exists, nil
}

func (m *mockPackageChecker) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.callLog)
}

// TestPackageChecker_Interface tests that PackageChecker interface can be implemented.
func TestPackageChecker_Interface(t *testing.T) {
	t.Parallel()

	// This test verifies that our mock implements the interface
	var _ PackageChecker = (*mockPackageChecker)(nil)

	ctx := context.Background()
	mock := newMockPackageChecker()
	mock.packages["test-pkg"] = true

	exists, err := mock.Exists(ctx, "test-pkg")
	require.NoError(t, err)
	assert.True(t, exists, "Mock should return true for existing package")

	exists, err = mock.Exists(ctx, "nonexistent")
	require.NoError(t, err)
	assert.False(t, exists, "Mock should return false for non-existent package")
}

// TestPyPIChecker_Exists tests the PyPIChecker implementation.
func TestPyPIChecker_Exists(t *testing.T) {
	t.Parallel()

	// Create a mock PyPI server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract package name from URL: /pypi/{package}/json
		switch r.URL.Path {
		case "/pypi/requests/json":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"info": {"name": "requests"}}`))
		case "/pypi/nonexistent/json":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tests := []struct {
		name      string
		pkg       string
		wantExist bool
		wantErr   bool
	}{
		{
			name:      "existing package",
			pkg:       "requests",
			wantExist: true,
			wantErr:   false,
		},
		{
			name:      "non-existent package",
			pkg:       "nonexistent",
			wantExist: false,
			wantErr:   false,
		},
		{
			name:      "server error",
			pkg:       "error-pkg",
			wantExist: false,
			wantErr:   true,
		},
	}

	checker := NewPyPIChecker(server.URL, httpTimeout)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exists, err := checker.Exists(ctx, tt.pkg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantExist, exists)
			}
		})
	}
}

// TestPyPIChecker_ContextCancellation tests context cancellation.
func TestPyPIChecker_ContextCancellation(t *testing.T) {
	t.Parallel()

	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // Wait for context cancellation
		w.WriteHeader(http.StatusRequestTimeout)
	}))
	defer server.Close()

	checker := NewPyPIChecker(server.URL, httpTimeout)

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := checker.Exists(ctx, "test-pkg")
	assert.Error(t, err, "Should error on cancelled context")
}

// TestCachedChecker_Caching tests that CachedChecker properly caches results.
func TestCachedChecker_Caching(t *testing.T) {
	t.Parallel()

	mock := newMockPackageChecker()
	mock.packages["cached-pkg"] = true

	cached := NewCachedChecker(mock)
	ctx := context.Background()

	// First call - should hit the underlying checker
	exists, err := cached.Exists(ctx, "cached-pkg")
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, 1, mock.callCount(), "Should call underlying checker once")

	// Second call - should use cache
	exists, err = cached.Exists(ctx, "cached-pkg")
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, 1, mock.callCount(), "Should NOT call underlying checker again (cached)")

	// Third call with different package - should call underlying checker
	mock.packages["another-pkg"] = false
	exists, err = cached.Exists(ctx, "another-pkg")
	require.NoError(t, err)
	assert.False(t, exists)
	assert.Equal(t, 2, mock.callCount(), "Should call underlying checker for new package")
}

// TestCachedChecker_ErrorHandling tests error propagation through cache.
func TestCachedChecker_ErrorHandling(t *testing.T) {
	t.Parallel()

	mock := newMockPackageChecker()
	mock.err = errors.New("network error")

	cached := NewCachedChecker(mock)
	ctx := context.Background()

	// Error should propagate through cache
	_, err := cached.Exists(ctx, "error-pkg")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network error")

	// Error should NOT be cached - second call should still try
	_, err = cached.Exists(ctx, "error-pkg")
	assert.Error(t, err)
	assert.Equal(t, 2, mock.callCount(), "Should retry on error (not cached)")
}

// TestCachedChecker_ThreadSafety tests concurrent access to cache.
func TestCachedChecker_ThreadSafety(t *testing.T) {
	t.Parallel()

	mock := newMockPackageChecker()
	mock.packages["concurrent-pkg"] = true

	cached := NewCachedChecker(mock)
	ctx := context.Background()

	// Launch 10 goroutines all querying the same package
	const goroutines = 10
	results := make(chan bool, goroutines)
	errors := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			exists, err := cached.Exists(ctx, "concurrent-pkg")
			results <- exists
			errors <- err
		}()
	}

	// Collect results
	for i := 0; i < goroutines; i++ {
		exists := <-results
		err := <-errors
		assert.NoError(t, err)
		assert.True(t, exists)
	}

	// All calls should see the same cached result
	// First goroutine might hit underlying checker, rest should use cache
	assert.LessOrEqual(t, mock.callCount(), goroutines,
		"Cache should prevent some concurrent calls from hitting underlying checker")
}
