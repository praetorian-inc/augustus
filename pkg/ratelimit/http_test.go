package ratelimit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimitedHTTPClient_Do_RateLimits(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// 2 tokens, 1 per second refill -- third request must wait
	limiter := ratelimit.NewLimiter(2, 1.0)
	client := ratelimit.NewRateLimitedHTTPClient(&http.Client{}, limiter)

	ctx := context.Background()

	// First two requests should succeed immediately
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
	}

	// Third request should block ~1 second waiting for refill
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	resp, err := client.Do(req)
	duration := time.Since(start)

	require.NoError(t, err)
	resp.Body.Close()
	assert.GreaterOrEqual(t, duration, 900*time.Millisecond)
	assert.Equal(t, 3, requestCount)
}

func TestRateLimitedHTTPClient_Do_RespectsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	limiter := ratelimit.NewLimiter(1, 1.0)
	client := ratelimit.NewRateLimitedHTTPClient(&http.Client{}, limiter)

	// Exhaust the token
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	// Second request with cancelled context
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	req, _ = http.NewRequestWithContext(cancelCtx, "GET", server.URL, nil)
	_, err = client.Do(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRateLimitedHTTPClient_Do_NilLimiter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := ratelimit.NewRateLimitedHTTPClient(&http.Client{}, nil)

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHTTPDoerInterfaceCompatibility(t *testing.T) {
	var doer ratelimit.HTTPDoer

	// *http.Client satisfies HTTPDoer
	doer = &http.Client{}
	assert.NotNil(t, doer)

	// *RateLimitedHTTPClient satisfies HTTPDoer
	limiter := ratelimit.NewLimiter(10, 1.0)
	doer = ratelimit.NewRateLimitedHTTPClient(&http.Client{}, limiter)
	assert.NotNil(t, doer)
}
