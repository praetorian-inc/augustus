package lrl

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rateLimitMockTranslator records calls with thread-safe atomic counter for testing rate limiting.
type rateLimitMockTranslator struct {
	callCount atomic.Int32
}

func (m *rateLimitMockTranslator) Translate(ctx context.Context, text, targetLang string) (string, error) {
	m.callCount.Add(1)
	return "translated:" + text, nil
}

func TestRateLimitedTranslator_RateLimits(t *testing.T) {
	mock := &rateLimitMockTranslator{}
	// 2 tokens, 1/sec refill
	limiter := ratelimit.NewLimiter(2, 1.0)
	translator := NewRateLimitedTranslator(mock, limiter)

	ctx := context.Background()

	// First two should be immediate
	_, err := translator.Translate(ctx, "hello", "ET")
	require.NoError(t, err)
	_, err = translator.Translate(ctx, "world", "ET")
	require.NoError(t, err)

	// Third should wait ~1 second
	start := time.Now()
	_, err = translator.Translate(ctx, "delayed", "ET")
	duration := time.Since(start)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, duration, 900*time.Millisecond)
	assert.Equal(t, int32(3), mock.callCount.Load())
}

func TestRateLimitedTranslator_NilLimiterPassthrough(t *testing.T) {
	mock := &rateLimitMockTranslator{}
	translator := NewRateLimitedTranslator(mock, nil)

	ctx := context.Background()
	result, err := translator.Translate(ctx, "hello", "ET")

	require.NoError(t, err)
	assert.Equal(t, "translated:hello", result)
	assert.Equal(t, int32(1), mock.callCount.Load())
}

func TestRateLimitedTranslator_RespectsContext(t *testing.T) {
	mock := &rateLimitMockTranslator{}
	limiter := ratelimit.NewLimiter(1, 1.0)
	translator := NewRateLimitedTranslator(mock, limiter)

	// Exhaust token
	ctx := context.Background()
	_, err := translator.Translate(ctx, "first", "ET")
	require.NoError(t, err)

	// Cancel context
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = translator.Translate(cancelCtx, "second", "ET")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
