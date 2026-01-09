package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLimiter_Wait_AllowsWithinRate(t *testing.T) {
	// Token bucket: 10 tokens, refill 5 per second
	limiter := NewLimiter(10, 5.0)

	ctx := context.Background()

	// Should allow first 10 without waiting
	for i := 0; i < 10; i++ {
		err := limiter.Wait(ctx)
		require.NoError(t, err)
	}
}

func TestLimiter_Wait_BlocksWhenExhausted(t *testing.T) {
	// Token bucket: 2 tokens, refill 1 per second
	limiter := NewLimiter(2, 1.0)

	ctx := context.Background()

	// Exhaust tokens
	require.NoError(t, limiter.Wait(ctx))
	require.NoError(t, limiter.Wait(ctx))

	// Third call should wait ~1 second for refill
	start := time.Now()
	err := limiter.Wait(ctx)
	duration := time.Since(start)

	require.NoError(t, err)
	require.GreaterOrEqual(t, duration, 900*time.Millisecond)
}

func TestLimiter_Wait_RespectsContext(t *testing.T) {
	limiter := NewLimiter(1, 1.0)

	// Exhaust token
	require.NoError(t, limiter.Wait(context.Background()))

	// Cancel context while waiting
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := limiter.Wait(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

func TestLimiter_TryAcquire_NonBlocking(t *testing.T) {
	limiter := NewLimiter(2, 1.0)

	// First two should succeed
	require.True(t, limiter.TryAcquire())
	require.True(t, limiter.TryAcquire())

	// Third should fail (no wait)
	require.False(t, limiter.TryAcquire())
}
