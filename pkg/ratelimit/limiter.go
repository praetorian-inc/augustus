package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter implements a token bucket rate limiter.
// Thread-safe for concurrent use.
type Limiter struct {
	mu         sync.Mutex
	tokens     float64   // Current tokens available
	maxTokens  float64   // Maximum bucket capacity
	refillRate float64   // Tokens added per second
	lastRefill time.Time // Last time tokens were added
}

// NewLimiter creates a rate limiter with specified capacity and refill rate.
//
// Example: NewLimiter(100, 10.0) creates a limiter with:
// - 100 token capacity
// - 10 tokens per second refill rate
// - Allows bursts up to 100 requests
// - Steady state: 10 requests/sec
func NewLimiter(maxTokens, refillRate float64) *Limiter {
	return &Limiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available, respecting context cancellation.
// Returns context.Canceled or context.DeadlineExceeded if context ends.
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		l.refillLocked()

		if l.tokens >= 1.0 {
			l.tokens -= 1.0
			l.mu.Unlock()
			return nil
		}

		// Calculate wait time for next token
		tokensNeeded := 1.0 - l.tokens
		waitDuration := time.Duration(tokensNeeded / l.refillRate * float64(time.Second))
		l.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitDuration):
			// Loop to recheck after wait
		}
	}
}

// TryAcquire attempts to acquire a token without blocking.
// Returns true if token acquired, false if none available.
func (l *Limiter) TryAcquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.refillLocked()

	if l.tokens >= 1.0 {
		l.tokens -= 1.0
		return true
	}
	return false
}

// refillLocked adds tokens based on elapsed time since last refill.
// Must be called with l.mu held.
func (l *Limiter) refillLocked() {
	now := time.Now()
	elapsed := now.Sub(l.lastRefill)
	tokensToAdd := elapsed.Seconds() * l.refillRate

	l.tokens += tokensToAdd
	if l.tokens > l.maxTokens {
		l.tokens = l.maxTokens
	}

	l.lastRefill = now
}
