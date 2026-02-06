package lrl

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/ratelimit"
)

// Default rate limit constants for DeepL API.
const (
	DefaultDeepLRateLimit = 5.0  // requests per second
	DefaultDeepLBurstSize = 20.0 // max burst capacity
)

// rateLimitedTranslator wraps a Translator with token bucket rate limiting.
type rateLimitedTranslator struct {
	inner   Translator
	limiter *ratelimit.Limiter
}

// NewRateLimitedTranslator wraps a Translator with rate limiting.
// If limiter is nil, calls pass through without rate limiting.
func NewRateLimitedTranslator(inner Translator, limiter *ratelimit.Limiter) Translator {
	if limiter == nil {
		return inner
	}
	return &rateLimitedTranslator{inner: inner, limiter: limiter}
}

// Translate rate-limits and then delegates to the inner translator.
func (t *rateLimitedTranslator) Translate(ctx context.Context, text, targetLang string) (string, error) {
	if err := t.limiter.Wait(ctx); err != nil {
		return "", fmt.Errorf("rate limit wait: %w", err)
	}
	return t.inner.Translate(ctx, text, targetLang)
}
