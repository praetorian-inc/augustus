package ratelimit

import "net/http"

// HTTPDoer is an interface for making HTTP requests.
// Both *http.Client and *RateLimitedHTTPClient satisfy this interface.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// RateLimitedHTTPClient wraps an HTTPDoer with token bucket rate limiting.
type RateLimitedHTTPClient struct {
	inner   HTTPDoer
	limiter *Limiter
}

// NewRateLimitedHTTPClient wraps an existing HTTPDoer with rate limiting.
// If limiter is nil, requests pass through without rate limiting.
func NewRateLimitedHTTPClient(inner HTTPDoer, limiter *Limiter) *RateLimitedHTTPClient {
	return &RateLimitedHTTPClient{
		inner:   inner,
		limiter: limiter,
	}
}

// Do executes an HTTP request, blocking until a rate limit token is available.
func (c *RateLimitedHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}
	return c.inner.Do(req)
}
