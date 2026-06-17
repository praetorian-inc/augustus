---
title: Rate Limiting & Retry
aliases: ["Rate Limiting"]
tags: [augustus, concept, infrastructure]
type: concept
status: complete
---

# Rate Limiting & Retry

Scans fan out thousands of API calls across [[Generators|generators]], LLM judges, and translation/paraphrase [[Buffs|buffs]]. Two shared utilities keep this from overwhelming providers or failing on transient errors.

## Rate Limiting — Token Bucket

`pkg/ratelimit/` provides a thread-safe **token-bucket** `Limiter`:

```go
NewLimiter(maxTokens, refillRate float64)
// e.g. NewLimiter(100, 10.0):
//   - 100-token capacity  -> bursts up to 100 requests
//   - 10 tokens/sec refill -> steady state 10 req/s
```

Tokens refill continuously at `refillRate`; each request consumes one. `Wait` blocks (respecting `context`) until a token is available, while `TryAcquire` is non-blocking. `RateLimitedHTTPClient` (`pkg/ratelimit/http.go`) wraps an `HTTPDoer` so any HTTP-based generator or buff gets limiting transparently — used by REST generators and the LRL/paraphrase buffs.

## Retry — Exponential Backoff with Jitter

`pkg/retry/` provides `Do(ctx, cfg, fn)` for transient failures:

```go
type Config struct {
    MaxAttempts int      // including the initial attempt
    // ... base delay, max delay
    Jitter float64       // 0.0–1.0 randomness added to each delay
    RetryableFunc func(error) bool
}
```

Delays grow exponentially between attempts; `Jitter` adds randomness to avoid thundering-herd retries. `RetryableFunc` decides which errors are worth retrying — for example, the [[Attack Engine (PAIR & TAP)]] retries only when the attacker LLM returns empty or invalid JSON (`errRetryableAttack`), capped by `AttackMaxAttempts`. The loop also exits on context cancellation.

## Where They Show Up

- HTTP generators and translation/paraphrase buffs wrap transport in `RateLimitedHTTPClient`.
- Provider calls and JSON-parse loops use `retry.Do` for resilience.
- Concurrency itself is bounded separately by the [[Scanner]] / harness `errgroup` (default 10).

## Related

- [[Generators]] · [[Buffs]] · [[Harnesses]]
- [[Concepts MOC]] · [[Home]]
