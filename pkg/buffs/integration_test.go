package buffs_test

import (
	"context"
	"encoding/base64"
	"iter"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBase64Buff simulates a Base64 encoding buff
type mockBase64Buff struct {
	name string
}

func (m *mockBase64Buff) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	result := make([]*attempt.Attempt, len(attempts))
	for i, a := range attempts {
		clone := *a
		clone.Prompt = base64.StdEncoding.EncodeToString([]byte(a.Prompt))
		result[i] = &clone
	}
	return result, nil
}

func (m *mockBase64Buff) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		clone := *a
		clone.Prompt = base64.StdEncoding.EncodeToString([]byte(a.Prompt))
		yield(&clone)
	}
}

func (m *mockBase64Buff) Name() string        { return m.name }
func (m *mockBase64Buff) Description() string { return "mock base64 encoder" }

// Integration test 1: Full pipeline with Base64 buff (no network)
func TestBuffIntegration_FullPipelineBase64(t *testing.T) {
	// Create a mock prober
	inner := &mockProber{
		name:    "test-prober",
		prompts: []string{"hello world"},
	}

	// Create a Base64 buff
	base64Buff := &mockBase64Buff{name: "base64"}

	chain := buffs.NewBuffChain(base64Buff)

	// Create a mock generator
	gen := &mockGenerator{responses: []string{"response"}}

	// Create buffed prober
	prober := buffs.NewBuffedProber(inner, chain, gen)

	// Execute
	attempts, err := prober.Probe(context.Background(), gen)

	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify prompt was base64 encoded
	for _, a := range attempts {
		_, err := base64.StdEncoding.DecodeString(a.Prompt)
		assert.NoError(t, err, "prompt should be valid base64: %s", a.Prompt)
	}
}

// Integration test 2: Rate limiting prevents concurrent overload
func TestBuffIntegration_RateLimitingPreventsOverload(t *testing.T) {
	// Track max concurrent requests AFTER rate limiter allows them through
	var currentConcurrent atomic.Int32
	var maxConcurrent atomic.Int32
	var totalRequests atomic.Int32

	// Create a rate limiter: 2 RPS, burst 2
	limiter := ratelimit.NewLimiter(2, 2.0)

	// Simulate 10 concurrent requests
	ctx := context.Background()
	done := make(chan struct{}, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()

			// Wait for rate limit token BEFORE incrementing counter
			err := limiter.Wait(ctx)
			if err != nil {
				return
			}

			// Now track concurrency (after rate limiter allowed us through)
			current := currentConcurrent.Add(1)
			defer currentConcurrent.Add(-1)

			// Track max concurrent
			for {
				old := maxConcurrent.Load()
				if current <= old || maxConcurrent.CompareAndSwap(old, current) {
					break
				}
			}

			// Simulate work
			time.Sleep(10 * time.Millisecond)
			totalRequests.Add(1)
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// All requests should complete
	assert.Equal(t, int32(10), totalRequests.Load(), "all requests should complete")

	// Max concurrent should be bounded by burst size (2) + some slack
	assert.LessOrEqual(t, maxConcurrent.Load(), int32(4),
		"max concurrent should be bounded by rate limiter burst")
}

// Integration test 3: BuffChain with PostBuff hooks
func TestBuffIntegration_BuffChainWithPostBuff(t *testing.T) {
	// Create a buff that modifies prompts
	prefixBuff := &mockBuff{name: "prefix", prefix: "TEST:"}

	// Create a PostBuff that untransforms outputs
	postBuff := &mockPostBuffProber{
		mockBuff: mockBuff{name: "post", prefix: "P:"},
	}

	// Chain: prefix buff -> post buff
	chain := buffs.NewBuffChain(prefixBuff, postBuff)

	// Verify chain configuration
	assert.Equal(t, 2, chain.Len())
	assert.True(t, chain.HasPostBuffHooks())

	// Apply chain to attempts
	attempts := []*attempt.Attempt{{Prompt: "hello"}}
	result, err := chain.Apply(context.Background(), attempts)

	require.NoError(t, err)
	require.Len(t, result, 1)

	// Prompt should have both prefixes applied (in order: prefix then post)
	// First buff adds "TEST:", second buff adds "P:"
	assert.Equal(t, "P:TEST:hello", result[0].Prompt)

	// Test PostBuff untransform
	result[0].Outputs = []string{"original output"}
	untransformed, err := chain.ApplyPostBuffs(context.Background(), result[0])

	require.NoError(t, err)
	assert.Equal(t, "untransformed:original output", untransformed.Outputs[0])
}

// Integration test 4: Error handling - buff creation failure
func TestBuffIntegration_BuffCreationFailure(t *testing.T) {
	// Try to create a non-existent buff
	_, err := buffs.Create("nonexistent.Buff", nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// Integration test 5: Empty buff chain is zero-overhead
func TestBuffIntegration_EmptyChainZeroOverhead(t *testing.T) {
	inner := &mockProber{name: "inner", prompts: []string{"hello"}}
	chain := buffs.NewBuffChain() // Empty chain

	result := buffs.NewBuffedProber(inner, chain, nil)

	// Should return inner directly (same pointer)
	assert.Same(t, inner, result)
}

// Integration test 6: Multiple buffs with one-to-many expansion
func TestBuffIntegration_OneToManyExpansion(t *testing.T) {
	// Create a one-to-many buff (simulates LRL)
	expandBuff := &mockOneToManyBuff{
		name:     "expand",
		suffixes: []string{"-variant1", "-variant2", "-variant3"},
	}

	chain := buffs.NewBuffChain(expandBuff)

	// Start with 2 attempts
	attempts := []*attempt.Attempt{
		{Prompt: "hello"},
		{Prompt: "world"},
	}

	result, err := chain.Apply(context.Background(), attempts)

	require.NoError(t, err)
	// 2 attempts * 3 variants = 6 attempts
	assert.Len(t, result, 6)

	// Verify expansion
	expectedPrompts := []string{
		"hello-variant1", "hello-variant2", "hello-variant3",
		"world-variant1", "world-variant2", "world-variant3",
	}
	for i, expected := range expectedPrompts {
		assert.Equal(t, expected, result[i].Prompt)
	}
}
