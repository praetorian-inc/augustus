package buffs_test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test DefaultBuff function
func TestDefaultBuff(t *testing.T) {
	tests := []struct {
		name     string
		attempts []*attempt.Attempt
		want     int // expected number of results
	}{
		{
			name:     "single attempt produces single result",
			attempts: []*attempt.Attempt{{Prompt: "test"}},
			want:     1,
		},
		{
			name: "multiple attempts produce multiple results",
			attempts: []*attempt.Attempt{
				{Prompt: "test1"},
				{Prompt: "test2"},
			},
			want: 2,
		},
		{
			name:     "empty slice produces empty result",
			attempts: []*attempt.Attempt{},
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transformer := &mockBuff{name: "test", prefix: "PREFIX:"}
			result, err := buffs.DefaultBuff(context.Background(), tt.attempts, transformer)

			require.NoError(t, err)
			assert.Len(t, result, tt.want)

			// Verify transformation was applied
			for i, r := range result {
				assert.Equal(t, "PREFIX:"+tt.attempts[i].Prompt, r.Prompt)
			}
		})
	}
}

// Test DefaultBuff with context cancellation
func TestDefaultBuff_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	attempts := []*attempt.Attempt{
		{Prompt: "test1"},
		{Prompt: "test2"},
	}

	transformer := &mockBuff{name: "test", prefix: "PREFIX:"}
	result, err := buffs.DefaultBuff(ctx, attempts, transformer)

	// Should return error when context is cancelled
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
	// May have processed some attempts before cancellation
	assert.LessOrEqual(t, len(result), len(attempts))
}

// Test DefaultBuff with one-to-many transformer
func TestDefaultBuff_OneToMany(t *testing.T) {
	attempts := []*attempt.Attempt{{Prompt: "test"}}
	transformer := &mockOneToManyBuff{
		name:     "expand",
		suffixes: []string{"-A", "-B", "-C"},
	}

	result, err := buffs.DefaultBuff(context.Background(), attempts, transformer)

	require.NoError(t, err)
	// One input produces 3 outputs
	assert.Len(t, result, 3)
	assert.Equal(t, "test-A", result[0].Prompt)
	assert.Equal(t, "test-B", result[1].Prompt)
	assert.Equal(t, "test-C", result[2].Prompt)
}

// Test BuffChain.Buffs() getter
func TestBuffChain_Buffs(t *testing.T) {
	buff1 := &mockBuff{name: "A", prefix: "A:"}
	buff2 := &mockBuff{name: "B", prefix: "B:"}
	chain := buffs.NewBuffChain(buff1, buff2)

	buffs := chain.Buffs()
	require.Len(t, buffs, 2)
	assert.Equal(t, "A", buffs[0].Name())
	assert.Equal(t, "B", buffs[1].Name())
}

// Test BuffChain.Transform for empty chain
func TestBuffChain_Transform_EmptyChain(t *testing.T) {
	chain := buffs.NewBuffChain()
	a := &attempt.Attempt{Prompt: "test"}

	var results []*attempt.Attempt
	for transformed := range chain.Transform(a) {
		results = append(results, transformed)
	}

	require.Len(t, results, 1)
	assert.Equal(t, "test", results[0].Prompt)
}

// Test BuffChain.Transform with single buff
func TestBuffChain_Transform_SingleBuff(t *testing.T) {
	buff := &mockBuff{name: "prefix", prefix: "PREFIX:"}
	chain := buffs.NewBuffChain(buff)
	a := &attempt.Attempt{Prompt: "hello"}

	var results []*attempt.Attempt
	for transformed := range chain.Transform(a) {
		results = append(results, transformed)
	}

	require.Len(t, results, 1)
	assert.Equal(t, "PREFIX:hello", results[0].Prompt)
}

// Test BuffChain.Transform with multiple buffs
func TestBuffChain_Transform_MultipleBuffs(t *testing.T) {
	buff1 := &mockBuff{name: "A", prefix: "A:"}
	buff2 := &mockBuff{name: "B", prefix: "B:"}
	chain := buffs.NewBuffChain(buff1, buff2)
	a := &attempt.Attempt{Prompt: "hello"}

	var results []*attempt.Attempt
	for transformed := range chain.Transform(a) {
		results = append(results, transformed)
	}

	require.Len(t, results, 1)
	// Buffs chain: A applied first, then B
	assert.Equal(t, "B:A:hello", results[0].Prompt)
}

// Test BuffChain.Transform with one-to-many expansion
func TestBuffChain_Transform_OneToMany(t *testing.T) {
	buff := &mockOneToManyBuff{
		name:     "expand",
		suffixes: []string{"-X", "-Y"},
	}
	chain := buffs.NewBuffChain(buff)
	a := &attempt.Attempt{Prompt: "test"}

	var results []*attempt.Attempt
	for transformed := range chain.Transform(a) {
		results = append(results, transformed)
	}

	require.Len(t, results, 2)
	assert.Equal(t, "test-X", results[0].Prompt)
	assert.Equal(t, "test-Y", results[1].Prompt)
}

// Test BuffChain.Transform early break
func TestBuffChain_Transform_EarlyBreak(t *testing.T) {
	buff := &mockOneToManyBuff{
		name:     "expand",
		suffixes: []string{"-A", "-B", "-C"},
	}
	chain := buffs.NewBuffChain(buff)
	a := &attempt.Attempt{Prompt: "test"}

	var results []*attempt.Attempt
	for transformed := range chain.Transform(a) {
		results = append(results, transformed)
		if len(results) == 1 {
			break // Stop after first result
		}
	}

	// Should only get one result due to early break
	assert.Len(t, results, 1)
	assert.Equal(t, "test-A", results[0].Prompt)
}

// Test buff registry: Register, List, Get
func TestBuffRegistry_RegisterListGet(t *testing.T) {
	// Create a test buff factory
	testFactory := func(cfg registry.Config) (buffs.Buff, error) {
		return &mockBuff{name: "test-buff", prefix: "TEST:"}, nil
	}

	// Register the buff
	buffs.Register("test.TestBuff", testFactory)

	// List should include our buff
	list := buffs.List()
	assert.Contains(t, list, "test.TestBuff")

	// Get should return our factory
	factory, ok := buffs.Get("test.TestBuff")
	require.True(t, ok, "buff should be found in registry")
	assert.NotNil(t, factory)

	// Create buff using the factory
	buff, err := factory(nil)
	require.NoError(t, err)
	assert.Equal(t, "test-buff", buff.Name())
}

// Test buff registry: Get non-existent buff
func TestBuffRegistry_GetNonExistent(t *testing.T) {
	_, ok := buffs.Get("nonexistent.Buff")
	assert.False(t, ok, "non-existent buff should not be found")
}

// Test chainTransforms via BuffChain.Transform with multiple buffs
func TestBuffChain_ChainTransforms(t *testing.T) {
	// Test chaining with mixed one-to-one and one-to-many buffs
	buff1 := &mockBuff{name: "prefix", prefix: "P:"}
	buff2 := &mockOneToManyBuff{
		name:     "expand",
		suffixes: []string{"-A", "-B"},
	}
	chain := buffs.NewBuffChain(buff1, buff2)
	a := &attempt.Attempt{Prompt: "test"}

	var results []*attempt.Attempt
	for transformed := range chain.Transform(a) {
		results = append(results, transformed)
	}

	// First buff adds prefix, second buff expands to 2 variants
	require.Len(t, results, 2)
	assert.Equal(t, "P:test-A", results[0].Prompt)
	assert.Equal(t, "P:test-B", results[1].Prompt)
}
