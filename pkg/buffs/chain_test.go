package buffs_test

import (
	"context"
	"errors"
	"iter"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBuff for testing - transforms prompt by adding prefix
type mockBuff struct {
	name   string
	prefix string
}

func (m *mockBuff) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	result := make([]*attempt.Attempt, len(attempts))
	for i, a := range attempts {
		clone := *a
		clone.Prompt = m.prefix + a.Prompt
		result[i] = &clone
	}
	return result, nil
}

func (m *mockBuff) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		clone := *a
		clone.Prompt = m.prefix + a.Prompt
		yield(&clone)
	}
}

func (m *mockBuff) Name() string        { return m.name }
func (m *mockBuff) Description() string { return "mock buff" }

// mockOneToManyBuff produces N attempts per input (like LRL)
type mockOneToManyBuff struct {
	name     string
	suffixes []string
}

func (m *mockOneToManyBuff) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	var result []*attempt.Attempt
	for _, a := range attempts {
		for _, suffix := range m.suffixes {
			clone := *a
			clone.Prompt = a.Prompt + suffix
			result = append(result, &clone)
		}
	}
	return result, nil
}

func (m *mockOneToManyBuff) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		for _, suffix := range m.suffixes {
			clone := *a
			clone.Prompt = a.Prompt + suffix
			if !yield(&clone) {
				return
			}
		}
	}
}

func (m *mockOneToManyBuff) Name() string        { return m.name }
func (m *mockOneToManyBuff) Description() string { return "one-to-many mock" }

// mockErrorBuff returns an error
type mockErrorBuff struct {
	name string
	err  error
}

func (m *mockErrorBuff) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	return nil, m.err
}

func (m *mockErrorBuff) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {}
}

func (m *mockErrorBuff) Name() string        { return m.name }
func (m *mockErrorBuff) Description() string { return "error mock" }

// Note: mockPostBuff is already defined in buff_test.go, reusing it here

// Test 1: Empty chain passes through
func TestBuffChain_EmptyChain(t *testing.T) {
	chain := buffs.NewBuffChain()

	assert.True(t, chain.IsEmpty())
	assert.Equal(t, 0, chain.Len())

	attempts := []*attempt.Attempt{{Prompt: "test"}}
	result, err := chain.Apply(context.Background(), attempts)

	require.NoError(t, err)
	assert.Equal(t, attempts, result)
}

// Test 2: Single buff transforms
func TestBuffChain_SingleBuff(t *testing.T) {
	buff := &mockBuff{name: "prefix", prefix: "PREFIX:"}
	chain := buffs.NewBuffChain(buff)

	assert.False(t, chain.IsEmpty())
	assert.Equal(t, 1, chain.Len())

	attempts := []*attempt.Attempt{{Prompt: "hello"}}
	result, err := chain.Apply(context.Background(), attempts)

	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "PREFIX:hello", result[0].Prompt)
}

// Test 3: Multiple buffs chain sequentially
func TestBuffChain_MultipleBuffs(t *testing.T) {
	buff1 := &mockBuff{name: "A", prefix: "A:"}
	buff2 := &mockBuff{name: "B", prefix: "B:"}
	chain := buffs.NewBuffChain(buff1, buff2)

	attempts := []*attempt.Attempt{{Prompt: "hello"}}
	result, err := chain.Apply(context.Background(), attempts)

	require.NoError(t, err)
	require.Len(t, result, 1)
	// Buffs chain: A applied first, then B
	assert.Equal(t, "B:A:hello", result[0].Prompt)
}

// Test 4: One-to-many buff expands
func TestBuffChain_OneToMany(t *testing.T) {
	buff := &mockOneToManyBuff{name: "languages", suffixes: []string{"-EN", "-FR", "-DE"}}
	chain := buffs.NewBuffChain(buff)

	attempts := []*attempt.Attempt{{Prompt: "hello"}}
	result, err := chain.Apply(context.Background(), attempts)

	require.NoError(t, err)
	require.Len(t, result, 3)
	assert.Equal(t, "hello-EN", result[0].Prompt)
	assert.Equal(t, "hello-FR", result[1].Prompt)
	assert.Equal(t, "hello-DE", result[2].Prompt)
}

// Test 5: PostBuff hooks are applied
func TestBuffChain_PostBuffHooks(t *testing.T) {
	postBuff := &mockPostBuff{name: "post"}
	chain := buffs.NewBuffChain(postBuff)

	assert.True(t, chain.HasPostBuffHooks())

	a := &attempt.Attempt{Prompt: "test", Outputs: []string{"output"}}
	result, err := chain.ApplyPostBuffs(context.Background(), a)

	require.NoError(t, err)
	assert.Equal(t, []string{"untransformed"}, result.Outputs)
}

// Test 6: HasPostBuffHooks returns false when no PostBuffs
func TestBuffChain_NoPostBuffHooks(t *testing.T) {
	buff := &mockBuff{name: "simple", prefix: "S:"}
	chain := buffs.NewBuffChain(buff)

	assert.False(t, chain.HasPostBuffHooks())
}

// Test 7: Error propagation
func TestBuffChain_ErrorPropagation(t *testing.T) {
	expectedErr := errors.New("buff failed")
	errBuff := &mockErrorBuff{name: "error", err: expectedErr}
	chain := buffs.NewBuffChain(errBuff)

	attempts := []*attempt.Attempt{{Prompt: "test"}}
	_, err := chain.Apply(context.Background(), attempts)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "buff error failed")
	assert.ErrorIs(t, err, expectedErr)
}
