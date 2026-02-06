package buffs_test

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProber for testing
type mockProber struct {
	name     string
	prompts  []string
	attempts []*attempt.Attempt
	err      error
}

func (m *mockProber) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.attempts != nil {
		return m.attempts, nil
	}
	result := make([]*attempt.Attempt, len(m.prompts))
	for i, p := range m.prompts {
		result[i] = &attempt.Attempt{Prompt: p, Outputs: []string{"response"}}
	}
	return result, nil
}

func (m *mockProber) Name() string              { return m.name }
func (m *mockProber) Description() string       { return "mock prober" }
func (m *mockProber) Goal() string              { return "test goal" }
func (m *mockProber) GetPrimaryDetector() string { return "" }
func (m *mockProber) GetPrompts() []string      { return m.prompts }

// mockGenerator for testing
type mockGenerator struct {
	responses []string
	callCount int
	err       error
	errors    []error // Error sequence for each call
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	idx := m.callCount
	m.callCount++

	// Check if we have a specific error for this call
	if len(m.errors) > idx && m.errors[idx] != nil {
		return nil, m.errors[idx]
	}

	if m.err != nil {
		return nil, m.err
	}
	response := "generated"
	if idx < len(m.responses) {
		response = m.responses[idx]
	}
	return []attempt.Message{{Content: response, Role: "assistant"}}, nil
}

func (m *mockGenerator) ClearHistory()        {}
func (m *mockGenerator) Name() string         { return "mock" }
func (m *mockGenerator) Description() string  { return "mock generator" }

// mockPostBuffProber implements PostBuff
type mockPostBuffProber struct {
	mockBuff
}

func (m *mockPostBuffProber) HasPostBuffHook() bool { return true }
func (m *mockPostBuffProber) Untransform(ctx context.Context, a *attempt.Attempt) (*attempt.Attempt, error) {
	clone := *a
	if len(clone.Outputs) > 0 {
		clone.Outputs[0] = "untransformed:" + clone.Outputs[0]
	}
	return &clone, nil
}

// mockErrorPostBuff implements PostBuff but returns error
type mockErrorPostBuff struct {
	mockBuff
	err error
}

func (m *mockErrorPostBuff) HasPostBuffHook() bool { return true }
func (m *mockErrorPostBuff) Untransform(ctx context.Context, a *attempt.Attempt) (*attempt.Attempt, error) {
	return nil, m.err
}

// Test 1: Nil/empty chain returns inner prober directly
func TestBuffedProber_NilChain(t *testing.T) {
	inner := &mockProber{name: "test", prompts: []string{"hello"}}
	result := buffs.NewBuffedProber(inner, nil, nil)

	// Should return inner directly (zero overhead)
	assert.Equal(t, inner, result)
}

func TestBuffedProber_EmptyChain(t *testing.T) {
	inner := &mockProber{name: "test", prompts: []string{"hello"}}
	chain := buffs.NewBuffChain() // empty
	result := buffs.NewBuffedProber(inner, chain, nil)

	// Should return inner directly
	assert.Equal(t, inner, result)
}

// Test 2: Simple buff transforms prompt and re-generates
func TestBuffedProber_SimpleBuff(t *testing.T) {
	inner := &mockProber{
		name:    "test",
		prompts: []string{"hello"},
	}
	buff := &mockBuff{name: "prefix", prefix: "PREFIX:"}
	chain := buffs.NewBuffChain(buff)
	gen := &mockGenerator{responses: []string{"new response"}}

	prober := buffs.NewBuffedProber(inner, chain, gen)
	attempts, err := prober.Probe(context.Background(), gen)

	require.NoError(t, err)
	require.Len(t, attempts, 1)
	assert.Equal(t, "PREFIX:hello", attempts[0].Prompt)
	// Should have re-generated with the buffed prompt
	assert.Equal(t, 1, gen.callCount)
	assert.Equal(t, "new response", attempts[0].Outputs[0])
}

// Test 3: One-to-many buff produces multiple attempts
func TestBuffedProber_OneToMany(t *testing.T) {
	inner := &mockProber{
		name:    "test",
		prompts: []string{"hello"},
	}
	buff := &mockOneToManyBuff{name: "expand", suffixes: []string{"-A", "-B", "-C"}}
	chain := buffs.NewBuffChain(buff)
	gen := &mockGenerator{responses: []string{"resp-A", "resp-B", "resp-C"}}

	prober := buffs.NewBuffedProber(inner, chain, gen)
	attempts, err := prober.Probe(context.Background(), gen)

	require.NoError(t, err)
	require.Len(t, attempts, 3)
	assert.Equal(t, "hello-A", attempts[0].Prompt)
	assert.Equal(t, "hello-B", attempts[1].Prompt)
	assert.Equal(t, "hello-C", attempts[2].Prompt)
	assert.Equal(t, 3, gen.callCount) // Each variant gets generated
	assert.Equal(t, "resp-A", attempts[0].Outputs[0])
	assert.Equal(t, "resp-B", attempts[1].Outputs[0])
	assert.Equal(t, "resp-C", attempts[2].Outputs[0])
}

// Test 4: PostBuff hook is applied to generated responses
func TestBuffedProber_PostBuffHook(t *testing.T) {
	inner := &mockProber{
		name:    "test",
		prompts: []string{"hello"},
	}
	postBuff := &mockPostBuffProber{mockBuff: mockBuff{name: "post", prefix: "P:"}}
	chain := buffs.NewBuffChain(postBuff)
	gen := &mockGenerator{responses: []string{"original"}}

	prober := buffs.NewBuffedProber(inner, chain, gen)
	attempts, err := prober.Probe(context.Background(), gen)

	require.NoError(t, err)
	require.Len(t, attempts, 1)
	// PostBuff should have transformed the output
	assert.Equal(t, "untransformed:original", attempts[0].Outputs[0])
}

// Test 5: Generation error sets attempt error state (partial failure)
func TestBuffedProber_GenerationError(t *testing.T) {
	inner := &mockProber{
		name:    "test",
		prompts: []string{"hello"},
	}
	buff := &mockOneToManyBuff{name: "expand", suffixes: []string{"-A", "-B"}}
	chain := buffs.NewBuffChain(buff)

	// Generator succeeds on first call, fails on second
	gen := &mockGenerator{
		responses: []string{"ok", "never used"},
		errors:    []error{nil, errors.New("generation failed")},
	}

	prober := buffs.NewBuffedProber(inner, chain, gen)
	attempts, err := prober.Probe(context.Background(), gen)

	// Should NOT fail completely - partial results returned
	require.NoError(t, err)
	require.Len(t, attempts, 2)
	// First attempt succeeded
	assert.Empty(t, attempts[0].Error)
	assert.Equal(t, "ok", attempts[0].Outputs[0])
	// Second attempt has error recorded
	assert.NotEmpty(t, attempts[1].Error)
	assert.Equal(t, "generation failed", attempts[1].Error)
}

// Test 6: PostBuff error causes probe to fail completely
func TestBuffedProber_PostBuffError(t *testing.T) {
	inner := &mockProber{
		name:    "test",
		prompts: []string{"hello"},
	}
	postBuff := &mockErrorPostBuff{
		mockBuff: mockBuff{name: "error-post", prefix: "PREFIX:"}, // Add prefix so prompt changes
		err:      errors.New("untransform failed"),
	}
	chain := buffs.NewBuffChain(postBuff)
	gen := &mockGenerator{responses: []string{"response"}}

	prober := buffs.NewBuffedProber(inner, chain, gen)
	_, err := prober.Probe(context.Background(), gen)

	// PostBuff error is fatal - probe fails
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post-buff failed")
}

// Test 7: Delegated methods pass through
func TestBuffedProber_DelegatedMethods(t *testing.T) {
	inner := &mockProber{
		name:    "inner-probe",
		prompts: []string{"hello", "world"},
	}
	buff := &mockBuff{name: "buff", prefix: "B:"}
	chain := buffs.NewBuffChain(buff)

	prober := buffs.NewBuffedProber(inner, chain, nil)

	// These should delegate to inner
	assert.Equal(t, "inner-probe", prober.Name())
	assert.Equal(t, "mock prober", prober.Description())
	assert.Equal(t, "test goal", prober.Goal())
	assert.Equal(t, "", prober.GetPrimaryDetector())
	assert.Equal(t, []string{"hello", "world"}, prober.GetPrompts())
}
