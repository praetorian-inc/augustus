package base

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTriggerMatchDetector_Contains_Match(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchContains, "test.Contains", "test")

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []string{"secret"})
	a.AddOutput("The secret is here")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0])
}

func TestTriggerMatchDetector_Contains_NoMatch(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchContains, "test.Contains", "test")

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []string{"secret"})
	a.AddOutput("Nothing to see here")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0])
}

func TestTriggerMatchDetector_Contains_CaseInsensitive(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchContains, "test.Contains", "test")

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []string{"SECRET"})
	a.AddOutput("the secret is out")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0], "should match case-insensitively by default")
}

func TestTriggerMatchDetector_Contains_CaseSensitive(t *testing.T) {
	d := NewTriggerMatchDetector(
		registry.Config{"case_sensitive": true},
		MatchContains, "test.Contains", "test",
	)

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []string{"SECRET"})
	a.AddOutput("the secret is out")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0], "should not match when case-sensitive")
}

func TestTriggerMatchDetector_Contains_MultipleTriggers(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchContains, "test.Contains", "test")

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []string{"alpha", "beta", "gamma"})
	a.AddOutput("only beta here")
	a.AddOutput("no triggers")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 2)
	assert.Equal(t, 1.0, scores[0], "should match 'beta'")
	assert.Equal(t, 0.0, scores[1], "should not match any trigger")
}

func TestTriggerMatchDetector_Contains_NoTriggers(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchContains, "test.Contains", "test")

	a := attempt.New("test prompt")
	// No triggers set
	a.AddOutput("some output")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Empty(t, scores, "should return empty scores when no triggers")
}

func TestTriggerMatchDetector_Contains_InvalidTriggerType(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchContains, "test.Contains", "test")

	a := attempt.New("test prompt")
	a.Metadata["triggers"] = 123
	a.AddOutput("some output")

	_, err := d.Detect(context.Background(), a)
	assert.Error(t, err, "should error on invalid trigger type")
}

func TestTriggerMatchDetector_StartsWith_Match(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchStartsWith, "test.StartsWith", "test")

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []string{"Hello"})
	a.AddOutput("Hello world")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0])
}

func TestTriggerMatchDetector_StartsWith_NoMatch(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchStartsWith, "test.StartsWith", "test")

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []string{"Hello"})
	a.AddOutput("World Hello")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0], "should not match when trigger is not at start")
}

func TestTriggerMatchDetector_StartsWith_TrimsWhitespace(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchStartsWith, "test.StartsWith", "test")

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []string{"Hello"})
	a.AddOutput("   Hello world")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0], "should trim whitespace before matching prefix")
}

func TestTriggerMatchDetector_StartsWith_CaseInsensitive(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchStartsWith, "test.StartsWith", "test")

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []string{"HELLO"})
	a.AddOutput("hello world")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0], "should match case-insensitively")
}

func TestTriggerMatchDetector_NameAndDescription(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchContains, "my.Detector", "my description")
	assert.Equal(t, "my.Detector", d.Name())
	assert.Equal(t, "my description", d.Description())
}

func TestTriggerMatchDetector_MultipleOutputs(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchContains, "test.Contains", "test")

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []string{"secret"})
	a.AddOutput("no match")
	a.AddOutput("the secret is here")
	a.AddOutput("")
	a.AddOutput("another secret output")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 4)
	assert.Equal(t, 0.0, scores[0])
	assert.Equal(t, 1.0, scores[1])
	assert.Equal(t, 0.0, scores[2])
	assert.Equal(t, 1.0, scores[3])
}

func TestTriggerMatchDetector_TriggersAsAnySlice(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchContains, "test.Contains", "test")

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []any{"secret"})
	a.AddOutput("the secret is here")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0])
}

func TestTriggerMatchDetector_SingleStringTrigger(t *testing.T) {
	d := NewTriggerMatchDetector(registry.Config{}, MatchContains, "test.Contains", "test")

	a := attempt.New("test prompt")
	a.Metadata["triggers"] = "secret"
	a.AddOutput("the secret is here")

	scores, err := d.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0])
}
