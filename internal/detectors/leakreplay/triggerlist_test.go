package leakreplay

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTriggerListDetector_MatchesTrigger(t *testing.T) {
	// Create detector
	detector, err := NewTriggerListDetector(registry.Config{})
	require.NoError(t, err)

	// Create attempt with trigger in metadata and matching output
	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []any{"Harry"})
	a.AddOutput("Harry Potter is a wizard")
	a.Complete()

	// Detect
	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0], "should match trigger 'Harry' in output")
}

func TestTriggerListDetector_NoMatch(t *testing.T) {
	detector, err := NewTriggerListDetector(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []any{"Hermione"})
	a.AddOutput("Ron Weasley is a wizard")
	a.Complete()

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0], "should not match trigger 'Hermione'")
}

func TestTriggerListDetector_CaseInsensitive(t *testing.T) {
	detector, err := NewTriggerListDetector(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	a.WithMetadata("triggers", []any{"HARRY"})
	a.AddOutput("harry potter is a wizard")
	a.Complete()

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0], "should match case-insensitively")
}

func TestTriggerListDetector_NoTriggers(t *testing.T) {
	detector, err := NewTriggerListDetector(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test prompt")
	// No triggers in metadata
	a.AddOutput("Some output")
	a.Complete()

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	assert.Empty(t, scores, "should return empty scores when no triggers")
}

func TestTriggerListDetector_Name(t *testing.T) {
	detector, err := NewTriggerListDetector(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "base.TriggerListDetector", detector.Name())
}

func TestStartsWith_MatchesPrefix(t *testing.T) {
	detector, err := NewStartsWith(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("Stay gold, ")
	a.WithMetadata("triggers", []any{"Ponyboy"})
	a.AddOutput("Ponyboy ran down the street")
	a.Complete()

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0], "should match prefix trigger")
}

func TestStartsWith_NoMatch(t *testing.T) {
	detector, err := NewStartsWith(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("Stay gold, ")
	a.WithMetadata("triggers", []any{"Ponyboy"})
	a.AddOutput("The boy ran down the street") // doesn't start with Ponyboy
	a.Complete()

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0], "should not match non-prefix")
}

func TestStartsWith_CaseInsensitive(t *testing.T) {
	detector, err := NewStartsWith(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test")
	a.WithMetadata("triggers", []any{"PONYBOY"})
	a.AddOutput("ponyboy ran") // lowercase
	a.Complete()

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0], "should match case-insensitively")
}

func TestStartsWith_StripsWhitespace(t *testing.T) {
	detector, err := NewStartsWith(registry.Config{})
	require.NoError(t, err)

	a := attempt.New("test")
	a.WithMetadata("triggers", []any{"Ponyboy"})
	a.AddOutput("   Ponyboy ran") // leading whitespace
	a.Complete()

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0], "should strip whitespace before matching")
}

func TestStartsWith_Name(t *testing.T) {
	detector, err := NewStartsWith(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "leakreplay.StartsWith", detector.Name())
}
