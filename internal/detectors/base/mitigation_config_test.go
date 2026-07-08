package base

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestResolveMitigationPhrases(t *testing.T) {
	defaults := []string{"I'm sorry", "I cannot"}

	t.Run("nil config returns defaults", func(t *testing.T) {
		assert.Equal(t, defaults, ResolveMitigationPhrases(nil, defaults))
	})

	t.Run("empty config returns defaults", func(t *testing.T) {
		assert.Equal(t, defaults, ResolveMitigationPhrases(registry.Config{}, defaults))
	})

	t.Run("substrings replaces defaults entirely", func(t *testing.T) {
		got := ResolveMitigationPhrases(registry.Config{"substrings": []string{"custom"}}, defaults)
		assert.Equal(t, []string{"custom"}, got)
	})

	t.Run("extra_substrings augments defaults", func(t *testing.T) {
		got := ResolveMitigationPhrases(registry.Config{"extra_substrings": []string{"guardrail"}}, defaults)
		assert.Equal(t, []string{"I'm sorry", "I cannot", "guardrail"}, got)
	})

	t.Run("extra_substrings augments the substrings override", func(t *testing.T) {
		cfg := registry.Config{
			"substrings":       []string{"custom"},
			"extra_substrings": []string{"guardrail"},
		}
		assert.Equal(t, []string{"custom", "guardrail"}, ResolveMitigationPhrases(cfg, defaults))
	})

	t.Run("empty and whitespace-only phrases are dropped", func(t *testing.T) {
		got := ResolveMitigationPhrases(registry.Config{"extra_substrings": []string{"", "  ", "\t"}}, defaults)
		assert.Equal(t, defaults, got)
	})

	t.Run("all-empty override falls back to defaults", func(t *testing.T) {
		// An all-empty substrings override would otherwise leave a match-nothing
		// list; it must restore defaults rather than flag every output (LAB-4664).
		got := ResolveMitigationPhrases(registry.Config{"substrings": []string{"", " "}}, defaults)
		assert.Equal(t, defaults, got)
	})

	t.Run("refusal_patterns augments like extra_substrings", func(t *testing.T) {
		got := ResolveMitigationPhrases(registry.Config{"refusal_patterns": []string{"guardrail"}}, defaults)
		assert.Equal(t, []string{"I'm sorry", "I cannot", "guardrail"}, got)
	})

	t.Run("extra_substrings and refusal_patterns both augment, in order", func(t *testing.T) {
		cfg := registry.Config{
			"extra_substrings": []string{"extra"},
			"refusal_patterns": []string{"guardrail"},
		}
		assert.Equal(t, []string{"I'm sorry", "I cannot", "extra", "guardrail"},
			ResolveMitigationPhrases(cfg, defaults))
	})
}

// TestNewMitigationStringDetector guards the shared helper's behavior: it must
// resolve phrases via ResolveMitigationPhrases AND forward matchtype /
// case_sensitive to the inner StringDetector. QUAL-002 flagged that some
// detectors previously dropped matchtype/case_sensitive support before being
// unified through this helper (LAB-4664).
func TestNewMitigationStringDetector(t *testing.T) {
	t.Run("default config resolves defaults and matches as substrings", func(t *testing.T) {
		detector, err := NewMitigationStringDetector(registry.Config{}, []string{"sorry"})
		require.NoError(t, err)

		a := attempt.New("test prompt")
		a.AddOutput("I feel sorryish about this")

		scores, err := detector.Detect(context.Background(), a)
		require.NoError(t, err)
		require.Len(t, scores, 1)
		assert.Equal(t, 1.0, scores[0], "default 'str' matchtype must match 'sorry' embedded in 'sorryish'")
	})

	t.Run("matchtype word is honored", func(t *testing.T) {
		detector, err := NewMitigationStringDetector(registry.Config{
			"matchtype": "word",
		}, []string{"sorry"})
		require.NoError(t, err)

		a := attempt.New("test prompt")
		a.AddOutput("I feel sorryish about this")

		scores, err := detector.Detect(context.Background(), a)
		require.NoError(t, err)
		require.Len(t, scores, 1)
		assert.Equal(t, 0.0, scores[0], "word-boundary matching must not match 'sorry' inside 'sorryish'")

		a2 := attempt.New("test prompt")
		a2.AddOutput("I am sorry about that")

		scores, err = detector.Detect(context.Background(), a2)
		require.NoError(t, err)
		require.Len(t, scores, 1)
		assert.Equal(t, 1.0, scores[0], "word-boundary matching must match standalone word 'sorry'")
	})

	t.Run("case_sensitive is honored", func(t *testing.T) {
		detector, err := NewMitigationStringDetector(registry.Config{
			"case_sensitive": true,
		}, []string{"REFUSED"})
		require.NoError(t, err)

		a := attempt.New("test prompt")
		a.AddOutput("refused")

		scores, err := detector.Detect(context.Background(), a)
		require.NoError(t, err)
		require.Len(t, scores, 1)
		assert.Equal(t, 0.0, scores[0], "case-sensitive matching must not match differing case")

		a2 := attempt.New("test prompt")
		a2.AddOutput("REFUSED")

		scores, err = detector.Detect(context.Background(), a2)
		require.NoError(t, err)
		require.Len(t, scores, 1)
		assert.Equal(t, 1.0, scores[0], "case-sensitive matching must match exact case")
	})
}
