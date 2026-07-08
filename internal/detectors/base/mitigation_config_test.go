package base

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestResolveMitigationPhrases(t *testing.T) {
	defaults := []string{"I'm sorry", "I cannot"}

	t.Run("nil config returns defaults", func(t *testing.T) {
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
}
