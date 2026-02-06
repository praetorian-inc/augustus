package paraphrase

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParaphraseConfigFromMap(t *testing.T) {
	m := registry.Config{
		"model":                "custom-model",
		"api_url":              "https://custom.api",
		"api_key":              "test-key",
		"num_beams":            10,
		"num_beam_groups":      3,
		"num_return_sequences": 3,
		"repetition_penalty":   5.0,
		"diversity_penalty":    2.0,
		"no_repeat_ngram_size": 3,
		"max_length":           256,
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "custom-model", cfg.Model)
	assert.Equal(t, "https://custom.api", cfg.APIURL)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, 10, cfg.NumBeams)
	assert.Equal(t, 3, cfg.NumBeamGroups)
	assert.Equal(t, 3, cfg.NumReturnSequences)
	assert.Equal(t, 5.0, cfg.RepetitionPenalty)
	assert.Equal(t, 2.0, cfg.DiversityPenalty)
	assert.Equal(t, 3, cfg.NoRepeatNgramSize)
	assert.Equal(t, 256, cfg.MaxLength)
}

func TestParaphraseConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, DefaultFastModel, cfg.Model)
	assert.Equal(t, DefaultHuggingFaceAPIURL, cfg.APIURL)
	assert.Equal(t, "", cfg.APIKey)
	assert.Equal(t, 5, cfg.NumBeams)
	assert.Equal(t, 5, cfg.NumBeamGroups)
	assert.Equal(t, 5, cfg.NumReturnSequences)
	assert.Equal(t, 10.0, cfg.RepetitionPenalty)
	assert.Equal(t, 3.0, cfg.DiversityPenalty)
	assert.Equal(t, 2, cfg.NoRepeatNgramSize)
	assert.Equal(t, 128, cfg.MaxLength)
}

func TestParaphraseConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(
		DefaultConfig(),
		WithModel("test-model"),
		WithAPIURL("https://test.api"),
		WithNumBeams(7),
	)

	assert.Equal(t, "test-model", cfg.Model)
	assert.Equal(t, "https://test.api", cfg.APIURL)
	assert.Equal(t, 7, cfg.NumBeams)
}
