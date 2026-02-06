package paraphrase

import (
	"os"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// DefaultHuggingFaceAPIURL is imported from pegasus.go
// Defined as: "https://api-inference.huggingface.co/models"

// Config holds typed configuration for the Paraphrase buff.
type Config struct {
	// Model is the HuggingFace model name.
	Model string

	// APIURL is the HuggingFace Inference API URL.
	APIURL string

	// APIKey is the HuggingFace API key.
	APIKey string

	// NumBeams is the number of beams for beam search.
	NumBeams int

	// NumBeamGroups is the number of beam groups for diverse beam search.
	NumBeamGroups int

	// NumReturnSequences is the number of paraphrases to generate.
	NumReturnSequences int

	// RepetitionPenalty discourages repetition in generated text.
	RepetitionPenalty float64

	// DiversityPenalty encourages diversity between beam groups.
	DiversityPenalty float64

	// NoRepeatNgramSize prevents n-gram repetition.
	NoRepeatNgramSize int

	// MaxLength is the maximum length of generated text.
	MaxLength int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Model:              DefaultFastModel,
		APIURL:             DefaultHuggingFaceAPIURL,
		APIKey:             "",
		NumBeams:           5,
		NumBeamGroups:      5,
		NumReturnSequences: 5,
		RepetitionPenalty:  10.0,
		DiversityPenalty:   3.0,
		NoRepeatNgramSize:  2,
		MaxLength:          128,
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Optional: model
	cfg.Model = registry.GetString(m, "model", cfg.Model)

	// Optional: api_url
	cfg.APIURL = registry.GetString(m, "api_url", cfg.APIURL)

	// Optional: api_key (from config or env var)
	cfg.APIKey = registry.GetString(m, "api_key", cfg.APIKey)
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("HUGGINGFACE_API_KEY")
	}

	// Optional: numeric parameters
	cfg.NumBeams = registry.GetInt(m, "num_beams", cfg.NumBeams)
	cfg.NumBeamGroups = registry.GetInt(m, "num_beam_groups", cfg.NumBeamGroups)
	cfg.NumReturnSequences = registry.GetInt(m, "num_return_sequences", cfg.NumReturnSequences)
	cfg.RepetitionPenalty = registry.GetFloat64(m, "repetition_penalty", cfg.RepetitionPenalty)
	cfg.DiversityPenalty = registry.GetFloat64(m, "diversity_penalty", cfg.DiversityPenalty)
	cfg.NoRepeatNgramSize = registry.GetInt(m, "no_repeat_ngram_size", cfg.NoRepeatNgramSize)
	cfg.MaxLength = registry.GetInt(m, "max_length", cfg.MaxLength)

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithModel sets the model name.
func WithModel(model string) Option {
	return func(c *Config) {
		c.Model = model
	}
}

// WithAPIURL sets the API URL.
func WithAPIURL(url string) Option {
	return func(c *Config) {
		c.APIURL = url
	}
}

// WithAPIKey sets the API key.
func WithAPIKey(key string) Option {
	return func(c *Config) {
		c.APIKey = key
	}
}

// WithNumBeams sets the number of beams.
func WithNumBeams(beams int) Option {
	return func(c *Config) {
		c.NumBeams = beams
	}
}

// WithNumBeamGroups sets the number of beam groups.
func WithNumBeamGroups(groups int) Option {
	return func(c *Config) {
		c.NumBeamGroups = groups
	}
}

// WithNumReturnSequences sets the number of return sequences.
func WithNumReturnSequences(sequences int) Option {
	return func(c *Config) {
		c.NumReturnSequences = sequences
	}
}

// WithRepetitionPenalty sets the repetition penalty.
func WithRepetitionPenalty(penalty float64) Option {
	return func(c *Config) {
		c.RepetitionPenalty = penalty
	}
}

// WithDiversityPenalty sets the diversity penalty.
func WithDiversityPenalty(penalty float64) Option {
	return func(c *Config) {
		c.DiversityPenalty = penalty
	}
}

// WithNoRepeatNgramSize sets the no-repeat n-gram size.
func WithNoRepeatNgramSize(size int) Option {
	return func(c *Config) {
		c.NoRepeatNgramSize = size
	}
}

// WithMaxLength sets the maximum length.
func WithMaxLength(length int) Option {
	return func(c *Config) {
		c.MaxLength = length
	}
}
