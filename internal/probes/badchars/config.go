package badchars

import (
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// DeletionsConfig holds typed configuration for the badchars.Deletions probe.
type DeletionsConfig struct {
	Budget           int
	MaxPositions     int
	MaxASCIIVariants int
}

// DefaultDeletionsConfig returns defaults: budget=1, positions=6, ascii=16.
// Produces 768 prompts (vs 18,240 with old hardcoded values).
func DefaultDeletionsConfig() DeletionsConfig {
	return DeletionsConfig{
		Budget:           1,
		MaxPositions:     6,
		MaxASCIIVariants: 16,
	}
}

// DeletionsConfigFromMap parses a registry.Config map into a typed DeletionsConfig.
func DeletionsConfigFromMap(m registry.Config) (DeletionsConfig, error) {
	cfg := DefaultDeletionsConfig()
	cfg.Budget = registry.GetInt(m, "budget", cfg.Budget)
	cfg.MaxPositions = registry.GetInt(m, "max_positions", cfg.MaxPositions)
	cfg.MaxASCIIVariants = registry.GetInt(m, "max_ascii_variants", cfg.MaxASCIIVariants)
	return cfg, nil
}

// RepresentativeASCII contains 16 curated ASCII characters covering all tokenizer-relevant classes.
// These characters were selected to represent key character classes that affect tokenization:
// - Whitespace boundaries
// - Quote delimiters
// - Structural characters (brackets, braces)
// - Escape characters
// - Digits (start/end of range)
// - Uppercase/lowercase boundaries
var RepresentativeASCII = []rune{
	' ',  // 0x20 - whitespace (tokenizer boundary)
	'!',  // 0x21 - punctuation
	'"',  // 0x22 - quote (prompt delimiters)
	'\'', // 0x27 - single quote
	'(',  // 0x28 - grouping open
	'0',  // 0x30 - digit start
	'9',  // 0x39 - digit end
	'<',  // 0x3C - angle bracket (HTML/XML tokenizers)
	'>',  // 0x3E - angle bracket close
	'A',  // 0x41 - uppercase alpha start
	'\\', // 0x5C - escape character
	'a',  // 0x61 - lowercase alpha start
	'z',  // 0x7A - lowercase alpha end
	'{',  // 0x7B - structural (JSON/template)
	'}',  // 0x7D - structural close
	'~',  // 0x7E - tilde (high ASCII boundary)
}

// selectDeletionASCII selects ASCII characters based on count:
// - count <= 0 or >= 95: return all printable ASCII
// - count <= 16: return first count from RepresentativeASCII
// - count > 16: fall back to selectASCII(count) from full range
func selectDeletionASCII(count int) []rune {
	// Return all printable ASCII for count <= 0 or >= 95
	if count <= 0 || count >= 95 {
		result := make([]rune, len(asciiPrintable))
		copy(result, asciiPrintable)
		return result
	}

	// Return first count from RepresentativeASCII if count <= 16
	if count <= 16 {
		result := make([]rune, count)
		copy(result, RepresentativeASCII[:count])
		return result
	}

	// For count > 16, use existing selectASCII logic
	return selectASCII(count)
}
