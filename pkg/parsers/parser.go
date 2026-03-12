// Package parsers provides the parser interface and implementations for LLM response normalization.
//
// Parsers transform raw/fragmented LLM responses (e.g., SSE streams) into
// coherent text suitable for detector analysis. They sit between generators
// and detectors in the scan pipeline.
package parsers

import (
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Parser is a type alias for backward compatibility.
// See types.Parser for the canonical interface definition.
type Parser = types.Parser

// Registry is the global parser registry.
var Registry = registry.New[Parser]("parsers")

// Register adds a parser factory to the global registry.
// Called from init() functions in parser implementations.
func Register(name string, factory func(registry.Config) (Parser, error)) {
	Registry.Register(name, factory)
}

// List returns all registered parser names.
func List() []string {
	return Registry.List()
}

// Get retrieves a parser factory by name.
func Get(name string) (func(registry.Config) (Parser, error), bool) {
	return Registry.Get(name)
}

// Create instantiates a parser by name.
func Create(name string, cfg registry.Config) (Parser, error) {
	return Registry.Create(name, cfg)
}
