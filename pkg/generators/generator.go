// Package generators provides the generator interface and implementations for LLM access.
//
// Generators wrap LLM APIs (OpenAI, Anthropic, local models) with a common interface.
// They handle authentication, rate limiting, and conversation management.
package generators

import (
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Generator is a type alias for backward compatibility.
// See types.Generator for the canonical interface definition.
type Generator = types.Generator

// Registry is the global generator registry.
var Registry = registry.New[Generator]("generators")

// Register adds a generator factory to the global registry.
// Called from init() functions in generator implementations.
func Register(name string, factory func(registry.Config) (Generator, error)) {
	Registry.Register(name, factory)
}

// List returns all registered generator names.
func List() []string {
	return Registry.List()
}

// Get retrieves a generator factory by name.
func Get(name string) (func(registry.Config) (Generator, error), bool) {
	return Registry.Get(name)
}

// Create instantiates a generator by name.
func Create(name string, cfg registry.Config) (Generator, error) {
	return Registry.Create(name, cfg)
}
