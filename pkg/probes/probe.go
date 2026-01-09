// Package probes provides the probe interface and implementations for LLM testing.
//
// Probes generate attack prompts and coordinate with generators to test LLMs
// for vulnerabilities. Each probe implements a specific attack technique.
package probes

import (
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Generator is a type alias for backward compatibility.
// See types.Generator for the canonical interface definition.
type Generator = types.Generator

// Prober is a type alias for backward compatibility.
// See types.Prober for the canonical interface definition.
type Prober = types.Prober

// Registry is the global probe registry.
var Registry = registry.New[Prober]("probes")

// Register adds a probe factory to the global registry.
// Called from init() functions in probe implementations.
func Register(name string, factory func(registry.Config) (Prober, error)) {
	Registry.Register(name, factory)
}

// List returns all registered probe names.
func List() []string {
	return Registry.List()
}

// Get retrieves a probe factory by name.
func Get(name string) (func(registry.Config) (Prober, error), bool) {
	return Registry.Get(name)
}

// Create instantiates a probe by name.
func Create(name string, cfg registry.Config) (Prober, error) {
	return Registry.Create(name, cfg)
}
