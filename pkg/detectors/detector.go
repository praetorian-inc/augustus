// Package detectors provides the detector interface and implementations for output analysis.
//
// Detectors analyze LLM outputs from attempts and assign vulnerability scores.
// Scores range from 0.0 (safe/passed) to 1.0 (vulnerable/failed).
package detectors

import (
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Detector is a type alias for backward compatibility.
// See types.Detector for the canonical interface definition.
type Detector = types.Detector

// Registry is the global detector registry.
var Registry = registry.New[Detector]("detectors")

// Register adds a detector factory to the global registry.
// Called from init() functions in detector implementations.
func Register(name string, factory func(registry.Config) (Detector, error)) {
	Registry.Register(name, factory)
}

// List returns all registered detector names.
func List() []string {
	return Registry.List()
}

// Get retrieves a detector factory by name.
func Get(name string) (func(registry.Config) (Detector, error), bool) {
	return Registry.Get(name)
}

// Create instantiates a detector by name.
func Create(name string, cfg registry.Config) (Detector, error) {
	return Registry.Create(name, cfg)
}
