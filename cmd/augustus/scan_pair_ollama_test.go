package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestCreateProbes_InjectsTargetGeneratorType tests that createProbes injects
// the target generator type into probe config, allowing PAIR/TAP to inherit it
// for the attacker generator.
//
// Note: As of v0.0.7, the judge no longer inherits from the target. The target
// should never evaluate its own responses. Configure the judge explicitly via
// the global judge: section in your YAML config.
func TestCreateProbes_InjectsTargetGeneratorType(t *testing.T) {
	targetGeneratorName := "ollama.OllamaChat"
	targetGeneratorConfig := registry.Config{
		"model": "minimax-m2.5:cloud",
	}

	probeList, err := createProbes([]string{"test.Test"}, nil, targetGeneratorName, targetGeneratorConfig)
	assert.NoError(t, err, "createProbes should succeed")
	assert.Len(t, probeList, 1)
}
