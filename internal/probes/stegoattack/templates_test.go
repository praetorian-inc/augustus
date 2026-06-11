package stegoattack

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestProbesRegistered(t *testing.T) {
	expected := []string{
		"stegoattack.Acrostic",
		"stegoattack.WordInitial",
		"stegoattack.TagSmuggling",
		"stegoattack.SemanticStego",
	}

	registered := make(map[string]bool)
	for _, name := range probes.List() {
		registered[name] = true
	}

	for _, name := range expected {
		if !registered[name] {
			t.Errorf("probe %s not found in registry", name)
		}
	}
}

func TestProbeCreation(t *testing.T) {
	expected := []string{
		"stegoattack.Acrostic",
		"stegoattack.WordInitial",
		"stegoattack.TagSmuggling",
		"stegoattack.SemanticStego",
	}

	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			probe, err := probes.Create(name, registry.Config{})
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if probe.Name() != name {
				t.Errorf("Name() = %s, want %s", probe.Name(), name)
			}
			pm := probe.(probes.ProbeMetadata)
			if len(pm.GetPrompts()) == 0 {
				t.Error("no prompts")
			}
		})
	}
}
