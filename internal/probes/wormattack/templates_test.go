package wormattack

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestWormAttackProbesRegistered(t *testing.T) {
	expectedProbes := []string{
		"wormattack.ConfigInjection",
	}

	registeredProbes := probes.List()
	registered := make(map[string]bool)
	for _, name := range registeredProbes {
		registered[name] = true
	}

	for _, expected := range expectedProbes {
		if !registered[expected] {
			t.Errorf("probe %s not found in registry", expected)
		}
	}
}

func TestWormAttackProbeCreation(t *testing.T) {
	probe, err := probes.Create("wormattack.ConfigInjection", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}
	if probe == nil {
		t.Fatal("probes.Create() returned nil")
	}
	if probe.Name() != "wormattack.ConfigInjection" {
		t.Errorf("probe.Name() = %s, want wormattack.ConfigInjection", probe.Name())
	}
}

func TestWormAttackProbeMetadata(t *testing.T) {
	probe, err := probes.Create("wormattack.ConfigInjection", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	pm, ok := probe.(probes.ProbeMetadata)
	if !ok {
		t.Fatal("probe does not implement ProbeMetadata")
	}

	if pm.Description() == "" {
		t.Error("Description() returned empty string")
	}
	if pm.Goal() == "" {
		t.Error("Goal() returned empty string")
	}
	if pm.GetPrimaryDetector() != "judge.Judge" {
		t.Errorf("GetPrimaryDetector() = %s, want judge.Judge", pm.GetPrimaryDetector())
	}
	if len(pm.GetPrompts()) != 3 {
		t.Errorf("prompt count = %d, want 3", len(pm.GetPrompts()))
	}
}

func TestWormAttackProbeExecution(t *testing.T) {
	probe, err := probes.Create("wormattack.ConfigInjection", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	gen := &testutil.MockGenerator{
		GenName:   "test-model",
		Responses: []string{"I cannot include self-replicating directives in config files."},
	}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("probe.Probe() returned no attempts")
	}
}
