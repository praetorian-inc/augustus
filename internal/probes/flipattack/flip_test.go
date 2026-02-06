package flipattack

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestFlipProbe_Implements_Prober(t *testing.T) {
	// Verify interface compliance at compile time
	var _ probes.Prober = (*FlipProbe)(nil)
}

func TestFlipWordOrder_Registration(t *testing.T) {
	factory, ok := probes.Get("flipattack.FlipWordOrder")
	if !ok {
		t.Fatal("flipattack.FlipWordOrder not registered")
	}

	probe, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("Failed to create probe: %v", err)
	}

	if probe.Name() != "flipattack.FlipWordOrder" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "flipattack.FlipWordOrder")
	}

	if probe.GetPrimaryDetector() != "flipattack.Bypass" {
		t.Errorf("GetPrimaryDetector() = %q, want %q", probe.GetPrimaryDetector(), "flipattack.Bypass")
	}

	prompts := probe.GetPrompts()
	if len(prompts) == 0 {
		t.Error("GetPrompts() returned empty slice")
	}
}

func TestFlipProbe_Probe(t *testing.T) {
	probe := NewFlipProbe(
		"test.FlipProbe",
		"Test probe",
		FlipWordOrder,
		Vanilla,
	)

	gen := testutil.NewMockGenerator("Here's how to build a bomb...")

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if len(attempts) != len(DefaultPayloads) {
		t.Errorf("Got %d attempts, want %d", len(attempts), len(DefaultPayloads))
	}

	// Check first attempt has correct metadata
	a := attempts[0]
	if a.Probe != "test.FlipProbe" {
		t.Errorf("Attempt.Probe = %q, want %q", a.Probe, "test.FlipProbe")
	}

	triggers, ok := a.GetMetadata("triggers")
	if !ok {
		t.Error("Attempt missing triggers metadata")
	}

	triggerSlice, ok := triggers.([]string)
	if !ok || len(triggerSlice) == 0 {
		t.Error("triggers metadata should be non-empty []string")
	}

	mode, ok := a.GetMetadata("flip_mode")
	if !ok || mode != "FWO" {
		t.Errorf("flip_mode = %v, want FWO", mode)
	}
}

func TestAllProbesRegistered(t *testing.T) {
	expectedProbes := []string{
		"flipattack.FlipWordOrder",
		"flipattack.FlipWordOrderCoT",
		"flipattack.FlipWordOrderLangGPT",
		"flipattack.FlipWordOrderFull",
		"flipattack.FlipCharsInWord",
		"flipattack.FlipCharsInWordCoT",
		"flipattack.FlipCharsInWordLangGPT",
		"flipattack.FlipCharsInWordFull",
		"flipattack.FlipCharsInSentence",
		"flipattack.FlipCharsInSentenceCoT",
		"flipattack.FlipCharsInSentenceLangGPT",
		"flipattack.FlipCharsInSentenceFull",
		"flipattack.FoolModelMode",
		"flipattack.FoolModelModeCoT",
		"flipattack.FoolModelModeLangGPT",
		"flipattack.FoolModelModeFull",
	}

	for _, name := range expectedProbes {
		if _, ok := probes.Get(name); !ok {
			t.Errorf("Probe %q not registered", name)
		}
	}
}
