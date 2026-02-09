package flipattack_test

import (
	"strings"
	"testing"

	_ "github.com/praetorian-inc/augustus/internal/probes/flipattack"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func TestRegistration(t *testing.T) {
	_, ok := probes.Get("flipattack.FullAttack")
	if !ok {
		t.Fatal("flipattack.FullAttack not registered")
	}
}

func TestFullAttack_Name(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	probe, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}
	if probe.Name() != "flipattack.FullAttack" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "flipattack.FullAttack")
	}
}

func TestFullAttack_Metadata(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	probe, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}

	pm, ok := probe.(types.ProbeMetadata)
	if !ok {
		t.Fatal("probe should implement ProbeMetadata")
	}

	if pm.GetPrimaryDetector() != "flipattack.Bypass" {
		t.Errorf("GetPrimaryDetector() = %q, want %q", pm.GetPrimaryDetector(), "flipattack.Bypass")
	}

	if pm.Description() == "" {
		t.Error("Description() should not be empty")
	}

	if pm.Goal() == "" {
		t.Error("Goal() should not be empty")
	}
}

func TestFullAttack_Prompts(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	probe, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}

	pm, ok := probe.(types.ProbeMetadata)
	if !ok {
		t.Fatal("probe should implement ProbeMetadata")
	}

	prompts := pm.GetPrompts()
	if len(prompts) == 0 {
		t.Fatal("probe should have at least one prompt")
	}

	for i, prompt := range prompts {
		// Each prompt should contain adversarial framing elements
		if !strings.Contains(prompt, "NEVER") {
			t.Errorf("prompt[%d] should contain 'NEVER' (banned word instruction)", i)
		}
		if !strings.Contains(prompt, "TASK") {
			t.Errorf("prompt[%d] should contain 'TASK' (task reference)", i)
		}
		if !strings.Contains(prompt, "sorry") || !strings.Contains(prompt, "cannot") {
			t.Errorf("prompt[%d] should contain banned word list ('sorry', 'cannot')", i)
		}
	}
}

func TestFullAttack_PromptsContainPayloads(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	probe, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}

	pm := probe.(types.ProbeMetadata)
	prompts := pm.GetPrompts()

	// Prompts should contain actual test payloads embedded in the adversarial frame
	hasPayload := false
	for _, prompt := range prompts {
		lower := strings.ToLower(prompt)
		if strings.Contains(lower, "hack") || strings.Contains(lower, "steal") ||
			strings.Contains(lower, "bomb") || strings.Contains(lower, "exploit") {
			hasPayload = true
			break
		}
	}
	if !hasPayload {
		t.Error("prompts should contain harmful test payloads embedded in adversarial frame")
	}
}
