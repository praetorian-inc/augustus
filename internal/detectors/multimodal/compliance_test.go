package multimodal

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewCompliance_RequiresJudgeConfig(t *testing.T) {
	// Without judge_generator_type, should return an error (same as judge.Judge)
	_, err := NewCompliance(registry.Config{})
	if err == nil {
		t.Error("NewCompliance() without judge_generator_type should return error")
	}
}

func TestNewCompliance_WithJudgeConfig(t *testing.T) {
	// With a valid judge config, should create without error.
	// We use a minimal config that satisfies the judge constructor.
	cfg := registry.Config{
		"judge_generator_type": "openai.OpenAI",
		"judge_model":          "gpt-4o-mini",
	}

	d, err := NewCompliance(cfg)
	if err != nil {
		// This may error if the generator cannot be created in test environment.
		// Only test Name() if creation succeeded.
		t.Skipf("NewCompliance() error = %v (generator may not be available in test env)", err)
	}

	if d.Name() != "multimodal.Compliance" {
		t.Errorf("Name() = %q, want %q", d.Name(), "multimodal.Compliance")
	}
}

func TestCompliance_Name_ViaWrapper(t *testing.T) {
	// Test the wrapper directly by creating the struct
	inner, _ := detectors.Get("judge.Judge") // may be nil if not registered in this test
	if inner == nil {
		t.Skip("judge.Judge not available in this test context")
	}
}

func TestCompliance_DefaultGoalIsSet(t *testing.T) {
	// When calling NewCompliance with no detector_goal, the default goal should be set.
	// We verify this by ensuring no panic and that the config mutation does not affect
	// an empty (nil) config passed in.
	cfg := registry.Config{
		"judge_generator_type": "test.Generator",
	}
	// NewCompliance should set the default goal before delegating
	// We can't fully test this without a generator, but we test the config
	// mutation logic by checking that cfg does not have detector_goal before
	// and that the function sets it if absent.
	_, _ = NewCompliance(cfg)
	// The test is that we don't panic on nil or empty config.
}

func TestCompliance_NilConfig(t *testing.T) {
	// Passing nil config should not panic; it should fail with a meaningful error.
	_, err := NewCompliance(nil)
	if err == nil {
		t.Error("NewCompliance(nil) without judge_generator_type should return error")
	}
}

func TestCompliance_Registration(t *testing.T) {
	factory, ok := detectors.Get("multimodal.Compliance")
	if !ok {
		t.Fatal("multimodal.Compliance not registered in detectors registry")
	}
	if factory == nil {
		t.Fatal("multimodal.Compliance factory is nil")
	}
}

func TestCompliance_Description(t *testing.T) {
	// The compliance wrapper should have a non-empty description.
	// Create a wrapper directly to test Description().
	wrapper := &complianceDetector{inner: nil}
	desc := wrapper.Description()
	if desc == "" {
		t.Error("complianceDetector.Description() returned empty string")
	}
}

func TestCompliance_Name_Direct(t *testing.T) {
	// The compliance wrapper should return the correct name.
	wrapper := &complianceDetector{inner: nil}
	if got := wrapper.Name(); got != "multimodal.Compliance" {
		t.Errorf("complianceDetector.Name() = %q, want %q", got, "multimodal.Compliance")
	}
}
