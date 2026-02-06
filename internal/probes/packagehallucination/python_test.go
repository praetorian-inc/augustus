package packagehallucination

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewPython(t *testing.T) {
	probe, err := NewPython(registry.Config{})
	if err != nil {
		t.Fatalf("NewPython() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewPython() returned nil probe")
	}
}

func TestPython_Name(t *testing.T) {
	probe, err := NewPython(registry.Config{})
	if err != nil {
		t.Fatalf("NewPython() error = %v", err)
	}

	want := "packagehallucination.Python"
	if got := probe.Name(); got != want {
		t.Errorf("Python.Name() = %q, want %q", got, want)
	}
}

func TestPython_Description(t *testing.T) {
	probe, err := NewPython(registry.Config{})
	if err != nil {
		t.Fatalf("NewPython() error = %v", err)
	}

	desc := probe.Description()
	if desc == "" {
		t.Error("Python.Description() returned empty string")
	}

	// Should mention Python
	if indexString(desc, "Python") == -1 {
		t.Errorf("Python.Description() = %q, should mention 'Python'", desc)
	}
}

func TestPython_Goal(t *testing.T) {
	probe, err := NewPython(registry.Config{})
	if err != nil {
		t.Fatalf("NewPython() error = %v", err)
	}

	want := "generate python importing non-existent packages"
	if got := probe.Goal(); got != want {
		t.Errorf("Python.Goal() = %q, want %q", got, want)
	}
}

func TestPython_GetPrimaryDetector(t *testing.T) {
	probe, err := NewPython(registry.Config{})
	if err != nil {
		t.Fatalf("NewPython() error = %v", err)
	}

	want := "packagehallucination.PythonPypi"
	if got := probe.GetPrimaryDetector(); got != want {
		t.Errorf("Python.GetPrimaryDetector() = %q, want %q", got, want)
	}
}

func TestPython_GetPrompts(t *testing.T) {
	probe, err := NewPython(registry.Config{})
	if err != nil {
		t.Fatalf("NewPython() error = %v", err)
	}

	prompts := probe.GetPrompts()

	// Should have 240 prompts (10 stubs × 24 tasks)
	expectedCount := 240
	if len(prompts) != expectedCount {
		t.Errorf("Python.GetPrompts() returned %d prompts, want %d", len(prompts), expectedCount)
	}

	// Verify prompts contain "Python3"
	foundPython := false
	for _, prompt := range prompts {
		if indexString(prompt, "Python3") != -1 {
			foundPython = true
			break
		}
	}
	if !foundPython {
		t.Error("Python.GetPrompts() prompts don't contain 'Python3'")
	}
}

func TestPython_Probe(t *testing.T) {
	probe, err := NewPython(registry.Config{})
	if err != nil {
		t.Fatalf("NewPython() error = %v", err)
	}

	// Create mock generator
	gen := testutil.NewMockGenerator("import fake_package")

	// Execute probe
	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Python.Probe() error = %v", err)
	}

	// Should have 240 attempts (one per prompt)
	if len(attempts) != 240 {
		t.Errorf("Python.Probe() returned %d attempts, want 240", len(attempts))
	}

	// Verify attempts have correct metadata
	for i, att := range attempts {
		if att.Probe != "packagehallucination.Python" {
			t.Errorf("Attempt[%d].Probe = %q, want %q", i, att.Probe, "packagehallucination.Python")
		}
		if att.Detector != "packagehallucination.PythonPypi" {
			t.Errorf("Attempt[%d].Detector = %q, want %q", i, att.Detector, "packagehallucination.PythonPypi")
		}
		if len(att.Outputs) == 0 {
			t.Errorf("Attempt[%d] has no outputs", i)
		}
	}
}
