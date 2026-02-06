package packagehallucination

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewPackageHallucinationProbe_Python(t *testing.T) {
	cfg := registry.Config{
		"language": "python",
		"task_type": "security",
	}

	probe, err := NewPackageHallucinationProbe(cfg)
	if err != nil {
		t.Fatalf("NewPackageHallucinationProbe() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewPackageHallucinationProbe() returned nil probe")
	}
}

func TestNewPackageHallucinationProbe_Go(t *testing.T) {
	cfg := registry.Config{
		"language": "go",
		"task_type": "web",
	}

	probe, err := NewPackageHallucinationProbe(cfg)
	if err != nil {
		t.Fatalf("NewPackageHallucinationProbe() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewPackageHallucinationProbe() returned nil probe")
	}
}

func TestNewPackageHallucinationProbe_NPM(t *testing.T) {
	cfg := registry.Config{
		"language": "npm",
		"task_type": "data",
	}

	probe, err := NewPackageHallucinationProbe(cfg)
	if err != nil {
		t.Fatalf("NewPackageHallucinationProbe() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewPackageHallucinationProbe() returned nil probe")
	}
}

func TestPackageHallucinationProbe_Name(t *testing.T) {
	cfg := registry.Config{
		"language": "python",
	}

	probe, err := NewPackageHallucinationProbe(cfg)
	if err != nil {
		t.Fatalf("NewPackageHallucinationProbe() error = %v", err)
	}

	name := probe.Name()
	if name == "" {
		t.Error("PackageHallucinationProbe.Name() returned empty string")
	}

	// Should include language
	if indexString(name, "python") == -1 && indexString(name, "Python") == -1 {
		t.Errorf("PackageHallucinationProbe.Name() = %q, should mention language", name)
	}
}

func TestPackageHallucinationProbe_Description(t *testing.T) {
	cfg := registry.Config{
		"language": "go",
	}

	probe, err := NewPackageHallucinationProbe(cfg)
	if err != nil {
		t.Fatalf("NewPackageHallucinationProbe() error = %v", err)
	}

	desc := probe.Description()
	if desc == "" {
		t.Error("PackageHallucinationProbe.Description() returned empty string")
	}

	// Should mention hallucination or packages
	if indexString(desc, "hallucination") == -1 && indexString(desc, "package") == -1 {
		t.Errorf("PackageHallucinationProbe.Description() = %q, should mention hallucination or packages", desc)
	}
}

func TestPackageHallucinationProbe_Goal(t *testing.T) {
	cfg := registry.Config{
		"language": "npm",
	}

	probe, err := NewPackageHallucinationProbe(cfg)
	if err != nil {
		t.Fatalf("NewPackageHallucinationProbe() error = %v", err)
	}

	goal := probe.Goal()
	if goal == "" {
		t.Error("PackageHallucinationProbe.Goal() returned empty string")
	}
}

func TestPackageHallucinationProbe_GetPrimaryDetector(t *testing.T) {
	cfg := registry.Config{
		"language": "python",
	}

	probe, err := NewPackageHallucinationProbe(cfg)
	if err != nil {
		t.Fatalf("NewPackageHallucinationProbe() error = %v", err)
	}

	detector := probe.GetPrimaryDetector()
	if detector == "" {
		t.Error("PackageHallucinationProbe.GetPrimaryDetector() returned empty string")
	}
}

func TestPackageHallucinationProbe_GetPrompts(t *testing.T) {
	cfg := registry.Config{
		"language": "python",
	}

	probe, err := NewPackageHallucinationProbe(cfg)
	if err != nil {
		t.Fatalf("NewPackageHallucinationProbe() error = %v", err)
	}

	prompts := probe.GetPrompts()

	// Should have prompts
	if len(prompts) == 0 {
		t.Error("PackageHallucinationProbe.GetPrompts() returned no prompts")
	}

	// Verify prompts contain the language name
	foundLanguage := false
	for _, prompt := range prompts {
		if indexString(prompt, "Python") != -1 || indexString(prompt, "python") != -1 {
			foundLanguage = true
			break
		}
	}
	if !foundLanguage {
		t.Error("PackageHallucinationProbe.GetPrompts() prompts don't contain language name")
	}
}

func TestPackageHallucinationProbe_Probe(t *testing.T) {
	cfg := registry.Config{
		"language": "python",
	}

	probe, err := NewPackageHallucinationProbe(cfg)
	if err != nil {
		t.Fatalf("NewPackageHallucinationProbe() error = %v", err)
	}

	// Create mock generator
	gen := &testutil.MockGenerator{
		Responses: []string{"import secure_crypto\nimport auth_helper"},
	}

	// Execute probe
	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("PackageHallucinationProbe.Probe() error = %v", err)
	}

	// Should have attempts
	if len(attempts) == 0 {
		t.Error("PackageHallucinationProbe.Probe() returned no attempts")
	}

	// Verify attempts have correct metadata
	for i, att := range attempts {
		if att.Probe == "" {
			t.Errorf("Attempt[%d].Probe is empty", i)
		}
		if att.Detector == "" {
			t.Errorf("Attempt[%d].Detector is empty", i)
		}
		if len(att.Outputs) == 0 {
			t.Errorf("Attempt[%d] has no outputs", i)
		}
	}
}

func TestHallucinatedPackages(t *testing.T) {
	// Verify HallucinatedPackages map exists and has entries
	if len(HallucinatedPackages) == 0 {
		t.Error("HallucinatedPackages map is empty")
	}

	// Should have python packages
	pythonPkgs, ok := HallucinatedPackages["python"]
	if !ok {
		t.Error("HallucinatedPackages missing 'python' entry")
	}
	if len(pythonPkgs) == 0 {
		t.Error("HallucinatedPackages['python'] is empty")
	}

	// Should have npm packages
	npmPkgs, ok := HallucinatedPackages["npm"]
	if !ok {
		t.Error("HallucinatedPackages missing 'npm' entry")
	}
	if len(npmPkgs) == 0 {
		t.Error("HallucinatedPackages['npm'] is empty")
	}

	// Should have go packages
	goPkgs, ok := HallucinatedPackages["go"]
	if !ok {
		t.Error("HallucinatedPackages missing 'go' entry")
	}
	if len(goPkgs) == 0 {
		t.Error("HallucinatedPackages['go'] is empty")
	}
}

func TestNewPackageHallucinationProbe_InvalidLanguage(t *testing.T) {
	cfg := registry.Config{
		"language": "invalid-language",
	}

	probe, err := NewPackageHallucinationProbe(cfg)

	// Should handle gracefully - either return error or default
	if err != nil && probe != nil {
		t.Error("NewPackageHallucinationProbe() returned both error and probe")
	}
}

func TestNewPackageHallucinationProbe_MissingLanguage(t *testing.T) {
	cfg := registry.Config{}

	probe, err := NewPackageHallucinationProbe(cfg)

	// Should handle gracefully - either return error or default
	if err != nil && probe != nil {
		t.Error("NewPackageHallucinationProbe() returned both error and probe")
	}
}
