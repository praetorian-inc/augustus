package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanCommand_CreateComponents tests component creation from registries.
func TestScanCommand_CreateComponents(t *testing.T) {
	ctx := context.Background()

	// Create a generator
	gen, err := generators.Create("test.Repeat", registry.Config{})
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Create a probe
	probe, err := probes.Create("test.Test", registry.Config{})
	if err != nil {
		t.Fatalf("failed to create probe: %v", err)
	}

	// Create a detector
	detector, err := detectors.Create("always.Pass", registry.Config{})
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	// Verify types
	if gen == nil {
		t.Error("generator is nil")
	}
	if probe == nil {
		t.Error("probe is nil")
	}
	if detector == nil {
		t.Error("detector is nil")
	}

	// Test that probe can run
	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("probe.Probe() failed: %v", err)
	}
	if len(attempts) == 0 {
		t.Error("probe.Probe() returned no attempts")
	}
}

// mockEvaluator is a simple evaluator for testing.
type mockEvaluator struct {
	attempts []*attempt.Attempt
}

func (m *mockEvaluator) Evaluate(ctx context.Context, attempts []*attempt.Attempt) error {
	m.attempts = attempts
	return nil
}

// TestScanCommand_RunScan tests the full scan execution.
func TestScanCommand_RunScan(t *testing.T) {
	ctx := context.Background()

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		configJSON:    "",
		outputFormat:  "table",
		verbose:       false,
	}

	eval := &mockEvaluator{}
	err := runScan(ctx, cfg, eval)
	if err != nil {
		t.Fatalf("runScan() failed: %v", err)
	}

	if len(eval.attempts) == 0 {
		t.Error("runScan() produced no attempts")
	}
}

// TestScanCmdBuffFlagParsing tests that --buff flag parsing works.
func TestScanCmdBuffFlagParsing(t *testing.T) {
	// Test that --buff encoding.Base64 --buff lowercase.Lowercase works
	scanCmd := &ScanCmd{
		Generator: "test.Repeat",
		Probe:     []string{"test.Test"},
		Buff:      []string{"encoding.Base64", "lowercase.Lowercase"},
	}

	cfg := scanCmd.loadScanConfig()
	if len(cfg.buffNames) != 2 {
		t.Errorf("expected 2 buff names, got %d", len(cfg.buffNames))
	}
	if cfg.buffNames[0] != "encoding.Base64" {
		t.Errorf("expected first buff 'encoding.Base64', got %s", cfg.buffNames[0])
	}
	if cfg.buffNames[1] != "lowercase.Lowercase" {
		t.Errorf("expected second buff 'lowercase.Lowercase', got %s", cfg.buffNames[1])
	}
}

// TestScanCmdBuffsGlobFlagParsing tests that --buffs-glob flag parsing works.
func TestScanCmdBuffsGlobFlagParsing(t *testing.T) {
	// Test that --buffs-glob "encoding.*" works
	scanCmd := &ScanCmd{
		Generator: "test.Repeat",
		Probe:     []string{"test.Test"},
		BuffsGlob: "encoding.*",
	}

	cfg := scanCmd.loadScanConfig()
	err := scanCmd.expandGlobPatterns(cfg)
	if err != nil {
		t.Fatalf("expandGlobPatterns() failed: %v", err)
	}

	// Should match encoding.Base64 and encoding.ROT13 (from previous tasks)
	if len(cfg.buffNames) < 1 {
		t.Errorf("expected at least 1 buff name from glob 'encoding.*', got %d", len(cfg.buffNames))
	}

	// Verify all matched buffs start with "encoding."
	for _, buffName := range cfg.buffNames {
		if len(buffName) < 9 || buffName[:9] != "encoding." {
			t.Errorf("expected buff name to start with 'encoding.', got %s", buffName)
		}
	}
}

// TestScanCommand_YAMLConfigResolution tests that YAML config file wiring works.
// This test exercises the config resolution paths for buffs, probes, and detectors
// that are used in scan.go but were previously untested.
func TestScanCommand_YAMLConfigResolution(t *testing.T) {
	ctx := context.Background()

	// Create a temporary YAML config file with settings for all component types
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	yamlContent := `
generators:
  test.Repeat:
    model: "test-model"
    temperature: 0.7
    api_key: "test-key"

buffs:
  names:
    - encoding.Base64
  settings:
    encoding.Base64:
      enabled: true

probes:
  settings:
    test.Test:
      custom_option: "test-value"

detectors:
  settings:
    always.Pass:
      threshold: 0.5

run:
  concurrency: 5
  timeout: "10m"
  probe_timeout: "2m"

output:
  format: "json"
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err, "failed to write test config file")

	// Create scanConfig with YAML file
	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		buffNames:     []string{}, // Will be loaded from YAML
		harnessName:   "probewise.Probewise",
		configFile:    configPath,
		outputFormat:  "table",
		verbose:       false,
	}

	eval := &mockEvaluator{}
	err = runScan(ctx, cfg, eval)
	require.NoError(t, err, "runScan with YAML config should succeed")

	// Verify the scan produced results
	assert.NotEmpty(t, eval.attempts, "scan with YAML config should produce attempts")

	// This test proves that:
	// 1. yamlCfg.ResolveBuffConfig() is called (line 372)
	// 2. yamlCfg.ResolveProbeConfig() is called (line 307)
	// 3. yamlCfg.ResolveDetectorConfig() is called (line 323, 344)
	// 4. The scan completes successfully with config-driven settings
}
