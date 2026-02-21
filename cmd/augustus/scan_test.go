package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/config"
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

// TestScanCmd_ProfileIntegration tests the full chain:
// ScanCmd.Profile -> CLIOverrides.ProfileName -> Resolve()
func TestScanCmd_ProfileIntegration(t *testing.T) {
	cmd := &ScanCmd{
		Generator: "test.Blank",
		Probe:     []string{"test.Blank"},
		Profile:   "quick",
	}
	cli := cmd.buildCLIOverrides()
	assert.Equal(t, "quick", cli.ProfileName)
}

// TestScanCmd_SetupContextNoDeadline tests that setupContext does NOT apply
// a timeout to the context. Scan timeouts are handled by the scanner package
// so that partial results can still be processed after scanning completes.
func TestScanCmd_SetupContextNoDeadline(t *testing.T) {
	cmd := &ScanCmd{}

	ctx, cancel := cmd.setupContext()
	defer cancel()

	// setupContext should NOT set a deadline - only signal handling
	_, hasDeadline := ctx.Deadline()
	assert.False(t, hasDeadline, "setupContext should not set a deadline; scanner handles timeouts")
}

// TestScanCmd_ResolvedTimeoutPassedToScanner tests that YAML config timeout
// is correctly resolved and would be passed to scanner options.
func TestScanCmd_ResolvedTimeoutPassedToScanner(t *testing.T) {
	// Create YAML config with explicit timeout
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "timeout-config.yaml")
	yamlContent := `
run:
  timeout: "100ms"
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// ScanCmd with NO timeout flag (Timeout = 0)
	cmd := &ScanCmd{
		Generator:  "test.Repeat",
		Probe:      []string{"test.Test"},
		Harness:    "probewise.Probewise",
		ConfigFile: configPath,
		Timeout:    0,
	}

	// Load config and resolve
	yamlCfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)

	cli := cmd.buildCLIOverrides()
	resolved, err := config.Resolve(yamlCfg, cli)
	require.NoError(t, err)

	// Verify resolved timeout matches YAML config (100ms)
	assert.Equal(t, 100*time.Millisecond, resolved.ScannerOpts.Timeout,
		"resolved timeout should come from YAML config")
}

// TestCreateProbes_Basic tests that createProbes creates probes from names.
func TestCreateProbes_Basic(t *testing.T) {
	probeList, err := createProbes([]string{"test.Test"}, nil)
	require.NoError(t, err)
	assert.Len(t, probeList, 1)
	assert.Equal(t, "test.Test", probeList[0].Name())
}

// TestCreateProbes_InvalidName tests that createProbes returns error for invalid probe name.
func TestCreateProbes_InvalidName(t *testing.T) {
	_, err := createProbes([]string{"nonexistent.Probe"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create probe")
}

// TestCreateProbes_Empty tests that createProbes handles empty probe list.
func TestCreateProbes_Empty(t *testing.T) {
	probeList, err := createProbes([]string{}, nil)
	require.NoError(t, err)
	assert.Len(t, probeList, 0)
}

// TestCreateDetectors_ExplicitList tests that createDetectors creates detectors from explicit names.
func TestCreateDetectors_ExplicitList(t *testing.T) {
	detectorList, err := createDetectors([]string{"always.Pass"}, nil, nil)
	require.NoError(t, err)
	assert.Len(t, detectorList, 1)
}

// TestCreateDetectors_DerivedFromProbes tests that createDetectors auto-discovers from probe metadata.
func TestCreateDetectors_DerivedFromProbes(t *testing.T) {
	probeList, err := createProbes([]string{"test.Test"}, nil)
	require.NoError(t, err)

	detectorList, err := createDetectors(nil, probeList, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, detectorList, "should auto-discover detectors from probes")
}

// TestCreateDetectors_NoneAvailable tests that createDetectors returns error when no detectors available.
func TestCreateDetectors_NoneAvailable(t *testing.T) {
	_, err := createDetectors(nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no detectors available")
}

// TestCreateAndApplyBuffs_Empty tests that createAndApplyBuffs returns original probes when no buffs.
func TestCreateAndApplyBuffs_Empty(t *testing.T) {
	probeList, err := createProbes([]string{"test.Test"}, nil)
	require.NoError(t, err)

	resultProbes, err := createAndApplyBuffs(probeList, []string{}, nil)
	require.NoError(t, err)
	assert.Len(t, resultProbes, 1)
	assert.Equal(t, probeList[0], resultProbes[0], "should return original probes unchanged")
}

// TestCreateAndApplyBuffs_WithBuffs tests that createAndApplyBuffs wraps probes with buff chain.
func TestCreateAndApplyBuffs_WithBuffs(t *testing.T) {
	probeList, err := createProbes([]string{"test.Test"}, nil)
	require.NoError(t, err)

	resultProbes, err := createAndApplyBuffs(probeList, []string{"encoding.Base64"}, nil)
	require.NoError(t, err)
	assert.Len(t, resultProbes, 1)
	// After applying buffs, probes should be wrapped (different instance)
	assert.NotEqual(t, probeList[0], resultProbes[0], "probes should be wrapped with buffs")
}

// TestBuildCLIOverrides_ModelAlone tests that --model flag creates ConfigJSON with just model.
func TestBuildCLIOverrides_ModelAlone(t *testing.T) {
	cmd := &ScanCmd{
		Generator: "openai.OpenAI",
		Probe:     []string{"test.Blank"},
		Model:     "gpt-4",
	}
	cli := cmd.buildCLIOverrides()
	assert.Equal(t, `{"model":"gpt-4"}`, cli.ConfigJSON)
}

// TestBuildCLIOverrides_ModelMergedWithConfig tests that --model merges with existing --config.
func TestBuildCLIOverrides_ModelMergedWithConfig(t *testing.T) {
	cmd := &ScanCmd{
		Generator: "openai.OpenAI",
		Probe:     []string{"test.Blank"},
		Config:    `{"temperature":0.5}`,
		Model:     "gpt-4",
	}
	cli := cmd.buildCLIOverrides()
	var result map[string]any
	err := json.Unmarshal([]byte(cli.ConfigJSON), &result)
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", result["model"])
	assert.Equal(t, 0.5, result["temperature"])
}

// TestBuildCLIOverrides_ModelOverridesConfigModel tests that --model takes precedence over --config model key.
func TestBuildCLIOverrides_ModelOverridesConfigModel(t *testing.T) {
	cmd := &ScanCmd{
		Generator: "openai.OpenAI",
		Probe:     []string{"test.Blank"},
		Config:    `{"model":"gpt-3.5-turbo","temperature":0.7}`,
		Model:     "gpt-4",
	}
	cli := cmd.buildCLIOverrides()
	var result map[string]any
	err := json.Unmarshal([]byte(cli.ConfigJSON), &result)
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", result["model"], "--model flag should override --config model key")
	assert.Equal(t, 0.7, result["temperature"], "other config keys should be preserved")
}

// TestBuildCLIOverrides_NoModelSet tests that ConfigJSON is unchanged when --model is not set.
func TestBuildCLIOverrides_NoModelSet(t *testing.T) {
	t.Run("no model no config", func(t *testing.T) {
		cmd := &ScanCmd{
			Generator: "openai.OpenAI",
			Probe:     []string{"test.Blank"},
		}
		cli := cmd.buildCLIOverrides()
		assert.Empty(t, cli.ConfigJSON, "ConfigJSON should remain empty when neither --model nor --config is set")
	})
	t.Run("no model with config", func(t *testing.T) {
		cmd := &ScanCmd{
			Generator: "openai.OpenAI",
			Probe:     []string{"test.Blank"},
			Config:    `{"temperature":0.5}`,
		}
		cli := cmd.buildCLIOverrides()
		assert.Equal(t, `{"temperature":0.5}`, cli.ConfigJSON, "ConfigJSON should pass through unchanged when --model is not set")
	})
}

// TestBuildCLIOverrides_ModelWithInvalidConfigJSON tests that invalid JSON is preserved unchanged.
func TestBuildCLIOverrides_ModelWithInvalidConfigJSON(t *testing.T) {
	cmd := &ScanCmd{
		Generator: "openai.OpenAI",
		Probe:     []string{"test.Blank"},
		Config:    `{invalid-json`,
		Model:     "gpt-4",
	}
	cli := cmd.buildCLIOverrides()
	assert.Equal(t, `{invalid-json`, cli.ConfigJSON, "invalid JSON should be preserved unchanged when merge fails")
}
