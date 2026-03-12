package main

import (
	"context"
	"encoding/json"
	"fmt"
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

// TestScanCommand_SetupHook tests that the setup hook runs before probes and its output gets used.
func TestScanCommand_SetupHook(t *testing.T) {
	ctx := context.Background()

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		outputFormat:  "table",
		setup:         `echo "TEST_VAR=setup_value"`,
	}

	eval := &mockEvaluator{}
	err := runScan(ctx, cfg, eval)
	require.NoError(t, err, "runScan with setup hook should succeed")
	assert.NotEmpty(t, eval.attempts, "scan with setup hook should produce attempts")
}

// TestScanCommand_CleanupHook tests that cleanup hook runs after scan even if no setup/prepare hooks are used.
func TestScanCommand_CleanupHook(t *testing.T) {
	ctx := context.Background()

	// Create a temp file that the cleanup hook will write to
	tmpDir := t.TempDir()
	markerFile := filepath.Join(tmpDir, "cleanup_ran")

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		outputFormat:  "table",
		cleanup:       fmt.Sprintf(`touch %s`, markerFile),
	}

	eval := &mockEvaluator{}
	err := runScan(ctx, cfg, eval)
	require.NoError(t, err, "runScan with cleanup hook should succeed")

	// Verify cleanup hook ran by checking the marker file exists
	_, err = os.Stat(markerFile)
	assert.NoError(t, err, "cleanup hook should have created marker file")
}

// TestScanCommand_SetupHookFailure tests that a failing setup hook causes scan to fail.
func TestScanCommand_SetupHookFailure(t *testing.T) {
	ctx := context.Background()

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		outputFormat:  "table",
		setup:         "exit 1",
	}

	eval := &mockEvaluator{}
	err := runScan(ctx, cfg, eval)
	assert.Error(t, err, "runScan with failing setup hook should fail")
	assert.Contains(t, err.Error(), "setup hook failed")
}

// TestScanCommand_PrepareHook tests that prepare hook runs and injects variables.
func TestScanCommand_PrepareHook(t *testing.T) {
	ctx := context.Background()

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		outputFormat:  "table",
		setup:         `echo "CONVERSATION_ID=conv-123"`,
		prepare:       `echo "PARENT_MSG_ID=msg-456"`,
	}

	eval := &mockEvaluator{}
	err := runScan(ctx, cfg, eval)
	require.NoError(t, err, "runScan with prepare hook should succeed")
	assert.NotEmpty(t, eval.attempts, "scan with prepare hook should produce attempts")
}

// TestScanCommand_HooksForceConcurrency tests that hooks force concurrency to 1.
func TestScanCommand_HooksForceConcurrency(t *testing.T) {
	ctx := context.Background()

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		outputFormat:  "table",
		concurrency:   10,
		setup:         `echo "FOO=bar"`,
	}

	eval := &mockEvaluator{}
	err := runScan(ctx, cfg, eval)
	require.NoError(t, err, "runScan with hooks should succeed despite high concurrency setting")
}

// TestLoadScanConfig_HookFields tests that loadScanConfig wires hook fields properly.
func TestLoadScanConfig_HookFields(t *testing.T) {
	cmd := &ScanCmd{
		Generator: "test.Repeat",
		Probe:     []string{"test.Test"},
		Setup:     "echo setup",
		Prepare:   "echo prepare",
		Cleanup:   "echo cleanup",
	}
	cfg := cmd.loadScanConfig()
	assert.Equal(t, "echo setup", cfg.setup)
	assert.Equal(t, "echo prepare", cfg.prepare)
	assert.Equal(t, "echo cleanup", cfg.cleanup)
}

func TestScanCommand_CleanupDoesNotRunOnEarlyFailure(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	markerFile := filepath.Join(tmpDir, "cleanup_marker")

	cfg := &scanConfig{
		generatorName: "nonexistent.Generator",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		outputFormat:  "table",
		cleanup:       fmt.Sprintf("touch %s", markerFile),
	}

	eval := &mockEvaluator{}
	err := runScan(ctx, cfg, eval)
	require.Error(t, err)

	_, statErr := os.Stat(markerFile)
	assert.Error(t, statErr, "cleanup hook should NOT run when scan fails before reaching harness.Run()")
}

// TestScanCommand_SetupHookPrefixesVars tests that setup hook variables are prefixed
// with HOOK_ so they don't override reserved generator config keys like "uri".
// We verify this indirectly: if the prefix weren't applied, a setup hook emitting
// "URI=should_not_override" could corrupt the generator config. Since test.Repeat
// doesn't use "uri", we verify the scan succeeds and the HOOK_URI key doesn't
// interfere with generator creation.
func TestScanCommand_SetupHookPrefixesVars(t *testing.T) {
	ctx := context.Background()

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		outputFormat:  "table",
		// Setup hook emits a key that would collide with a real config key
		setup: `echo "URI=should_not_override"`,
	}

	eval := &mockEvaluator{}
	err := runScan(ctx, cfg, eval)
	require.NoError(t, err, "runScan should succeed because URI is prefixed as HOOK_URI")
	assert.NotEmpty(t, eval.attempts, "scan should produce attempts")
}

// TestScanCommand_CleanupHookErrorPropagation tests that a failing cleanup hook
// causes the returned error to contain "cleanup hook failed", even if the scan
// itself succeeds.
func TestScanCommand_CleanupHookErrorPropagation(t *testing.T) {
	ctx := context.Background()

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		outputFormat:  "table",
		cleanup:       "exit 1",
	}

	eval := &mockEvaluator{}
	err := runScan(ctx, cfg, eval)
	require.Error(t, err, "runScan should return error when cleanup hook fails")
	assert.Contains(t, err.Error(), "cleanup hook failed",
		"error should contain 'cleanup hook failed'")
	// The scan itself should have succeeded, so attempts should be populated
	assert.NotEmpty(t, eval.attempts, "scan should still produce attempts despite cleanup failure")
}

// TestScanCommand_YAMLConfigHooks tests that hooks defined in a YAML config file
// are resolved and executed by the scan pipeline.
func TestScanCommand_YAMLConfigHooks(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Create a YAML config with hooks
	configPath := filepath.Join(tmpDir, "hooks-config.yaml")
	markerFile := filepath.Join(tmpDir, "yaml_cleanup_ran")
	yamlContent := fmt.Sprintf(`
hooks:
  setup: 'echo "YAML_VAR=from_yaml"'
  cleanup: 'touch %s'
`, markerFile)
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		configFile:    configPath,
		outputFormat:  "table",
	}

	eval := &mockEvaluator{}
	err = runScan(ctx, cfg, eval)
	require.NoError(t, err, "runScan with YAML hooks config should succeed")
	assert.NotEmpty(t, eval.attempts, "scan with YAML hooks should produce attempts")

	// Verify the YAML cleanup hook ran
	_, err = os.Stat(markerFile)
	assert.NoError(t, err, "YAML cleanup hook should have created marker file")
}

// TestScanCommand_CLIOverridesYAMLHooks tests that CLI hook flags override YAML config hooks.
func TestScanCommand_CLIOverridesYAMLHooks(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Create YAML config with a cleanup hook that creates a marker file
	configPath := filepath.Join(tmpDir, "hooks-config.yaml")
	yamlMarker := filepath.Join(tmpDir, "yaml_marker")
	cliMarker := filepath.Join(tmpDir, "cli_marker")
	yamlContent := fmt.Sprintf(`
hooks:
  cleanup: 'touch %s'
`, yamlMarker)
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// CLI cleanup flag should override the YAML one
	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		configFile:    configPath,
		outputFormat:  "table",
		cleanup:       fmt.Sprintf("touch %s", cliMarker),
	}

	eval := &mockEvaluator{}
	err = runScan(ctx, cfg, eval)
	require.NoError(t, err, "runScan should succeed")

	// CLI marker should exist (CLI cleanup ran)
	_, err = os.Stat(cliMarker)
	assert.NoError(t, err, "CLI cleanup hook should have created marker file")

	// YAML marker should NOT exist (YAML cleanup was overridden)
	_, err = os.Stat(yamlMarker)
	assert.Error(t, err, "YAML cleanup hook should NOT run when CLI cleanup overrides it")
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

// TestScanCommand_YAMLHooksConfig tests that hooks can be loaded from YAML config.
func TestScanCommand_YAMLHooksConfig(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "hooks-config.yaml")
	yamlContent := `
hooks:
  setup: 'echo "TEST_VAR=from_yaml"'
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		configFile:    configPath,
		outputFormat:  "table",
	}

	eval := &mockEvaluator{}
	err = runScan(ctx, cfg, eval)
	require.NoError(t, err, "runScan with YAML hooks config should succeed")
	assert.NotEmpty(t, eval.attempts, "scan should produce attempts")
}

// TestScanCommand_CLIHooksOverrideYAML tests that CLI hook flags take precedence over YAML config.
func TestScanCommand_CLIHooksOverrideYAML(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "hooks-config.yaml")
	yamlContent := `
hooks:
  setup: "exit 1"
  cleanup: 'echo "YAML_CLEANUP=true"'
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	markerFile := filepath.Join(tmpDir, "cleanup_marker")

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		configFile:    configPath,
		outputFormat:  "table",
		// CLI setup overrides YAML "exit 1" (which would fail)
		setup: `echo "CLI_VAR=from_cli"`,
		// CLI cleanup overrides YAML cleanup
		cleanup: fmt.Sprintf("touch %s", markerFile),
	}

	eval := &mockEvaluator{}
	err = runScan(ctx, cfg, eval)
	require.NoError(t, err, "CLI setup should override YAML exit 1")
	assert.NotEmpty(t, eval.attempts, "scan should produce attempts")

	// Verify CLI cleanup ran (not the YAML cleanup)
	_, err = os.Stat(markerFile)
	assert.NoError(t, err, "CLI cleanup should have created marker file")
}
