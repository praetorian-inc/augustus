package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestBasicYAMLLoading tests loading a single YAML configuration file
func TestBasicYAMLLoading(t *testing.T) {
	// Create a temporary YAML file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
run:
  max_attempts: 5
  timeout: 30s

generators:
  huggingface:
    model: gpt2
    temperature: 0.7

probes:
  encoding:
    enabled: true

detectors:
  always:
    enabled: true

output:
  format: json
  path: ./results
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Load the config
	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify fields are loaded correctly
	assert.Equal(t, 5, cfg.Run.MaxAttempts)
	assert.Equal(t, "30s", cfg.Run.Timeout)
	assert.Equal(t, "gpt2", cfg.Generators["huggingface"].Model)
	assert.Equal(t, 0.7, cfg.Generators["huggingface"].Temperature)
	assert.True(t, cfg.Probes.Encoding.Enabled)
	assert.True(t, cfg.Detectors.Always.Enabled)
	assert.Equal(t, "json", cfg.Output.Format)
	assert.Equal(t, "./results", cfg.Output.Path)
}

// TestHierarchicalMerge tests merging multiple configuration files
func TestHierarchicalMerge(t *testing.T) {
	tmpDir := t.TempDir()

	// Base config
	baseConfig := filepath.Join(tmpDir, "base.yaml")
	baseYAML := `
run:
  max_attempts: 3
  timeout: 20s

generators:
  huggingface:
    model: gpt2
    temperature: 0.5

output:
  format: json
  path: ./results
`
	err := os.WriteFile(baseConfig, []byte(baseYAML), 0644)
	require.NoError(t, err)

	// Site config (overrides some base values)
	siteConfig := filepath.Join(tmpDir, "site.yaml")
	siteYAML := `
run:
  max_attempts: 5
  # timeout inherited from base

generators:
  huggingface:
    temperature: 0.7  # Override temperature
    # model inherited from base

output:
  format: jsonl  # Override format
  # path inherited from base
`
	err = os.WriteFile(siteConfig, []byte(siteYAML), 0644)
	require.NoError(t, err)

	// Load with hierarchical merge
	cfg, err := LoadConfig(baseConfig, siteConfig)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify merged values
	assert.Equal(t, 5, cfg.Run.MaxAttempts)           // From site (overridden)
	assert.Equal(t, "20s", cfg.Run.Timeout)           // From base (inherited)
	assert.Equal(t, "gpt2", cfg.Generators["huggingface"].Model) // From base (inherited)
	assert.Equal(t, 0.7, cfg.Generators["huggingface"].Temperature) // From site (overridden)
	assert.Equal(t, "jsonl", cfg.Output.Format)       // From site (overridden)
	assert.Equal(t, "./results", cfg.Output.Path)     // From base (inherited)
}

// TestEnvironmentVariableInterpolation tests ${VAR} expansion
func TestEnvironmentVariableInterpolation(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Set environment variables
	os.Setenv("AUGUSTUS_API_KEY", "test-api-key-123")
	os.Setenv("AUGUSTUS_OUTPUT_DIR", "/tmp/augustus-output")
	defer func() {
		os.Unsetenv("AUGUSTUS_API_KEY")
		os.Unsetenv("AUGUSTUS_OUTPUT_DIR")
	}()

	yamlContent := `
generators:
  huggingface:
    api_key: ${AUGUSTUS_API_KEY}
    model: gpt2

output:
  path: ${AUGUSTUS_OUTPUT_DIR}
  format: json
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Load config with env var interpolation
	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify environment variables were interpolated
	assert.Equal(t, "test-api-key-123", cfg.Generators["huggingface"].APIKey)
	assert.Equal(t, "/tmp/augustus-output", cfg.Output.Path)
}

// TestMissingEnvironmentVariable tests handling of undefined env vars
func TestMissingEnvironmentVariable(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Ensure env var is NOT set
	os.Unsetenv("AUGUSTUS_MISSING_VAR")

	yamlContent := `
generators:
  huggingface:
    api_key: ${AUGUSTUS_MISSING_VAR}
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Loading should fail with helpful error
	cfg, err := LoadConfig(configPath)
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "AUGUSTUS_MISSING_VAR")
	assert.Contains(t, err.Error(), "not set")
}

// TestValidation tests configuration validation
func TestValidation(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			yaml: `
run:
  max_attempts: 5
output:
  format: json
`,
			expectError: false,
		},
		{
			name: "invalid max_attempts (negative)",
			yaml: `
run:
  max_attempts: -1
`,
			expectError: true,
			errorMsg:    "max_attempts must be non-negative",
		},
		{
			name: "invalid output format",
			yaml: `
output:
  format: invalid-format
`,
			expectError: true,
			errorMsg:    "invalid output format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			err := os.WriteFile(configPath, []byte(tt.yaml), 0644)
			require.NoError(t, err)

			cfg, err := LoadConfig(configPath)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, cfg)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
			}
		})
	}
}

// TestProfileSystem tests loading named configuration profiles
func TestProfileSystem(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
profiles:
  production:
    run:
      max_attempts: 10
      timeout: 60s
    output:
      format: json

  development:
    run:
      max_attempts: 3
      timeout: 10s
    output:
      format: jsonl

run:
  max_attempts: 5
  timeout: 30s
output:
  format: json
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Test loading production profile
	cfg, err := LoadConfigWithProfile(configPath, "production")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, 10, cfg.Run.MaxAttempts)
	assert.Equal(t, "60s", cfg.Run.Timeout)

	// Test loading development profile
	cfg, err = LoadConfigWithProfile(configPath, "development")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, 3, cfg.Run.MaxAttempts)
	assert.Equal(t, "10s", cfg.Run.Timeout)
	assert.Equal(t, "jsonl", cfg.Output.Format)

	// Test loading without profile (uses base)
	cfg, err = LoadConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, 5, cfg.Run.MaxAttempts)
}

// TestInvalidYAML tests handling of malformed YAML
func TestInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	invalidYAML := `
run:
  max_attempts: 5
  invalid indentation
generators:
  huggingface
`

	err := os.WriteFile(configPath, []byte(invalidYAML), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfig(configPath)
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "yaml")
}

// TestNonexistentFile tests handling of missing config files
func TestNonexistentFile(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/config.yaml")
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

// TestConcurrencyAndProbeTimeout tests loading new concurrency and probe_timeout fields
func TestConcurrencyAndProbeTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
run:
  max_attempts: 5
  timeout: 30m
  concurrency: 20
  probe_timeout: 10m

generators:
  openai:
    model: gpt-4
    temperature: 0.7

output:
  format: json
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Load the config
	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify fields are loaded correctly
	assert.Equal(t, 5, cfg.Run.MaxAttempts)
	assert.Equal(t, "30m", cfg.Run.Timeout)
	assert.Equal(t, 20, cfg.Run.Concurrency)
	assert.Equal(t, "10m", cfg.Run.ProbeTimeout)
}

// TestConcurrencyValidation tests concurrency validation
func TestConcurrencyValidation(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid concurrency",
			yaml: `
run:
  concurrency: 10
`,
			expectError: false,
		},
		{
			name: "negative concurrency",
			yaml: `
run:
  concurrency: -5
`,
			expectError: true,
			errorMsg:    "concurrency must be non-negative",
		},
		{
			name: "zero concurrency (treated as not set)",
			yaml: `
run:
  concurrency: 0
`,
			expectError: false, // 0 means not set, should be valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			err := os.WriteFile(configPath, []byte(tt.yaml), 0644)
			require.NoError(t, err)

			cfg, err := LoadConfig(configPath)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, cfg)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
			}
		})
	}
}

// TestProbeTimeoutValidation tests probe_timeout validation
func TestProbeTimeoutValidation(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid probe_timeout",
			yaml: `
run:
  probe_timeout: 5m
`,
			expectError: false,
		},
		{
			name: "invalid probe_timeout format",
			yaml: `
run:
  probe_timeout: invalid-duration
`,
			expectError: true,
			errorMsg:    "invalid run.probe_timeout",
		},
		{
			name: "probe_timeout with seconds",
			yaml: `
run:
  probe_timeout: 30s
`,
			expectError: false,
		},
		{
			name: "probe_timeout with hours",
			yaml: `
run:
  probe_timeout: 2h
`,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			err := os.WriteFile(configPath, []byte(tt.yaml), 0644)
			require.NoError(t, err)

			cfg, err := LoadConfig(configPath)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, cfg)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
			}
		})
	}
}

// TestMergeWithConcurrencyAndProbeTimeout tests merging configs with new fields
func TestMergeWithConcurrencyAndProbeTimeout(t *testing.T) {
	tmpDir := t.TempDir()

	// Base config
	baseConfig := filepath.Join(tmpDir, "base.yaml")
	baseYAML := `
run:
  max_attempts: 3
  timeout: 20m
  concurrency: 10
  probe_timeout: 5m

generators:
  openai:
    model: gpt-4
    temperature: 0.5
`
	err := os.WriteFile(baseConfig, []byte(baseYAML), 0644)
	require.NoError(t, err)

	// Override config (overrides some base values)
	overrideConfig := filepath.Join(tmpDir, "override.yaml")
	overrideYAML := `
run:
  max_attempts: 5
  concurrency: 25
  # timeout and probe_timeout inherited from base

generators:
  openai:
    temperature: 0.8
`
	err = os.WriteFile(overrideConfig, []byte(overrideYAML), 0644)
	require.NoError(t, err)

	// Load with hierarchical merge
	cfg, err := LoadConfig(baseConfig, overrideConfig)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify merged values
	assert.Equal(t, 5, cfg.Run.MaxAttempts)       // From override
	assert.Equal(t, "20m", cfg.Run.Timeout)       // From base (inherited)
	assert.Equal(t, 25, cfg.Run.Concurrency)      // From override
	assert.Equal(t, "5m", cfg.Run.ProbeTimeout)   // From base (inherited)
	assert.Equal(t, "gpt-4", cfg.Generators["openai"].Model) // From base
	assert.Equal(t, 0.8, cfg.Generators["openai"].Temperature) // From override
}

// TestDefaultConcurrencyAndProbeTimeout tests that defaults are applied when not specified
func TestDefaultConcurrencyAndProbeTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
run:
  max_attempts: 5
  timeout: 30m
  # concurrency and probe_timeout not specified

generators:
  openai:
    model: gpt-4

output:
  format: json
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify defaults are applied (0 values since not specified in YAML)
	assert.Equal(t, 0, cfg.Run.Concurrency)    // 0 means "not set", default applied in scanner
	assert.Equal(t, "", cfg.Run.ProbeTimeout)  // empty means "not set", default applied in scanner
}

// TestBuffsYAML tests loading buff configuration from YAML
func TestBuffsYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
buffs:
  names:
    - encoding.Base64
    - lrl.LRLBuff
  settings:
    lrl.LRLBuff:
      api_key: test-key
      rate_limit: 5.0
      burst_size: 10.0
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify buffs are loaded correctly
	assert.Equal(t, []string{"encoding.Base64", "lrl.LRLBuff"}, cfg.Buffs.Names)
	assert.NotNil(t, cfg.Buffs.Settings["lrl.LRLBuff"])
	assert.Equal(t, "test-key", cfg.Buffs.Settings["lrl.LRLBuff"]["api_key"])
	assert.Equal(t, 5.0, cfg.Buffs.Settings["lrl.LRLBuff"]["rate_limit"])
	assert.Equal(t, 10.0, cfg.Buffs.Settings["lrl.LRLBuff"]["burst_size"])
}

// TestBuffsMerge tests merging buff configuration
func TestBuffsMerge(t *testing.T) {
	base := &Config{
		Buffs: BuffConfig{
			Names: []string{"encoding.Base64"},
		},
	}
	overlay := &Config{
		Buffs: BuffConfig{
			Names: []string{"lrl.LRLBuff"},
			Settings: map[string]map[string]any{
				"lrl.LRLBuff": {"rate_limit": 5.0},
			},
		},
	}

	base.Merge(overlay)

	// Overlay should win
	assert.Equal(t, []string{"lrl.LRLBuff"}, base.Buffs.Names)
	assert.NotNil(t, base.Buffs.Settings["lrl.LRLBuff"])
	assert.Equal(t, 5.0, base.Buffs.Settings["lrl.LRLBuff"]["rate_limit"])
}

// TestResolveProbeConfig tests the two-layer probe config resolution
func TestResolveProbeConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		probeName string
		wantKeys  map[string]any
	}{
		{
			name: "global attacker/judge config propagates",
			config: Config{
				Probes: ProbeConfig{
					AttackerGeneratorType: "anthropic.Anthropic",
					AttackerConfig:        map[string]any{"model": "claude-sonnet-4-20250514"},
					JudgeGeneratorType:    "anthropic.Anthropic",
					JudgeConfig:           map[string]any{"model": "claude-sonnet-4-20250514"},
				},
			},
			probeName: "pair.IterativePAIR",
			wantKeys: map[string]any{
				"attacker_generator_type": "anthropic.Anthropic",
				"attacker_config":         map[string]any{"model": "claude-sonnet-4-20250514"},
				"judge_generator_type":    "anthropic.Anthropic",
				"judge_config":            map[string]any{"model": "claude-sonnet-4-20250514"},
			},
		},
		{
			name: "per-probe settings override globals",
			config: Config{
				Probes: ProbeConfig{
					AttackerGeneratorType: "openai.OpenAI",
					Settings: map[string]map[string]any{
						"tap.IterativeTAP": {
							"attacker_generator_type": "anthropic.Anthropic",
						},
					},
				},
			},
			probeName: "tap.IterativeTAP",
			wantKeys: map[string]any{
				"attacker_generator_type": "anthropic.Anthropic", // per-probe wins
			},
		},
		{
			name: "empty config returns empty map",
			config: Config{
				Probes: ProbeConfig{},
			},
			probeName: "any.Probe",
			wantKeys:  map[string]any{},
		},
		{
			name: "unknown probe name returns only globals",
			config: Config{
				Probes: ProbeConfig{
					AttackerGeneratorType: "openai.OpenAI",
					Settings: map[string]map[string]any{
						"pair.IterativePAIR": {"extra": "value"},
					},
				},
			},
			probeName: "unknown.Probe",
			wantKeys: map[string]any{
				"attacker_generator_type": "openai.OpenAI",
			},
		},
		{
			name: "per-probe override preserves non-overridden globals",
			config: Config{
				Probes: ProbeConfig{
					AttackerGeneratorType: "openai.OpenAI",
					AttackerConfig:        map[string]any{"model": "gpt-4"},
					JudgeGeneratorType:    "anthropic.Anthropic",
					JudgeConfig:           map[string]any{"model": "claude-sonnet"},
					Settings: map[string]map[string]any{
						"tap.IterativeTAP": {
							"attacker_generator_type": "local.Ollama",
						},
					},
				},
			},
			probeName: "tap.IterativeTAP",
			wantKeys: map[string]any{
				"attacker_generator_type": "local.Ollama",                       // overridden
				"attacker_config":         map[string]any{"model": "gpt-4"},     // preserved
				"judge_generator_type":    "anthropic.Anthropic",                // preserved
				"judge_config":            map[string]any{"model": "claude-sonnet"}, // preserved
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.ResolveProbeConfig(tt.probeName)
			assert.Equal(t, tt.wantKeys, result)
		})
	}
}

// TestResolveDetectorConfig tests detector config resolution
func TestResolveDetectorConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       Config
		detectorName string
		wantKeys     map[string]any
	}{
		{
			name: "per-detector settings resolve",
			config: Config{
				Detectors: DetectorConfig{
					Settings: map[string]map[string]any{
						"poetry.HarmJudge": {
							"judge_generator": "anthropic.Anthropic",
						},
					},
				},
			},
			detectorName: "poetry.HarmJudge",
			wantKeys: map[string]any{
				"judge_generator": "anthropic.Anthropic",
			},
		},
		{
			name: "unknown detector returns empty map",
			config: Config{
				Detectors: DetectorConfig{
					Settings: map[string]map[string]any{
						"poetry.HarmJudge": {"key": "value"},
					},
				},
			},
			detectorName: "unknown.Detector",
			wantKeys:     map[string]any{},
		},
		{
			name: "nil settings returns empty map",
			config: Config{
				Detectors: DetectorConfig{},
			},
			detectorName: "any.Detector",
			wantKeys:     map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.ResolveDetectorConfig(tt.detectorName)
			assert.Equal(t, tt.wantKeys, result)
		})
	}
}

// TestResolveBuffConfig tests buff config resolution
func TestResolveBuffConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		buffName string
		wantKeys map[string]any
	}{
		{
			name: "per-buff settings resolve",
			config: Config{
				Buffs: BuffConfig{
					Settings: map[string]map[string]any{
						"conlang.Klingon": {
							"transform_generator": "anthropic.Anthropic",
						},
					},
				},
			},
			buffName: "conlang.Klingon",
			wantKeys: map[string]any{
				"transform_generator": "anthropic.Anthropic",
			},
		},
		{
			name: "unknown buff returns empty map",
			config: Config{
				Buffs: BuffConfig{
					Settings: map[string]map[string]any{
						"conlang.Klingon": {"key": "value"},
					},
				},
			},
			buffName: "unknown.Buff",
			wantKeys: map[string]any{},
		},
		{
			name: "nil settings returns empty map",
			config: Config{
				Buffs: BuffConfig{},
			},
			buffName: "any.Buff",
			wantKeys: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.ResolveBuffConfig(tt.buffName)
			assert.Equal(t, tt.wantKeys, result)
		})
	}
}

// TestNestedEnvVarInterpolation tests that env vars in nested config maps are resolved
func TestNestedEnvVarInterpolation(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	os.Setenv("AUGUSTUS_ANTHROPIC_KEY", "sk-ant-test-123")
	defer os.Unsetenv("AUGUSTUS_ANTHROPIC_KEY")

	yamlContent := `
probes:
  attacker_generator_type: anthropic.Anthropic
  attacker_config:
    api_key: ${AUGUSTUS_ANTHROPIC_KEY}
    model: claude-sonnet-4-20250514

buffs:
  names:
    - conlang.Klingon
  settings:
    conlang.Klingon:
      transform_generator: anthropic.Anthropic
      transform_generator_config:
        api_key: ${AUGUSTUS_ANTHROPIC_KEY}

detectors:
  settings:
    poetry.HarmJudge:
      judge_generator_config:
        api_key: ${AUGUSTUS_ANTHROPIC_KEY}
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify env var was interpolated in nested probe config
	assert.Equal(t, "sk-ant-test-123", cfg.Probes.AttackerConfig["api_key"])
	assert.Equal(t, "claude-sonnet-4-20250514", cfg.Probes.AttackerConfig["model"])

	// Verify env var was interpolated in nested buff settings
	klingonCfg := cfg.Buffs.Settings["conlang.Klingon"]
	require.NotNil(t, klingonCfg)
	genCfg, ok := klingonCfg["transform_generator_config"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "sk-ant-test-123", genCfg["api_key"])

	// Verify env var was interpolated in nested detector settings
	harmCfg := cfg.Detectors.Settings["poetry.HarmJudge"]
	require.NotNil(t, harmCfg)
	judgeCfg, ok := harmCfg["judge_generator_config"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "sk-ant-test-123", judgeCfg["api_key"])
}

func TestGeneratorConfig_ExtraFieldsCaptured(t *testing.T) {
	yamlData := []byte(`
generators:
  openai.OpenAI:
    model: gpt-4
    temperature: 0.7
    api_key: sk-test
    max_tokens: 4096
    base_url: https://custom.api.com
    top_p: 0.9
`)
	var cfg Config
	err := yaml.Unmarshal(yamlData, &cfg)
	require.NoError(t, err)

	gen := cfg.Generators["openai.OpenAI"]
	assert.Equal(t, "gpt-4", gen.Model)
	assert.Equal(t, 0.7, gen.Temperature)
	assert.Equal(t, "sk-test", gen.APIKey)
	assert.Equal(t, 4096, gen.Extra["max_tokens"])
	assert.Equal(t, "https://custom.api.com", gen.Extra["base_url"])
	assert.Equal(t, 0.9, gen.Extra["top_p"])
}

// TestGeneratorConfig_ToRegistryConfig tests converting GeneratorConfig to registry config map
func TestGeneratorConfig_ToRegistryConfig(t *testing.T) {
	gen := GeneratorConfig{
		Model:       "gpt-4",
		Temperature: 0.7,
		APIKey:      "sk-test",
		RateLimit:   10.5,
		Extra: map[string]any{
			"max_tokens": 4096,
			"base_url":   "https://custom.api.com",
			"top_p":      0.9,
		},
	}

	result := gen.ToRegistryConfig()

	// Typed fields should be in the map
	assert.Equal(t, "gpt-4", result["model"])
	assert.Equal(t, 0.7, result["temperature"])
	assert.Equal(t, "sk-test", result["api_key"])
	assert.Equal(t, 10.5, result["rate_limit"])

	// Extra fields should also be in the map
	assert.Equal(t, 4096, result["max_tokens"])
	assert.Equal(t, "https://custom.api.com", result["base_url"])
	assert.Equal(t, 0.9, result["top_p"])
}

// TestGeneratorConfig_ToRegistryConfig_TemperatureZero tests that temperature:0 is preserved
func TestGeneratorConfig_ToRegistryConfig_TemperatureZero(t *testing.T) {
	gen := GeneratorConfig{
		Model:       "gpt-4",
		Temperature: 0.0, // Explicitly zero
		APIKey:      "sk-test",
	}

	result := gen.ToRegistryConfig()

	// Zero temperature must be preserved (not omitted)
	assert.Equal(t, 0.0, result["temperature"])
	assert.Contains(t, result, "temperature")
}

// TestGeneratorConfig_ToRegistryConfig_ExtraOverridesTypedFields tests that Extra fields override typed fields
func TestGeneratorConfig_ToRegistryConfig_ExtraOverridesTypedFields(t *testing.T) {
	gen := GeneratorConfig{
		Model:       "gpt-4",
		Temperature: 0.7,
		Extra: map[string]any{
			"model":       "gpt-3.5-turbo", // Override model
			"temperature": 0.9,             // Override temperature
			"custom":      "value",         // Extra field
		},
	}

	result := gen.ToRegistryConfig()

	// Extra fields should override typed fields
	assert.Equal(t, "gpt-3.5-turbo", result["model"])
	assert.Equal(t, 0.9, result["temperature"])
	assert.Equal(t, "value", result["custom"])
}

// TestConfig_Validate_InvalidTimeout tests that Validate() rejects invalid timeout format
func TestConfig_Validate_InvalidTimeout(t *testing.T) {
	cfg := &Config{
		Run: RunConfig{Timeout: "not-a-duration"},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "run.timeout")
}

// TestConfig_Validate_ValidTimeout tests that Validate() accepts valid timeout format
func TestConfig_Validate_ValidTimeout(t *testing.T) {
	cfg := &Config{
		Run: RunConfig{Timeout: "30s"},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}
