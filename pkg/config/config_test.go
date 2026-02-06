package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
