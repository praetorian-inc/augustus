package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadConfigKoanf_BasicYAML tests loading a YAML file with Koanf
func TestLoadConfigKoanf_BasicYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
run:
  max_attempts: 5
  timeout: 30s

generators:
  openai:
    model: gpt-4
    temperature: 0.7
    api_key: test-key

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

	// Load config
	cfg, err := LoadConfigKoanf(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify fields loaded correctly
	assert.Equal(t, 5, cfg.Run.MaxAttempts)
	assert.Equal(t, "30s", cfg.Run.Timeout)
	assert.Equal(t, "gpt-4", cfg.Generators["openai"].Model)
	assert.Equal(t, 0.7, cfg.Generators["openai"].Temperature)
	assert.Equal(t, "test-key", cfg.Generators["openai"].APIKey)
	assert.True(t, cfg.Probes.Encoding.Enabled)
	assert.True(t, cfg.Detectors.Always.Enabled)
	assert.Equal(t, "json", cfg.Output.Format)
	assert.Equal(t, "./results", cfg.Output.Path)
}

// TestLoadConfigKoanf_EmptyPath tests loading with empty config path
func TestLoadConfigKoanf_EmptyPath(t *testing.T) {
	// Empty path should succeed (uses environment variables + defaults)
	cfg, err := LoadConfigKoanf("")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify defaults
	assert.Equal(t, 0, cfg.Run.MaxAttempts)
}

// TestLoadConfigKoanf_EnvironmentVariables tests AUGUSTUS_* env var support
func TestLoadConfigKoanf_EnvironmentVariables(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
run:
  max_attempts: 5
  timeout: 30s

generators:
  openai:
    model: gpt-3.5-turbo
    temperature: 0.5

output:
  format: json
  path: ./results
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Set environment variables (should override YAML)
	os.Setenv("AUGUSTUS_RUN__MAX_ATTEMPTS", "10")
	os.Setenv("AUGUSTUS_RUN__TIMEOUT", "1h")
	os.Setenv("AUGUSTUS_OUTPUT__FORMAT", "jsonl")
	os.Setenv("AUGUSTUS_OUTPUT__PATH", "/tmp/output")
	defer func() {
		os.Unsetenv("AUGUSTUS_RUN__MAX_ATTEMPTS")
		os.Unsetenv("AUGUSTUS_RUN__TIMEOUT")
		os.Unsetenv("AUGUSTUS_OUTPUT__FORMAT")
		os.Unsetenv("AUGUSTUS_OUTPUT__PATH")
	}()

	// Load config with env vars
	cfg, err := LoadConfigKoanf(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Environment variables should override YAML
	assert.Equal(t, 10, cfg.Run.MaxAttempts)
	assert.Equal(t, "1h", cfg.Run.Timeout)
	assert.Equal(t, "jsonl", cfg.Output.Format)
	assert.Equal(t, "/tmp/output", cfg.Output.Path)

	// YAML values without env override should remain
	assert.Equal(t, "gpt-3.5-turbo", cfg.Generators["openai"].Model)
	assert.Equal(t, 0.5, cfg.Generators["openai"].Temperature)
}

// TestLoadConfigKoanf_EnvVarTransformation tests key transformation
func TestLoadConfigKoanf_EnvVarTransformation(t *testing.T) {
	// Test the transformation: AUGUSTUS_RUN__TIMEOUT -> run.timeout
	os.Setenv("AUGUSTUS_RUN__MAX_ATTEMPTS", "7")
	os.Setenv("AUGUSTUS_OUTPUT__FORMAT", "table")
	defer func() {
		os.Unsetenv("AUGUSTUS_RUN__MAX_ATTEMPTS")
		os.Unsetenv("AUGUSTUS_OUTPUT__FORMAT")
	}()

	cfg, err := LoadConfigKoanf("")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify transformation worked
	assert.Equal(t, 7, cfg.Run.MaxAttempts)
	assert.Equal(t, "table", cfg.Output.Format)
}

// TestLoadConfigKoanf_PrecedenceOrder tests ENV > YAML precedence
func TestLoadConfigKoanf_PrecedenceOrder(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
run:
  max_attempts: 3
  timeout: 20s

output:
  format: json
  path: ./yaml-results
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Set environment variables for some (not all) fields
	os.Setenv("AUGUSTUS_RUN__MAX_ATTEMPTS", "8")
	os.Setenv("AUGUSTUS_OUTPUT__FORMAT", "jsonl")
	defer func() {
		os.Unsetenv("AUGUSTUS_RUN__MAX_ATTEMPTS")
		os.Unsetenv("AUGUSTUS_OUTPUT__FORMAT")
	}()

	cfg, err := LoadConfigKoanf(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Environment overrides YAML
	assert.Equal(t, 8, cfg.Run.MaxAttempts)
	assert.Equal(t, "jsonl", cfg.Output.Format)

	// YAML values without env override
	assert.Equal(t, "20s", cfg.Run.Timeout)
	assert.Equal(t, "./yaml-results", cfg.Output.Path)
}

// TestLoadConfigKoanf_Validation tests validator integration
func TestLoadConfigKoanf_Validation(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		envVars     map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			yaml: `
run:
  max_attempts: 5
generators:
  openai:
    temperature: 1.0
output:
  format: json
`,
			expectError: false,
		},
		{
			name: "invalid: negative max_attempts",
			yaml: `
run:
  max_attempts: -1
`,
			expectError: true,
			errorMsg:    "validation failed",
		},
		{
			name: "invalid: temperature too high",
			yaml: `
generators:
  openai:
    temperature: 3.0
`,
			expectError: true,
			errorMsg:    "validation failed",
		},
		{
			name: "invalid: temperature negative",
			yaml: `
generators:
  openai:
    temperature: -0.5
`,
			expectError: true,
			errorMsg:    "validation failed",
		},
		{
			name: "invalid: output format",
			yaml: `
output:
  format: invalid-format
`,
			expectError: true,
			errorMsg:    "validation failed",
		},
		{
			name: "valid: output format from env",
			yaml: `
run:
  max_attempts: 3
`,
			envVars: map[string]string{
				"AUGUSTUS_OUTPUT__FORMAT": "jsonl",
			},
			expectError: false,
		},
		{
			name: "invalid: output format from env",
			yaml: `
run:
  max_attempts: 3
`,
			envVars: map[string]string{
				"AUGUSTUS_OUTPUT__FORMAT": "bad-format",
			},
			expectError: true,
			errorMsg:    "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			err := os.WriteFile(configPath, []byte(tt.yaml), 0644)
			require.NoError(t, err)

			// Set environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			cfg, err := LoadConfigKoanf(configPath)

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

// TestLoadConfigKoanf_InvalidYAML tests handling of malformed YAML
func TestLoadConfigKoanf_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	invalidYAML := `
run:
  max_attempts: 5
  invalid indentation here
generators:
  broken yaml
`

	err := os.WriteFile(configPath, []byte(invalidYAML), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfigKoanf(configPath)
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to load config file")
}

// TestLoadConfigKoanf_NonexistentFile tests handling of missing file
func TestLoadConfigKoanf_NonexistentFile(t *testing.T) {
	cfg, err := LoadConfigKoanf("/nonexistent/path/config.yaml")
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to load config file")
}

// TestLoadConfigKoanf_NestedEnvVars tests nested environment variable keys
func TestLoadConfigKoanf_NestedEnvVars(t *testing.T) {
	// Test nested keys: AUGUSTUS_GENERATORS__OPENAI__MODEL -> generators.openai.model
	os.Setenv("AUGUSTUS_GENERATORS__OPENAI__MODEL", "gpt-4-turbo")
	os.Setenv("AUGUSTUS_GENERATORS__OPENAI__TEMPERATURE", "0.9")
	os.Setenv("AUGUSTUS_GENERATORS__OPENAI__API_KEY", "env-api-key")
	defer func() {
		os.Unsetenv("AUGUSTUS_GENERATORS__OPENAI__MODEL")
		os.Unsetenv("AUGUSTUS_GENERATORS__OPENAI__TEMPERATURE")
		os.Unsetenv("AUGUSTUS_GENERATORS__OPENAI__API_KEY")
	}()

	cfg, err := LoadConfigKoanf("")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify nested env vars loaded
	assert.Equal(t, "gpt-4-turbo", cfg.Generators["openai"].Model)
	assert.Equal(t, 0.9, cfg.Generators["openai"].Temperature)
	assert.Equal(t, "env-api-key", cfg.Generators["openai"].APIKey)
}

// TestLoadConfigKoanf_ComplexMerge tests ENV + YAML merge for nested structures
func TestLoadConfigKoanf_ComplexMerge(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
run:
  max_attempts: 5
  timeout: 30s

generators:
  openai:
    model: gpt-3.5-turbo
    temperature: 0.5
  anthropic:
    model: claude-3-opus
    temperature: 1.0

output:
  format: json
  path: ./yaml-results
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	// Override only specific nested fields via env
	os.Setenv("AUGUSTUS_RUN__TIMEOUT", "1h")
	os.Setenv("AUGUSTUS_GENERATORS__OPENAI__TEMPERATURE", "0.8")
	os.Setenv("AUGUSTUS_OUTPUT__FORMAT", "jsonl")
	defer func() {
		os.Unsetenv("AUGUSTUS_RUN__TIMEOUT")
		os.Unsetenv("AUGUSTUS_GENERATORS__OPENAI__TEMPERATURE")
		os.Unsetenv("AUGUSTUS_OUTPUT__FORMAT")
	}()

	cfg, err := LoadConfigKoanf(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Environment overrides specific fields
	assert.Equal(t, "1h", cfg.Run.Timeout)
	assert.Equal(t, 0.8, cfg.Generators["openai"].Temperature)
	assert.Equal(t, "jsonl", cfg.Output.Format)

	// YAML values without env override remain
	assert.Equal(t, 5, cfg.Run.MaxAttempts)
	assert.Equal(t, "gpt-3.5-turbo", cfg.Generators["openai"].Model)
	assert.Equal(t, "claude-3-opus", cfg.Generators["anthropic"].Model)
	assert.Equal(t, 1.0, cfg.Generators["anthropic"].Temperature)
	assert.Equal(t, "./yaml-results", cfg.Output.Path)
}

// TestLoadConfigKoanf_ProfilesWithEnv tests profiles still work with Koanf
func TestLoadConfigKoanf_ProfilesWithEnv(t *testing.T) {
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

run:
  max_attempts: 5
  timeout: 30s
output:
  format: jsonl
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfigKoanf(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify profiles are loaded (but not applied automatically)
	assert.NotNil(t, cfg.Profiles)
	assert.Contains(t, cfg.Profiles, "production")
	assert.Equal(t, 10, cfg.Profiles["production"].Run.MaxAttempts)
}

// TestLoadConfigKoanf_EmptyConfig tests loading completely empty config
func TestLoadConfigKoanf_EmptyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write empty YAML
	err := os.WriteFile(configPath, []byte(""), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfigKoanf(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Should have zero values
	assert.Equal(t, 0, cfg.Run.MaxAttempts)
	assert.Equal(t, "", cfg.Run.Timeout)
}

// TestLoadConfigKoanf_CaseSensitivity tests case-sensitive key handling
func TestLoadConfigKoanf_CaseSensitivity(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// YAML keys should be case-sensitive
	yamlContent := `
run:
  max_attempts: 5
  Max_Attempts: 10
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfigKoanf(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Should use the correct case key
	assert.Equal(t, 5, cfg.Run.MaxAttempts)
}
