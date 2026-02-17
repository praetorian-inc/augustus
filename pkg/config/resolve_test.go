package config

import (
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve_DefaultsOnly(t *testing.T) {
	cli := CLIOverrides{GeneratorName: "openai.OpenAI"}
	resolved, err := Resolve(nil, cli)
	require.NoError(t, err)

	defaults := scanner.DefaultOptions()
	assert.Equal(t, defaults.Concurrency, resolved.ScannerOpts.Concurrency)
	assert.Equal(t, defaults.Timeout, resolved.ScannerOpts.Timeout)
	assert.Equal(t, defaults.ProbeTimeout, resolved.ScannerOpts.ProbeTimeout)
	assert.Equal(t, defaults.RetryCount, resolved.ScannerOpts.RetryCount)
	assert.Equal(t, "table", resolved.OutputFormat)
	assert.Empty(t, resolved.OutputFile)
	assert.Empty(t, resolved.GeneratorConfig)
}

func TestResolve_YAMLOverridesDefaults(t *testing.T) {
	yamlCfg := &Config{
		Run: RunConfig{
			Concurrency:  20,
			Timeout:      "1h",
			ProbeTimeout: "10m",
			MaxAttempts:  3,
		},
		Generators: map[string]GeneratorConfig{
			"openai.OpenAI": {
				Model:       "gpt-4",
				Temperature: 0.5,
				APIKey:      "sk-test",
				Extra:       map[string]any{"max_tokens": 4096},
			},
		},
		Output: OutputConfig{Format: "jsonl", Path: "/tmp/results.jsonl"},
	}
	cli := CLIOverrides{GeneratorName: "openai.OpenAI"}

	resolved, err := Resolve(yamlCfg, cli)
	require.NoError(t, err)

	assert.Equal(t, 20, resolved.ScannerOpts.Concurrency)
	assert.Equal(t, 1*time.Hour, resolved.ScannerOpts.Timeout)
	assert.Equal(t, 10*time.Minute, resolved.ScannerOpts.ProbeTimeout)
	assert.Equal(t, 3, resolved.ScannerOpts.RetryCount)
	assert.Equal(t, "gpt-4", resolved.GeneratorConfig["model"])
	assert.Equal(t, 0.5, resolved.GeneratorConfig["temperature"])
	assert.Equal(t, 4096, resolved.GeneratorConfig["max_tokens"])
	assert.Equal(t, "jsonl", resolved.OutputFormat)
	assert.Equal(t, "/tmp/results.jsonl", resolved.OutputFile)
}

func TestResolve_CLIOverridesYAML(t *testing.T) {
	yamlCfg := &Config{
		Run: RunConfig{
			Concurrency:  20,
			Timeout:      "1h",
			ProbeTimeout: "10m",
		},
	}

	// CLI provides explicit overrides via pointer fields
	concurrency := 50
	timeout := 30 * time.Minute
	probeTimeout := 5 * time.Minute

	cli := CLIOverrides{
		GeneratorName: "openai.OpenAI",
		Concurrency:   &concurrency,
		Timeout:       &timeout,
		ProbeTimeout:  &probeTimeout,
	}

	resolved, err := Resolve(yamlCfg, cli)
	require.NoError(t, err)

	// CLI pointer values override YAML
	assert.Equal(t, 50, resolved.ScannerOpts.Concurrency)
	assert.Equal(t, 30*time.Minute, resolved.ScannerOpts.Timeout)
	assert.Equal(t, 5*time.Minute, resolved.ScannerOpts.ProbeTimeout)
}

func TestResolve_CLINilDoesNotOverrideYAML(t *testing.T) {
	yamlCfg := &Config{
		Run: RunConfig{
			Concurrency:  20,
			Timeout:      "1h",
			ProbeTimeout: "10m",
		},
	}

	// CLI provides no overrides (nil pointers)
	cli := CLIOverrides{
		GeneratorName: "openai.OpenAI",
		Concurrency:   nil,
		Timeout:       nil,
		ProbeTimeout:  nil,
	}

	resolved, err := Resolve(yamlCfg, cli)
	require.NoError(t, err)

	// YAML values preserved when CLI pointers are nil
	assert.Equal(t, 20, resolved.ScannerOpts.Concurrency)
	assert.Equal(t, 1*time.Hour, resolved.ScannerOpts.Timeout)
	assert.Equal(t, 10*time.Minute, resolved.ScannerOpts.ProbeTimeout)
}

func TestResolve_TemperatureZeroIsValid(t *testing.T) {
	yamlCfg := &Config{
		Generators: map[string]GeneratorConfig{
			"openai.OpenAI": {Model: "gpt-4", Temperature: 0.0},
		},
	}
	cli := CLIOverrides{GeneratorName: "openai.OpenAI"}

	resolved, err := Resolve(yamlCfg, cli)
	require.NoError(t, err)

	temp, exists := resolved.GeneratorConfig["temperature"]
	assert.True(t, exists, "temperature=0.0 must be present")
	assert.Equal(t, 0.0, temp)
}

func TestResolve_NoYAMLWithCLIJSON(t *testing.T) {
	cli := CLIOverrides{
		GeneratorName: "openai.OpenAI",
		ConfigJSON:    `{"model":"gpt-4","api_key":"sk-test"}`,
	}

	resolved, err := Resolve(nil, cli)
	require.NoError(t, err)

	assert.Equal(t, "gpt-4", resolved.GeneratorConfig["model"])
	assert.Equal(t, "sk-test", resolved.GeneratorConfig["api_key"])
}

func TestResolve_InvalidYAMLTimeout(t *testing.T) {
	yamlCfg := &Config{Run: RunConfig{Timeout: "not-a-duration"}}
	cli := CLIOverrides{GeneratorName: "openai.OpenAI"}

	_, err := Resolve(yamlCfg, cli)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid run.timeout")
}

func TestResolve_InvalidCLIJSON(t *testing.T) {
	cli := CLIOverrides{
		GeneratorName: "openai.OpenAI",
		ConfigJSON:    `{invalid`,
	}

	_, err := Resolve(nil, cli)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config JSON")
}

func TestResolve_GeneratorNotInYAML(t *testing.T) {
	yamlCfg := &Config{
		Generators: map[string]GeneratorConfig{
			"anthropic.Claude": {Model: "claude-3"},
		},
	}
	cli := CLIOverrides{GeneratorName: "openai.OpenAI"}

	resolved, err := Resolve(yamlCfg, cli)
	require.NoError(t, err)
	assert.Empty(t, resolved.GeneratorConfig)
}

func TestResolve_ProfileApplied(t *testing.T) {
	yamlCfg := &Config{
		Run: RunConfig{
			Concurrency: 10,
		},
		Generators: map[string]GeneratorConfig{
			"openai.OpenAI": {
				Model: "gpt-4",
			},
		},
		Profiles: map[string]Profile{
			"quick": {
				Run: RunConfig{
					Concurrency: 2,
				},
				Generators: map[string]GeneratorConfig{
					"openai.OpenAI": {
						Model: "gpt-3.5-turbo",
					},
				},
			},
		},
	}
	cli := CLIOverrides{
		GeneratorName: "openai.OpenAI",
		ProfileName:   "quick",
	}

	resolved, err := Resolve(yamlCfg, cli)
	require.NoError(t, err)

	// Profile values should override base config
	assert.Equal(t, 2, resolved.ScannerOpts.Concurrency, "profile should override concurrency")
	assert.Equal(t, "gpt-3.5-turbo", resolved.GeneratorConfig["model"], "profile should override model")
}
