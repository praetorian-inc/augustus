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
