package config

import (
	"testing"

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
