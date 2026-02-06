package logging

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigure_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	Configure(slog.LevelInfo, "json", &buf)

	slog.Info("test message", "key", "value")

	output := buf.String()
	require.Contains(t, output, `"msg":"test message"`)
	require.Contains(t, output, `"key":"value"`)
}

func TestConfigure_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	Configure(slog.LevelDebug, "text", &buf)

	slog.Debug("debug message")

	output := buf.String()
	require.Contains(t, output, "debug message")
}

func TestConfigure_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	Configure(slog.LevelWarn, "text", &buf)

	slog.Info("info message")   // Should be filtered
	slog.Warn("warn message")    // Should appear

	output := buf.String()
	require.NotContains(t, output, "info message")
	require.Contains(t, output, "warn message")
}
