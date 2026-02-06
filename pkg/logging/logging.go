package logging

import (
	"io"
	"log/slog"
	"os"
)

// Configure sets up the global slog logger with specified level and format.
//
// Formats:
//   - "json": Structured JSON output for production
//   - "text": Human-readable text for development
//
// Levels: slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError
func Configure(level slog.Level, format string, output io.Writer) {
	if output == nil {
		output = os.Stderr
	}

	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: level,
	}

	switch format {
	case "json":
		handler = slog.NewJSONHandler(output, opts)
	case "text":
		handler = slog.NewTextHandler(output, opts)
	default:
		handler = slog.NewTextHandler(output, opts)
	}

	slog.SetDefault(slog.New(handler))
}

// ParseLevel converts string to slog.Level
func ParseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
