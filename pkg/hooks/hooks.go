// Package hooks provides lifecycle command hooks for stateful scanning.
//
// Hooks execute shell commands at specific points in the scan lifecycle:
//   - Setup: once before all probes (e.g., create a conversation)
//   - Prepare: before each probe execution (e.g., extract state from last response)
//   - Cleanup: once after all probes complete
//
// Shell commands communicate back to Augustus via KEY=VALUE lines on stdout,
// which get injected into the generator's request template as $KEY substitutions.
package hooks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/types"
)

// validKeyPattern restricts hook variable keys to uppercase alphanumeric and underscores.
var validKeyPattern = regexp.MustCompile(`^[A-Z0-9_]+$`)

// Hook represents a shell command to be executed at a specific lifecycle point.
type Hook struct {
	Command string
}

// Result contains the output from executing a hook command.
type Result struct {
	// Variables contains KEY=VALUE pairs parsed from stdout.
	Variables map[string]string
	// Stdout contains the raw stdout output.
	Stdout string
	// Stderr contains the raw stderr output.
	Stderr string
}

// Run executes the hook command with the given environment variables.
// It parses KEY=VALUE lines from stdout and returns them in Result.Variables.
// Lines starting with '#' or without '=' are ignored.
func (h *Hook) Run(ctx context.Context, env map[string]string) (*Result, error) {
	if h.Command == "" {
		return &Result{Variables: make(map[string]string)}, nil
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", h.Command)

	// Inherit current environment and add custom vars
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return &Result{
			Stdout: stdout.String(),
			Stderr: stderr.String(),
		}, fmt.Errorf("hook command failed: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	rawStdout := stdout.String()
	vars := ParseKeyValueLines(rawStdout)

	return &Result{
		Variables: vars,
		Stdout:    rawStdout,
		Stderr:    stderr.String(),
	}, nil
}

// ParseKeyValueLines extracts KEY=VALUE pairs from text.
// Lines that don't contain '=' or start with '#' are ignored.
// Keys are uppercased for consistent template substitution.
func ParseKeyValueLines(text string) map[string]string {
	vars := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key != "" {
			upperKey := strings.ToUpper(key)
			if !validKeyPattern.MatchString(upperKey) {
				continue // skip keys with invalid characters
			}
			vars[upperKey] = value
		}
	}
	return vars
}

// WithVars returns a new context with hook variables attached.
// Delegates to types.WithHookVars for decoupled context passing.
func WithVars(ctx context.Context, vars map[string]string) context.Context {
	return types.WithHookVars(ctx, vars)
}

// VarsFromContext returns hook variables from the context, or nil if none are set.
// Delegates to types.HookVarsFromContext for decoupled context passing.
func VarsFromContext(ctx context.Context) map[string]string {
	return types.HookVarsFromContext(ctx)
}

// RawResponseProvider is an optional interface for generators that expose
// their last raw HTTP response body for use by runtime hooks.
type RawResponseProvider interface {
	LastRawResponse() []byte
}
