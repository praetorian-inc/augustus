// Package external provides a parser that runs external scripts for custom parsing logic.
package external

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/praetorian-inc/augustus/pkg/parsers"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	parsers.Register("external.Script", NewScript)
}

// ExecutionMode determines how the script is executed.
type ExecutionMode string

const (
	// ModeDocker runs the script in an ephemeral Docker container (default).
	ModeDocker ExecutionMode = "docker"
	// ModeNsjail runs the script in an nsjail sandbox (Linux only).
	ModeNsjail ExecutionMode = "nsjail"
	// ModeUnsafe runs the script directly on the host (requires --allow-unsafe-parsers flag).
	ModeUnsafe ExecutionMode = "unsafe"
)

// Compile-time interface assertion.
var _ parsers.Parser = (*Script)(nil)

// ScriptInput is the JSON sent to the external script via stdin.
type ScriptInput struct {
	RawResponse string            `json:"raw_response"`
	ContentType string            `json:"content_type"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ScriptOutput is the JSON expected from the script via stdout.
type ScriptOutput struct {
	Content string `json:"content"`
	Error   string `json:"error,omitempty"`
}

// Script runs an external Python/shell script for custom parsing.
type Script struct {
	command     string
	mode        ExecutionMode
	image       string
	timeout     time.Duration
	maxMemory   string
	noNetwork   bool
	allowUnsafe bool
}

// NewScript creates a new external script parser.
func NewScript(cfg registry.Config) (parsers.Parser, error) {
	s := &Script{
		mode:      ModeDocker,
		image:     "python:3.11-slim",
		timeout:   30 * time.Second,
		maxMemory: "128m",
		noNetwork: true,
	}

	// Required: command
	cmd, ok := cfg["command"].(string)
	if !ok || cmd == "" {
		return nil, fmt.Errorf("external.Script requires 'command' configuration")
	}
	s.command = cmd

	// Optional: execution mode
	if mode, ok := cfg["mode"].(string); ok {
		switch ExecutionMode(mode) {
		case ModeDocker, ModeNsjail, ModeUnsafe:
			s.mode = ExecutionMode(mode)
		default:
			return nil, fmt.Errorf("external.Script: invalid mode %q (must be 'docker', 'nsjail', or 'unsafe')", mode)
		}
	}

	// Optional: Docker image
	if image, ok := cfg["image"].(string); ok && image != "" {
		s.image = image
	}

	// Optional: timeout
	if timeout, ok := cfg["timeout"].(float64); ok {
		s.timeout = time.Duration(timeout) * time.Second
	} else if timeout, ok := cfg["timeout"].(int); ok {
		s.timeout = time.Duration(timeout) * time.Second
	}

	// Optional: memory limit
	if maxMemory, ok := cfg["max_memory"].(string); ok && maxMemory != "" {
		s.maxMemory = maxMemory
	}

	// Optional: network isolation
	if noNetwork, ok := cfg["no_network"].(bool); ok {
		s.noNetwork = noNetwork
	}

	// Safety flag from CLI
	if allowUnsafe, ok := cfg["allow_unsafe"].(bool); ok {
		s.allowUnsafe = allowUnsafe
	}

	// Validate unsafe mode
	if s.mode == ModeUnsafe && !s.allowUnsafe {
		return nil, fmt.Errorf("external.Script: unsafe mode requires --allow-unsafe-parsers flag")
	}

	// Emit warnings
	s.emitWarnings()

	return s, nil
}

// emitWarnings logs warnings about the execution mode.
func (s *Script) emitWarnings() {
	switch s.mode {
	case ModeDocker:
		log.Printf("WARN external.Script: Running in Docker container. Performance may be slower due to container overhead. Ensure Docker daemon is running.")
	case ModeNsjail:
		log.Printf("WARN external.Script: Running in nsjail sandbox. Limited to Linux hosts with nsjail installed.")
	case ModeUnsafe:
		log.Printf("WARN ⚠️  external.Script: Running in UNSAFE mode. Script has full host access. Only use trusted scripts. Consider using 'docker' mode for untrusted parsers.")
	}
	log.Printf("INFO external.Script: External parsers add latency (~50-200ms per call). For high-volume scans, consider implementing a built-in parser.")
}

// Parse executes the external script and returns the parsed content.
func (s *Script) Parse(ctx context.Context, raw []byte, contentType string) (string, error) {
	switch s.mode {
	case ModeDocker:
		return s.parseDocker(ctx, raw, contentType)
	case ModeNsjail:
		return s.parseNsjail(ctx, raw, contentType)
	case ModeUnsafe:
		return s.parseUnsafe(ctx, raw, contentType)
	default:
		return "", fmt.Errorf("external.Script: unknown execution mode: %s", s.mode)
	}
}

// parseDocker runs the script in a Docker container.
func (s *Script) parseDocker(ctx context.Context, raw []byte, contentType string) (string, error) {
	input := ScriptInput{
		RawResponse: string(raw),
		ContentType: contentType,
	}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("external.Script: failed to marshal input: %w", err)
	}

	// Build Docker command with security restrictions
	args := []string{
		"run", "--rm", "-i",
		"--memory", s.maxMemory,
		"--cpus", "0.5",
		"--read-only",
		"--security-opt", "no-new-privileges",
	}
	if s.noNetwork {
		args = append(args, "--network", "none")
	}
	args = append(args, s.image, "sh", "-c", s.command)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = bytes.NewReader(inputBytes)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("external.Script: timeout after %s", s.timeout)
		}
		return "", fmt.Errorf("external.Script: docker failed: %w: %s", err, stderr.String())
	}

	return s.parseOutput(stdout.Bytes())
}

// parseNsjail runs the script in an nsjail sandbox.
func (s *Script) parseNsjail(ctx context.Context, raw []byte, contentType string) (string, error) {
	input := ScriptInput{
		RawResponse: string(raw),
		ContentType: contentType,
	}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("external.Script: failed to marshal input: %w", err)
	}

	// Build nsjail command
	args := []string{
		"--mode", "o",
		"--time_limit", fmt.Sprintf("%d", int(s.timeout.Seconds())),
		"--rlimit_as", "128",
		"--rlimit_cpu", "10",
		"--disable_clone_newnet",
		"--",
		"sh", "-c", s.command,
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nsjail", args...)
	cmd.Stdin = bytes.NewReader(inputBytes)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("external.Script: timeout after %s", s.timeout)
		}
		return "", fmt.Errorf("external.Script: nsjail failed: %w: %s", err, stderr.String())
	}

	return s.parseOutput(stdout.Bytes())
}

// parseUnsafe runs the script directly on the host.
func (s *Script) parseUnsafe(ctx context.Context, raw []byte, contentType string) (string, error) {
	input := ScriptInput{
		RawResponse: string(raw),
		ContentType: contentType,
	}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("external.Script: failed to marshal input: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", s.command)
	cmd.Stdin = bytes.NewReader(inputBytes)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("external.Script: timeout after %s", s.timeout)
		}
		return "", fmt.Errorf("external.Script: script failed: %w: %s", err, stderr.String())
	}

	return s.parseOutput(stdout.Bytes())
}

// parseOutput parses the JSON output from the script.
func (s *Script) parseOutput(stdout []byte) (string, error) {
	var output ScriptOutput
	if err := json.Unmarshal(stdout, &output); err != nil {
		return "", fmt.Errorf("external.Script: invalid script output (expected JSON): %w", err)
	}

	if output.Error != "" {
		return "", fmt.Errorf("external.Script: script error: %s", output.Error)
	}

	return output.Content, nil
}

// Name returns the parser name.
func (s *Script) Name() string {
	return "external.Script"
}

// Description returns a human-readable description.
func (s *Script) Description() string {
	return "Runs external script for custom parsing"
}
