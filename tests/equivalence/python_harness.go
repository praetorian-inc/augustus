package equivalence

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

// PythonHarness wraps the Python harness subprocess for invoking garak capabilities.
type PythonHarness struct {
	PythonPath  string        // Path to python3 executable (default: "python3")
	HarnessPath string        // Path to harness.py
	GarakPath   string        // Path to garak for PYTHONPATH
	Timeout     time.Duration // Subprocess timeout (default: 30s)
	UseArch     bool          // Use arch -arm64 wrapper (for macOS universal binaries)
}

// NewPythonHarness creates a harness with auto-detected paths.
func NewPythonHarness() (*PythonHarness, error) {
	// Find python3 executable
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		return nil, fmt.Errorf("python3 not found in PATH: %w", err)
	}

	// Find harness.py
	harnessPath, err := FindHarnessPath()
	if err != nil {
		return nil, fmt.Errorf("harness.py not found: %w", err)
	}

	// Find garak directory
	garakPath, err := FindGarakPath()
	if err != nil {
		return nil, fmt.Errorf("garak not found: %w", err)
	}

	// On macOS, Python may be a universal binary and site-packages may have
	// arm64-only .so files. Use arch -arm64 to ensure Python runs natively.
	// Detect arm64 hardware via sysctl (works even when Go runs under Rosetta).
	useArch := false
	if runtime.GOOS == "darwin" {
		// Check if running on arm64 hardware (even under Rosetta)
		out, err := exec.Command("sysctl", "-n", "hw.optional.arm64").Output()
		if err == nil && len(out) > 0 && out[0] == '1' {
			useArch = true
		}
	}

	return &PythonHarness{
		PythonPath:  pythonPath,
		HarnessPath: harnessPath,
		GarakPath:   garakPath,
		Timeout:     30 * time.Second,
		UseArch:     useArch,
	}, nil
}

// buildCommand creates the exec.Cmd with proper architecture handling.
// On macOS arm64, wraps with "arch -arm64" to ensure native execution.
func (h *PythonHarness) buildCommand(ctx context.Context, args []string) *exec.Cmd {
	// Prepend harness path to args
	fullArgs := append([]string{h.HarnessPath}, args...)

	var cmd *exec.Cmd
	if h.UseArch {
		// Use arch -arm64 python3 <harness> <args...>
		archArgs := append([]string{"-arm64", h.PythonPath}, fullArgs...)
		cmd = exec.CommandContext(ctx, "arch", archArgs...)
	} else {
		// Direct python3 <harness> <args...>
		cmd = exec.CommandContext(ctx, h.PythonPath, fullArgs...)
	}

	// Set PYTHONPATH to include garak
	cmd.Env = append(cmd.Environ(), fmt.Sprintf("PYTHONPATH=%s", h.GarakPath))

	return cmd
}

// harnessResult matches the Python harness JSON output structure.
type harnessResult struct {
	Success        bool                   `json:"success"`
	CapabilityType string                 `json:"capability_type"`
	CapabilityName string                 `json:"capability_name"`
	Output         map[string]any `json:"output"`
	Error          string                 `json:"error,omitempty"`
}

// RunGenerator calls the Python harness to run a generator.
// Command: python harness.py generator <name> --prompt <p> --generations <n>
func (h *PythonHarness) RunGenerator(ctx context.Context, name, prompt string, generations int) (*GeneratorResult, error) {
	// Build command arguments
	args := []string{
		"generator",
		name,
		"--prompt", prompt,
		"--generations", fmt.Sprintf("%d", generations),
	}

	// Execute with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	cmd := h.buildCommand(timeoutCtx, args)

	// Capture stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("harness command failed: %w\nOutput: %s", err, string(output))
	}

	// Parse JSON output
	var result harnessResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse harness output: %w\nOutput: %s", err, string(output))
	}

	// Convert to GeneratorResult
	genResult := &GeneratorResult{
		Success: result.Success,
		Name:    result.CapabilityName,
		Error:   result.Error,
	}

	if result.Success {
		// Extract generations from output
		if generations, ok := result.Output["generations"].([]any); ok {
			genResult.Outputs = make([]string, len(generations))
			for i, gen := range generations {
				if s, ok := gen.(string); ok {
					genResult.Outputs[i] = s
				} else if gen == nil {
					genResult.Outputs[i] = ""
				}
			}
		}
	}

	return genResult, nil
}

// DetectorConfig holds configuration for detectors like StringDetector.
type DetectorConfig struct {
	Substrings    []string `json:"substrings,omitempty"`
	MatchType     string   `json:"matchtype,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
}

// RunDetector calls the Python harness to run a detector.
// Command: python harness.py detector <name> --attempt <json>
func (h *PythonHarness) RunDetector(ctx context.Context, name string, attempt AttemptInput) (*DetectorResult, error) {
	return h.RunDetectorWithConfig(ctx, name, attempt, nil)
}

// RunDetectorWithConfig calls the Python harness to run a detector with config.
// Command: python harness.py detector <name> --attempt <json> --config <json>
func (h *PythonHarness) RunDetectorWithConfig(ctx context.Context, name string, attempt AttemptInput, config *DetectorConfig) (*DetectorResult, error) {
	// Serialize attempt to JSON
	attemptJSON, err := json.Marshal(attempt)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attempt: %w", err)
	}

	// Build command arguments
	args := []string{
		"detector",
		name,
		"--attempt", string(attemptJSON),
	}

	// Add config if provided
	if config != nil {
		configJSON, err := json.Marshal(config)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal config: %w", err)
		}
		args = append(args, "--config", string(configJSON))
	}

	// Execute with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	cmd := h.buildCommand(timeoutCtx, args)

	// Capture stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("harness command failed: %w\nOutput: %s", err, string(output))
	}

	// Parse JSON output
	var result harnessResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse harness output: %w\nOutput: %s", err, string(output))
	}

	// Convert to DetectorResult
	detResult := &DetectorResult{
		Success: result.Success,
		Name:    result.CapabilityName,
		Error:   result.Error,
	}

	if result.Success {
		// Extract scores from output
		if scores, ok := result.Output["scores"].([]any); ok {
			detResult.Scores = make([]float64, len(scores))
			for i, score := range scores {
				if f, ok := score.(float64); ok {
					detResult.Scores[i] = f
				}
			}
		}
	}

	return detResult, nil
}

// RunProbe calls the Python harness to run a probe.
// Command: python harness.py probe <name> [--generator <gen>]
func (h *PythonHarness) RunProbe(ctx context.Context, name string, generatorName string) (*ProbeResult, error) {
	// Build command arguments
	args := []string{
		"probe",
		name,
	}

	// Add generator if specified
	if generatorName != "" {
		args = append(args, "--generator", generatorName)
	}

	// Execute with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	cmd := h.buildCommand(timeoutCtx, args)

	// Capture stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("harness command failed: %w\nOutput: %s", err, string(output))
	}

	// Parse JSON output
	var result harnessResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse harness output: %w\nOutput: %s", err, string(output))
	}

	// Convert to ProbeResult
	probeResult := &ProbeResult{
		Success: result.Success,
		Name:    result.CapabilityName,
		Error:   result.Error,
	}

	if result.Success {
		// Extract prompts from output
		if prompts, ok := result.Output["prompts"].([]any); ok {
			probeResult.Prompts = make([]string, len(prompts))
			for i, p := range prompts {
				if s, ok := p.(string); ok {
					probeResult.Prompts[i] = s
				}
			}
		}

		// Extract primary detector
		if detector, ok := result.Output["primary_detector"].(string); ok {
			probeResult.PrimaryDetector = detector
		}

		// Extract goal
		if goal, ok := result.Output["goal"].(string); ok {
			probeResult.Goal = goal
		}
	}

	return probeResult, nil
}
