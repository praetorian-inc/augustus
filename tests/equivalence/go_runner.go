package equivalence

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"

	// Import test capabilities to ensure they're registered
	_ "github.com/praetorian-inc/augustus/internal/detectors/always"
	_ "github.com/praetorian-inc/augustus/internal/detectors/base"
	_ "github.com/praetorian-inc/augustus/internal/detectors/packagehallucination"
	_ "github.com/praetorian-inc/augustus/internal/generators/test"
	_ "github.com/praetorian-inc/augustus/internal/probes/apikey"
	_ "github.com/praetorian-inc/augustus/internal/probes/dan"
	_ "github.com/praetorian-inc/augustus/internal/probes/test"
)

// RunGoGenerator runs a Go generator and returns a comparable result.
func RunGoGenerator(ctx context.Context, name, prompt string, generations int) (*GeneratorResult, error) {
	// Create generator instance
	gen, err := generators.Create(name, registry.Config{})
	if err != nil {
		return &GeneratorResult{
			Success: false,
			Name:    name,
			Error:   err.Error(),
		}, nil
	}

	// Create conversation with the prompt
	conv := attempt.NewConversation()
	conv.AddPrompt(prompt)

	// Generate responses
	messages, err := gen.Generate(ctx, conv, generations)
	if err != nil {
		return &GeneratorResult{
			Success: false,
			Name:    name,
			Error:   err.Error(),
		}, nil
	}

	// Extract message contents
	outputs := make([]string, len(messages))
	for i, msg := range messages {
		outputs[i] = msg.Content
	}

	return &GeneratorResult{
		Success: true,
		Name:    name,
		Outputs: outputs,
	}, nil
}

// RunGoDetector runs a Go detector and returns a comparable result.
func RunGoDetector(ctx context.Context, name string, attemptInput AttemptInput) (*DetectorResult, error) {
	return RunGoDetectorWithConfig(ctx, name, attemptInput, nil)
}

// RunGoDetectorWithConfig runs a Go detector with config and returns a comparable result.
func RunGoDetectorWithConfig(ctx context.Context, name string, attemptInput AttemptInput, config *DetectorConfig) (*DetectorResult, error) {
	// Build config map
	cfg := registry.Config{}
	if config != nil {
		if len(config.Substrings) > 0 {
			cfg["substrings"] = config.Substrings
		}
		if config.MatchType != "" {
			cfg["matchtype"] = config.MatchType
		}
		if config.CaseSensitive {
			cfg["case_sensitive"] = config.CaseSensitive
		}
	}

	// Create detector instance
	det, err := detectors.Create(name, cfg)
	if err != nil {
		return &DetectorResult{
			Success: false,
			Name:    name,
			Error:   err.Error(),
		}, nil
	}

	// Create attempt with the input data
	att := attempt.New(attemptInput.Prompt)
	for _, output := range attemptInput.Outputs {
		att.AddOutput(output)
	}

	// Run detection
	scores, err := det.Detect(ctx, att)
	if err != nil {
		return &DetectorResult{
			Success: false,
			Name:    name,
			Error:   err.Error(),
		}, nil
	}

	return &DetectorResult{
		Success: true,
		Name:    name,
		Scores:  scores,
	}, nil
}

// RunGoProbe runs a Go probe and returns a comparable result.
// If generatorName is empty, only returns prompts without running the probe.
// If generatorName is provided, runs the full probe with that generator.
func RunGoProbe(ctx context.Context, name string, generatorName string) (*ProbeResult, error) {
	// Create probe instance
	probe, err := probes.Create(name, registry.Config{})
	if err != nil {
		return &ProbeResult{
			Success: false,
			Name:    name,
			Error:   err.Error(),
		}, nil
	}

	// Get prompts from the probe
	prompts := probe.GetPrompts()

	// Get primary detector
	primaryDetector := probe.GetPrimaryDetector()

	// Get goal
	goal := probe.Goal()

	result := &ProbeResult{
		Success:         true,
		Name:            name,
		Prompts:         prompts,
		PrimaryDetector: primaryDetector,
		Goal:            goal,
	}

	// If generator provided, run the probe (not needed for equivalence comparison)
	if generatorName != "" {
		gen, err := generators.Create(generatorName, registry.Config{})
		if err != nil {
			return &ProbeResult{
				Success: false,
				Name:    name,
				Error:   fmt.Sprintf("failed to create generator %s: %v", generatorName, err),
			}, nil
		}

		// Run probe against generator
		_, err = probe.Probe(ctx, gen)
		if err != nil {
			return &ProbeResult{
				Success: false,
				Name:    name,
				Error:   err.Error(),
			}, nil
		}
		// Attempts returned but not needed for equivalence check
	}

	return result, nil
}
