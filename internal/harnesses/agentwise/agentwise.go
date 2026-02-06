// Package agentwise provides a harness that filters probes based on agent capabilities.
//
// The agentwise harness allows running only those probes that are applicable to
// a specific agent's capabilities (tools, browsing, memory, multi-agent support).
package agentwise

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/harnesses"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Errors returned by the agentwise harness.
var (
	ErrNoProbes    = errors.New("no probes provided")
	ErrNoDetectors = errors.New("no detectors provided")
)

// AgentConfig describes the capabilities of an AI agent.
type AgentConfig struct {
	// HasTools indicates if the agent has access to tools/functions.
	HasTools bool
	// HasBrowsing indicates if the agent can access web browsing.
	HasBrowsing bool
	// HasMemory indicates if the agent has persistent memory.
	HasMemory bool
	// HasMultiAgent indicates if the agent supports multi-agent interactions.
	HasMultiAgent bool
	// ToolList is the list of specific tools available to the agent.
	ToolList []string
}

// Agentwise implements a harness that filters probes based on agent capabilities.
type Agentwise struct {
	config AgentConfig
}

// New creates a new agentwise harness with the given configuration.
func New(config AgentConfig) *Agentwise {
	return &Agentwise{
		config: config,
	}
}

// Name returns the fully qualified harness name.
func (a *Agentwise) Name() string {
	return "agentwise.Agentwise"
}

// Description returns a human-readable description.
func (a *Agentwise) Description() string {
	return "Filters and executes probes based on agent capabilities"
}

// isProbeApplicable checks if a probe is applicable to the configured agent.
//
// Probes are filtered based on their name prefix:
// - "multiagent.*" requires HasMultiAgent=true
// - "browsing.*" requires HasBrowsing=true
// - All other probes are allowed by default
func (a *Agentwise) isProbeApplicable(probe probes.Prober) bool {
	name := probe.Name()

	// Check for multiagent probes
	if strings.HasPrefix(name, "multiagent.") {
		return a.config.HasMultiAgent
	}

	// Check for browsing probes
	if strings.HasPrefix(name, "browsing.") {
		return a.config.HasBrowsing
	}

	// Check for memory-related probes
	if strings.HasPrefix(name, "memory.") {
		return a.config.HasMemory
	}

	// Check for tool-related probes
	if strings.HasPrefix(name, "tool.") {
		return a.config.HasTools
	}

	// All other probes are allowed by default
	return true
}

// FilterProbes returns only the probes that are applicable to the configured agent.
func (a *Agentwise) FilterProbes(probeList []probes.Prober) []probes.Prober {
	var filtered []probes.Prober

	for _, probe := range probeList {
		if a.isProbeApplicable(probe) {
			filtered = append(filtered, probe)
		}
	}

	return filtered
}

// Run executes the filtered probes using a probe-by-probe strategy.
//
// It filters the provided probes based on agent capabilities, then runs
// each applicable probe with all detectors, similar to the probewise harness.
func (a *Agentwise) Run(
	ctx context.Context,
	gen generators.Generator,
	probeList []probes.Prober,
	detectorList []detectors.Detector,
	eval harnesses.Evaluator,
) error {
	// Filter probes based on agent capabilities
	filteredProbes := a.FilterProbes(probeList)

	// Validate inputs
	if len(filteredProbes) == 0 {
		return ErrNoProbes
	}
	if len(detectorList) == 0 {
		return ErrNoDetectors
	}

	// Check context cancellation early
	if err := ctx.Err(); err != nil {
		return err
	}

	slog.Debug("agentwise harness filtered probes",
		"original_count", len(probeList),
		"filtered_count", len(filteredProbes),
		"has_tools", a.config.HasTools,
		"has_browsing", a.config.HasBrowsing,
		"has_memory", a.config.HasMemory,
		"has_multiagent", a.config.HasMultiAgent,
	)

	// Collect all attempts across all probes
	var allAttempts []*attempt.Attempt

	// Process each filtered probe
	for _, probe := range filteredProbes {
		// Check context cancellation between probes
		if err := ctx.Err(); err != nil {
			return err
		}

		slog.Debug("running probe", "probe", probe.Name())

		// Run the probe to get attempts
		attempts, err := probe.Probe(ctx, gen)
		if err != nil {
			return fmt.Errorf("probe %s failed: %w", probe.Name(), err)
		}

		// Run all detectors on each attempt
		for _, att := range attempts {
			// Check context cancellation between attempts
			if err := ctx.Err(); err != nil {
				return err
			}

			// Set the generator name if not already set
			if att.Generator == "" {
				att.Generator = gen.Name()
			}

			// Run each detector and track highest score
			maxScore := 0.0
			primaryDetector := ""
			var primaryScores []float64
			firstDetector := ""
			var firstScores []float64

			for _, detector := range detectorList {
				slog.Debug("running detector", "detector", detector.Name(), "probe", probe.Name())

				scores, err := detector.Detect(ctx, att)
				if err != nil {
					return fmt.Errorf("detector %s failed on probe %s: %w",
						detector.Name(), probe.Name(), err)
				}

				// Store detector results
				att.SetDetectorResults(detector.Name(), scores)

				// Remember first detector as fallback
				if firstDetector == "" {
					firstDetector = detector.Name()
					firstScores = scores
				}

				// Track detector with highest score
				for _, score := range scores {
					if score > maxScore {
						maxScore = score
						primaryDetector = detector.Name()
						primaryScores = scores
					}
				}
			}

			// Set primary detector to one with highest score
			// If no detector had scores, use first detector
			if primaryDetector != "" {
				att.Detector = primaryDetector
				att.Scores = primaryScores
			} else if firstDetector != "" {
				att.Detector = firstDetector
				att.Scores = firstScores
			}

			// Mark attempt as complete only if not in error state
			if att.Status != attempt.StatusError {
				att.Complete()
			}
		}

		allAttempts = append(allAttempts, attempts...)
	}

	// Call evaluator if provided
	if eval != nil && len(allAttempts) > 0 {
		if err := eval.Evaluate(ctx, allAttempts); err != nil {
			return fmt.Errorf("evaluation failed: %w", err)
		}
	}

	return nil
}

// init registers the agentwise harness with the global registry.
func init() {
	harnesses.Register("agentwise.Agentwise", func(cfg registry.Config) (harnesses.Harness, error) {
		config := AgentConfig{
			HasTools:      getBoolConfig(cfg, "has_tools", false),
			HasBrowsing:   getBoolConfig(cfg, "has_browsing", false),
			HasMemory:     getBoolConfig(cfg, "has_memory", false),
			HasMultiAgent: getBoolConfig(cfg, "has_multiagent", false),
		}

		// Extract tool list if provided
		if toolList, ok := cfg["tool_list"].([]string); ok {
			config.ToolList = toolList
		}

		return New(config), nil
	})
}

// getBoolConfig retrieves a bool value from config with a default fallback.
func getBoolConfig(cfg registry.Config, key string, defaultValue bool) bool {
	if val, ok := cfg[key].(bool); ok {
		return val
	}
	return defaultValue
}

// Registry helper functions for package-level access.

// List returns all registered harness names.
func List() []string {
	return harnesses.List()
}

// Get retrieves a harness factory by name.
func Get(name string) (func(registry.Config) (harnesses.Harness, error), bool) {
	return harnesses.Get(name)
}

// Create instantiates a harness by name.
func Create(name string, cfg registry.Config) (harnesses.Harness, error) {
	return harnesses.Create(name, cfg)
}
